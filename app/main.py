"""FastAPI entry point for signed probe alert reception."""

from __future__ import annotations

from contextlib import asynccontextmanager
import math
import os
from pathlib import Path
import tempfile

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.config import ConfigError, ProbeConfig, default_config_path, load_probe_config
from app.db import (
    count_alerts,
    initialize_storage,
    is_revoked,
    list_alerts,
    list_import_batches,
    list_probes,
    revoke_probe,
)
from app.ingest import (
    IngestError,
    MAX_SIGNATURE_BYTES,
    ingest_batch,
)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"
DEFAULT_SAMPLES_DIR = PROJECT_DIR / "examples"

SAMPLE_FILES: dict[str, dict[str, str]] = {
    "probe-alpha-valid.jsonl": {
        "kind": "valid",
        "probe_id": "probe-alpha",
        "description": "正常样例：probe-alpha 的 6 行 JSONL，含一条完全相同的重复事件。",
    },
    "probe-alpha-valid.sig": {
        "kind": "signature",
        "probe_id": "probe-alpha",
        "description": "正常样例对应的 RSA-PSS/SHA256 独立签名（salt 长度 32）。",
    },
    "probe-alpha-tampered.jsonl": {
        "kind": "tampered",
        "probe_id": "probe-alpha",
        "description": "篡改样例：签名后修改了字段，需搭配 probe-alpha-valid.sig 上传以触发验签失败。",
    },
    "probe-beta-valid.jsonl": {
        "kind": "valid",
        "probe_id": "probe-beta",
        "description": "正常样例：probe-beta 的 3 行 JSONL。",
    },
    "probe-beta-valid.sig": {
        "kind": "signature",
        "probe_id": "probe-beta",
        "description": "probe-beta 正常样例对应的 RSA-PSS/SHA256 独立签名。",
    },
}


def _samples_dir() -> Path:
    return Path(os.environ.get("SAMPLES_DIR", str(DEFAULT_SAMPLES_DIR)))


def create_app(
    *,
    config_path: str | Path | None = None,
    db_path: str | Path | None = None,
    staging_dir: str | Path | None = None,
) -> FastAPI:
    resolved_config = Path(config_path or default_config_path())
    resolved_db = Path(
        db_path
        or os.environ.get("ALERT_DB_PATH", str(PROJECT_DIR / "data" / "alerts.sqlite3"))
    )
    resolved_staging = Path(
        staging_dir
        or os.environ.get("STAGING_DIR", str(Path(tempfile.gettempdir()) / "probe-alert-staging"))
    )
    max_file_bytes = int(os.environ.get("MAX_EVENTS_BYTES", str(32 * 1024 * 1024)))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            probes = await run_in_threadpool(load_probe_config, resolved_config)
        except ConfigError as exc:
            raise RuntimeError(str(exc)) from exc
        await run_in_threadpool(initialize_storage, resolved_db, probes)
        resolved_staging.mkdir(parents=True, exist_ok=True)
        app.state.probes = probes
        app.state.db_path = resolved_db
        app.state.staging_dir = resolved_staging
        app.state.max_file_bytes = max_file_bytes
        app.state.config_path = resolved_config
        yield

    app = FastAPI(
        title="探针告警签名接收",
        description=(
            "流式校验 RSA-PSS/SHA256 签名的 UTF-8 JSONL 探针告警，"
            "以单事务原子入库，并持久化不可恢复的探针撤销状态。"
        ),
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: JSONResponse | None = None
        if request.method == "POST" and request.url.path in {
            "/api/ingest",
            "/api/imports",
            "/api/alerts/import",
        }:
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    request_bytes = int(content_length)
                except ValueError:
                    request_bytes = 0
                # Multipart framing and the detached signature live in the
                # same body.  This early bound prevents an oversized request
                # from filling the tmpfs before endpoint validation.
                max_body = request.app.state.max_file_bytes + 2 * 1024 * 1024
                if request_bytes > max_body:
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "detail": {
                                "code": "file_too_large",
                                "message": (
                                    f"请求体超过 {request.app.state.max_file_bytes // (1024 * 1024)} "
                                    "MiB JSONL 上限及允许的 multipart 开销"
                                ),
                            }
                        },
                    )
        if response is None:
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def _probe_for(request: Request, probe_id: str) -> ProbeConfig:
        probe = request.app.state.probes.get(probe_id)
        if probe is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "probe_not_found",
                    "message": f"探针 {probe_id} 未在本地配置中登记",
                },
            )
        return probe

    def _error(exc: IngestError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.to_detail())

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/ingest", include_in_schema=False)
    @app.get("/alerts", include_in_schema=False)
    async def ingest_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "ingest.html")

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request) -> dict:
        def _check() -> None:
            from app.db import open_read_connection
            from contextlib import closing

            with closing(open_read_connection(request.app.state.db_path)) as conn:
                conn.execute("SELECT 1").fetchone()

        try:
            await run_in_threadpool(_check)
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "error", "message": "database unavailable"},
            )
        return {"status": "ok"}

    @app.get("/api/meta", summary="运行限制与页面入口")
    async def meta(request: Request) -> dict:
        return {
            "version": __version__,
            "max_file_bytes": request.app.state.max_file_bytes,
            "max_line_bytes": 4096,
            "salt_length": 32,
            "signature": "RSA-PSS / SHA-256",
            "ingest_path": "/ingest",
        }

    @app.get("/api/probes", summary="列出已配置探针及不可恢复的撤销状态")
    async def probes(request: Request) -> dict:
        items = await run_in_threadpool(list_probes, request.app.state.db_path)
        return {
            "probes": items,
            "limits": {
                "max_file_bytes": request.app.state.max_file_bytes,
                "max_line_bytes": 4096,
                "salt_length": 32,
            },
        }

    @app.post("/api/probes/{probe_id}/revoke", summary="不可恢复地撤销一台探针")
    @app.post("/api/probes/{probe_id}/revocation", include_in_schema=False)
    async def revoke(request: Request, probe_id: str) -> dict:
        _probe_for(request, probe_id)
        result = await run_in_threadpool(revoke_probe, request.app.state.db_path, probe_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "probe_not_found", "message": f"探针 {probe_id} 不存在"},
            )
        return result

    @app.post("/api/revoke/{probe_id}", include_in_schema=False)
    async def revoke_alias(request: Request, probe_id: str) -> dict:
        return await revoke(request, probe_id)

    async def _handle_ingest(
        request: Request,
        *,
        probe_id: str | None,
        probe_alias: str | None,
        events: UploadFile | None,
        file_alias: UploadFile | None,
        jsonl_alias: UploadFile | None,
        signature: UploadFile | None,
        signature_file_alias: UploadFile | None,
        sig_alias: UploadFile | None,
    ) -> dict:
        selected = (probe_id or probe_alias or "").strip()
        if not selected:
            raise HTTPException(
                status_code=400,
                detail={"code": "probe_missing", "message": "请选择或提供 probe_id"},
            )
        probe = _probe_for(request, selected)
        upload = events or file_alias or jsonl_alias
        if upload is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "events_missing",
                    "message": "请上传 UTF-8 JSONL（表单字段 events、file 或 jsonl）",
                },
            )
        sig_upload = signature or signature_file_alias or sig_alias
        if sig_upload is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "signature_missing",
                    "message": "请上传独立的 RSA-PSS/SHA256 签名文件（表单字段 signature）",
                },
            )

        max_bytes = int(request.app.state.max_file_bytes)
        declared_size = getattr(upload, "size", None)
        if declared_size is not None and declared_size > max_bytes:
            raise HTTPException(
                status_code=413,
                detail={
                    "code": "file_too_large",
                    "message": f"JSONL 文件超过 {max_bytes // (1024 * 1024)} MiB 上限",
                },
            )

        try:
            signature_raw = await sig_upload.read(MAX_SIGNATURE_BYTES + 1)
            if len(signature_raw) > MAX_SIGNATURE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail={"code": "signature_too_large", "message": "签名文件过大"},
                )
            # A fast, non-authoritative check rejects obviously revoked probes
            # without reading 32 MiB.  The mandatory check is repeated inside
            # the final write transaction in app.ingest._commit_staged.
            if await run_in_threadpool(is_revoked, request.app.state.db_path, probe.probe_id):
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "probe_revoked",
                        "message": f"探针 {probe.probe_id} 已被撤销，不能接收告警",
                    },
                )

            result = await run_in_threadpool(
                ingest_batch,
                db_path=request.app.state.db_path,
                staging_dir=request.app.state.staging_dir,
                probe=probe,
                events_file=upload.file,
                signature_raw=signature_raw,
                file_name=upload.filename,
                max_file_bytes=max_bytes,
            )
            return result.as_dict()
        except IngestError as exc:
            raise _error(exc) from exc
        finally:
            await upload.close()
            await sig_upload.close()

    @app.post("/api/ingest", summary="上传 probe_id、JSONL 与独立签名并原子导入")
    @app.post("/api/imports", include_in_schema=False)
    @app.post("/api/alerts/import", include_in_schema=False)
    async def ingest_endpoint(
        request: Request,
        probe_id: str | None = Form(default=None),
        probe: str | None = Form(default=None),
        events: UploadFile | None = File(default=None),
        file: UploadFile | None = File(default=None),
        jsonl: UploadFile | None = File(default=None),
        signature: UploadFile | None = File(default=None),
        signature_file: UploadFile | None = File(default=None),
        sig: UploadFile | None = File(default=None),
    ) -> dict:
        return await _handle_ingest(
            request,
            probe_id=probe_id,
            probe_alias=probe,
            events=events,
            file_alias=file,
            jsonl_alias=jsonl,
            signature=signature,
            signature_file_alias=signature_file,
            sig_alias=sig,
        )

    @app.get("/api/alerts", summary="分页查看已提交告警")
    async def alerts(
        request: Request,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
        probe_id: str | None = Query(default=None, max_length=255),
    ) -> dict:
        filter_probe = probe_id.strip() if probe_id else None
        if filter_probe:
            _probe_for(request, filter_probe)
        items, total = await run_in_threadpool(
            list_alerts,
            request.app.state.db_path,
            page=page,
            page_size=page_size,
            probe_id=filter_probe,
        )
        pages = math.ceil(total / page_size) if total else 0
        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": pages,
            "total_pages": pages,
            "has_prev": page > 1,
            "has_next": page < pages,
        }

    @app.get("/api/imports", summary="分页查看导入批次及失败原因")
    async def imports(
        request: Request,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=10, ge=1, le=100),
    ) -> dict:
        items, total = await run_in_threadpool(
            list_import_batches,
            request.app.state.db_path,
            page=page,
            page_size=page_size,
        )
        pages = math.ceil(total / page_size) if total else 0
        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": pages,
            "total_pages": pages,
            "has_prev": page > 1,
            "has_next": page < pages,
        }

    @app.get("/api/samples", summary="列出正常与篡改样例")
    async def samples() -> dict:
        return {
            "items": [
                {
                    "name": name,
                    "url": f"/samples/{name}",
                    **info,
                }
                for name, info in SAMPLE_FILES.items()
            ]
        }

    @app.get("/samples/{name}", include_in_schema=False)
    async def sample_file(name: str) -> FileResponse:
        info = SAMPLE_FILES.get(name)
        if info is None:
            raise HTTPException(status_code=404, detail="sample not found")
        path = _samples_dir() / name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="sample unavailable")
        media_type = (
            "application/octet-stream" if name.endswith(".sig") else "application/x-ndjson"
        )
        return FileResponse(
            path,
            media_type=media_type,
            filename=name,
            content_disposition_type="attachment",
        )

    @app.get("/api/samples/{name}", include_in_schema=False)
    async def sample_meta(name: str) -> dict:
        info = SAMPLE_FILES.get(name)
        if info is None:
            raise HTTPException(status_code=404, detail="sample not found")
        return {"name": name, "url": f"/samples/{name}", **info}

    # Expose a tiny aggregate without loading alert rows on the home page.
    @app.get("/api/summary", include_in_schema=False)
    async def summary(request: Request) -> dict:
        total = await run_in_threadpool(count_alerts, request.app.state.db_path)
        return {"alerts_total": total}

    return app


app = create_app()
