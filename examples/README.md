# 签名样例

所有 JSONL 均为 UTF-8、每行不超过 4 KiB，每行至少包含：

```json
{"probe_id":"...","event_id":"...","host":"...","time":1234567890,"rule":"..."}
```

| 文件 | 用途 |
| --- | --- |
| `probe-alpha-valid.jsonl` | 正常样例，6 行，含一条完全相同的重复事件 |
| `probe-alpha-valid.sig` | 与正常样例匹配的 RSA-PSS/SHA256 签名，salt 长度 32 |
| `probe-alpha-tampered.jsonl` | 签名后修改首行 rule；搭配正常签名上传应验签失败 |
| `probe-beta-valid.jsonl` | 第二台探针的正常样例 |
| `probe-beta-valid.sig` | probe-beta 对应签名 |

在签名接收页中选择：

- 正常：探针 `probe-alpha` + `probe-alpha-valid.jsonl` + `probe-alpha-valid.sig`
- 篡改：探针 `probe-alpha` + `probe-alpha-tampered.jsonl` + `probe-alpha-valid.sig`
- 第二台：探针 `probe-beta` + `probe-beta-valid.jsonl` + `probe-beta-valid.sig`

样例签名由一次性开发的私钥生成；仓库不保存对应私钥。重新生成请运行：

```bash
python tools/generate_examples.py
```
