# Custom Rule Template

复制 `custom_rules.template.json` 后修改。JSON 不支持注释，因此字段说明如下：

- `pack_name`、`version`、`description`：规则包元数据。
- `rules`：规则数组，最多 100 条。
- `id`：小写字母、数字和连字符组成的唯一 ID。
- `name`、`description`：可读名称和说明。
- `pattern`：只描述 Secret 本身的 Python 正则；也兼容包含 `(?P<secret>...)` 的高级写法。
- `keywords`：可选的扫描前置关键词，最多 20 个；任一关键词出现时执行规则。
- `severity_base`：20–100 的启发式基础分。
- `entropy_threshold`：可选，0–8；达到时将 Entropy 作为支持证据。
- `recommendation`：修复建议。

规则包是声明式 JSON，CredScope 不会执行其中的 Python、Shell、JavaScript 或模板代码。先运行：

```powershell
python main.py rules validate examples/custom_rules.template.json
```

模板中的 `COURSESRV_...` 是虚构且不可用的假格式。
