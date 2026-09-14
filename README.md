# CredScope v1.1

CredScope（Source Code Credential Security Auditor）是一个完全在本地运行的 Python 命令行工具，用于在代码提交、分享或发布前发现潜在硬编码凭据。v1.1 在保留 v1.0 扫描主链路的基础上增加安全 Baseline、声明式自定义规则、三个官方规则包和增强统计 Dashboard。

> CredScope 是辅助审计工具，不能保证发现所有 Secret。Risk Score 是可解释的启发式风险分，不是“凭据为真”的概率。

## 核心扫描原理

主链路保持为：文件发现 → Rule / Context / Entropy → False Positive Filter → Risk Engine → Finding。v1.1 的三个扩展分别接入明确位置：

- Rule Loader / Validator 位于 Rule Detector 之前；内置规则始终生效，自定义包只追加规则。
- Baseline 位于 Risk Engine 生成 Finding 之后，不改变检测结果。
- Statistics 仅从 `ScanResult` 和安全的 `Finding` 派生，不接触原始 Secret。

三类 Detector：

1. **Rule Detector**：执行通过 Validator 的格式规则，包括 GitHub Token、JWT、Bearer、私钥头、数据库 URL、AWS/Slack、Basic Auth、通用 API Key/Secret 等。
2. **Context Detector**：识别 `password = "..."`、`api_key: "..."` 等敏感字段的直接字符串赋值，并排除环境变量引用。
3. **Entropy Detector**：自行实现 Shannon Entropy，只提供支持证据，绝不单独形成 Finding。

Placeholder、UUID、环境变量引用和 allowlist 由独立 Filter 处理。Risk Engine 合并同一候选的多个检测器结果，生成 0–100 的启发式风险分：CRITICAL 80–100、HIGH 60–79、MEDIUM 40–59、LOW 20–39。

## 安装

推荐 Python 3.11 或更高版本。运行时仅使用标准库；pytest 只用于测试。

```powershell
cd "D:\大学\本科课程\大二上\python (pre semester)\project\credscope"
python -m pip install -r requirements.txt
python -m pytest -q
```

## 普通扫描与报告

原 v1.0 命令和参数继续兼容：

```powershell
python main.py scan demo_project
python main.py scan demo_project --report json --output output/demo-report-v11.json
python main.py scan demo_project --report html --output output/security-dashboard.html
python main.py scan demo_project --min-level medium --exclude generated --verbose
```

默认扫描常见源码、配置与文本文件，跳过 Git、虚拟环境、构建产物、缓存、IDE、`output`、已知二进制文件和超过 2 MiB 的文件。支持 UTF-8、UTF-8-SIG、GB18030 与 Windows 中文路径。单个文件异常不会中断完整扫描。

## Baseline

Baseline 用于区分历史 Finding，不代表 EXISTING 风险已经安全，也不会自动忽略或修复任何问题。

```powershell
# 创建；默认输出到扫描目录下 .credscope-baseline.json
python main.py baseline create demo_baseline/initial --output output/demo-baseline.json

# 比较，输出 NEW / EXISTING / RESOLVED
python main.py scan demo_baseline/changed --baseline output/demo-baseline.json

# 用户确认后更新
python main.py baseline update demo_baseline/changed --file output/demo-baseline.json
```

Fingerprint 使用 SHA-256，输入为：

```text
规范化相对路径
+ rule_id（无规则时使用 secret_type）
+ 排序后的 detector 集合
+ 将候选原值替换为 <SECRET> 后、折叠空白并 casefold 的单行上下文
```

行号不参与身份，因此代码插入导致的行号变化仍能识别为 EXISTING。Baseline 只保存 Fingerprint、脱敏值、类型、等级、规则与最后行号等安全摘要；不保存源码上下文、完整 Secret 或可逆数据。若变量名、规则类型、检测器或周围代码发生明显变化，会形成 NEW Finding。

## 自定义规则

复制 [examples/custom_rules.template.json](examples/custom_rules.template.json)，按 [examples/README.md](examples/README.md) 修改：

```powershell
python main.py rules validate examples/custom_rules.template.json
python main.py scan demo_custom_rules --rules examples/custom_rules.template.json
python main.py rules list --rules examples/custom_rules.template.json
```

可以重复 `--rules` 合并多个规则包：

```powershell
python main.py scan . `
  --rules rulepacks/ai_llm_services.json `
  --rules rulepacks/devops_registry.json
```

Custom Rule 是声明式 JSON，绝不执行 Python、Shell、JavaScript、模板或任意函数。Schema：

```json
{
  "pack_name": "My Rules",
  "version": "1.0",
  "description": "Pack description",
  "rules": [{
    "id": "service-token",
    "name": "Service Token",
    "description": "What it detects",
    "pattern": "SERVICE_[A-Za-z0-9]{20,}",
    "keywords": ["service", "token"],
    "severity_base": 60,
    "entropy_threshold": 3.5,
    "recommendation": "Rotate it and use an environment variable."
  }]
}
```

`pattern` 默认描述 Secret 本身，Loader 自动加入安全捕获组；也兼容带 `(?P<secret>...)` 的高级规则。内置、官方和用户规则统一为同一种运行时数据结构。

### Rule Validator 安全检查

Validator 检查 JSON/根结构、rules 数组、必需字段、ID 语法与重复、跨来源 ID 冲突、名称、Pattern 类型/空值/长度/编译、match-all、空字符串匹配、可疑嵌套无限量词、keywords 类型/数量/长度、severity 范围、entropy_threshold 类型/范围、recommendation 与单包规则总量。单行正则输入最多 8192 字符。

无效自定义规则只会被禁用并明确报告，不会让普通扫描崩溃；内置规则损坏仍作为配置错误终止。Validator 可以降低配置错误与 ReDoS 风险，但无法数学上证明任意正则表达式绝对安全，因此未知规则仍应人工复核。

## 官方 Rule Packs

详见 [rulepacks/README.md](rulepacks/README.md)：

- **AI & LLM**：Anthropic、Hugging Face、Replicate。
- **DevOps & Package Registry**：GitLab、PyPI、HCP Terraform。
- **Web & SaaS**：Stripe 服务端 Secret/Restricted Key、Shopify Access Token。

这些规则仅覆盖官方文档公开且相对稳定的前缀或结构。OpenAI 固定 Key 格式、npm Token、Twilio Secret、Discord Bot Token、SendGrid 完整结构等缺少足够稳定或独特的公开依据，本轮主动不加入；公开标识（如 Twilio Account SID、Stripe publishable key）也不作为 Secret。第三方格式未来可能变化，使用者应复核最新服务商文档。

## Security Audit Statistics

CLI 显示扫描规模、耗时、Findings、Severity、Top Risk Types、Top Risk Files；启用 Baseline 时增加 Delta。

JSON 保留 v1.0 的 `tool`、`target_path`、`summary`、`stats`、`findings`，新增 `statistics`：

- scan speed（lines/s）；
- severity distribution；
- credential type distribution；
- detector contribution；
- top risk files（Finding 数、最高分、总分）；
- risk score distribution；
- baseline delta（未启用时为 `null`）。

一个 Finding 可同时由 Rule、Context、Entropy 支持，因此 Detector Contribution 总和可能大于 Finding 数量。

HTML 是无 CDN、无网络请求的离线 Security Audit Dashboard，包含 Summary Cards、五组纯 CSS 分布图、可选 Baseline Delta、Finding 详情和 Resolved 区域。

## Demo

- `demo_project`：v1.0 基础场景，并加入仅在 AI Pack 下报告的假 Anthropic 格式。
- `demo_custom_rules`：用户模板 True Positive 与相似 Negative。
- `demo_baseline/initial`、`changed`：旧 Finding 行号移动、新 Finding 出现。
- `demo_statistics`：Dashboard 的多类型、多文件统计。

推荐演示：

```powershell
python main.py scan demo_project
python main.py scan demo_project --rules rulepacks/ai_llm_services.json
python main.py rules validate examples/custom_rules.template.json
python main.py baseline create demo_baseline/initial --output output/demo-baseline.json
python main.py scan demo_baseline/changed --baseline output/demo-baseline.json
python main.py scan demo_statistics --report html --output output/security-dashboard.html
```

## 项目结构

```text
credscope/
├── main.py
├── scanner.py
├── models.py
├── rule_loader.py
├── rule_detector.py
├── context_detector.py
├── entropy_detector.py
├── filters.py
├── risk_engine.py
├── baseline.py
├── audit_statistics.py
├── reporter.py
├── config/
├── examples/
├── rulepacks/
├── templates/
├── demo_project/
├── demo_custom_rules/
├── demo_baseline/
├── demo_statistics/
├── tests/
├── output/
├── requirements.txt
└── README.md
```

## v1.1 边界与安全声明

- 核心扫描、规则验证、Baseline 和报告生成全部在本地完成，不上传源码或候选值。
- CLI、日志、Baseline、JSON、HTML 只输出统一脱敏值。
- 工具不会修改被扫描项目源码。
- 本轮不包含 pre-commit/Git Hook/commit blocker，也没有 GUI、LLM 判断、Git 历史/API 扫描、在线 Token 验证、云扫描、Web Server、数据库、机器学习或复杂 AST。
- 正则与上下文启发式仍可能漏报或误报；跨行拼接、动态生成和未知格式可能无法识别。
- PyInstaller 打包时只需将 `config/`、`templates/`、`examples/`、`rulepacks/` 作为数据文件包含；运行时没有额外 Python 依赖。
