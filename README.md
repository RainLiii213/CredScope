# CredScope v1.0

CredScope（Source Code Credential Security Auditor）是一个本地运行的 Python 命令行课程项目，用于在代码提交、分享或发布前发现潜在的硬编码凭据。它不会上传源码，也不会在线验证 Token。

> CredScope 是辅助审计工具，不能保证发现所有 Secret。Risk Score 是可解释的启发式风险分，不是“凭据为真”的概率。

## 为什么需要它

API Key、密码、数据库连接串等内容很容易随源码进入仓库。CredScope 将明确格式、代码上下文与字符串随机性结合起来，并过滤常见安全写法和占位值，给出经过脱敏、可解释的结果。

## 核心原理

扫描管线按顺序完成文件发现、三个检测器、误报过滤、候选融合、风险评分和报告：

1. **Rule Detector** 从 `config/rules.json` 加载约 10 条代表性正则规则，包括 GitHub Token、JWT、Bearer Token、私钥头、带账号密码的数据库 URL、AWS/Slack Token、Basic Auth 与通用 API Key/Secret。
2. **Context Detector** 识别 `password = "..."`、`api_key: "..."` 等敏感字段的直接字符串赋值，不做复杂 AST 分析。
3. **Entropy Detector** 自行实现 Shannon Entropy，对足够长的赋值字符串提供支持证据；它绝不会单独形成 Finding。
4. **False Positive Filter** 过滤 Placeholder、UUID、环境变量引用和显式 allowlist。
5. **Risk Engine** 按“文件 + 行 + 原始候选”融合多个检测器，去重并生成 0–100 的启发式风险分。

初始评分包括：明确规则最高基础分 60（私钥 80）、敏感字段名 +25、硬编码 +15、高熵 +15、长度 +5、敏感配置路径 +5，最终限制在 0–100。等级边界为 CRITICAL 80–100、HIGH 60–79、MEDIUM 40–59、LOW 20–39；低于 20 不报告。

## 项目结构

```text
credscope/
├── main.py                 # CLI
├── scanner.py              # 文件发现、安全读取、扫描管线
├── rule_detector.py        # JSON 正则规则
├── context_detector.py     # 敏感字段上下文
├── entropy_detector.py     # Shannon Entropy
├── filters.py              # 误报过滤与脱敏
├── risk_engine.py          # 融合、评分、分级
├── models.py               # dataclass 统一数据模型
├── reporter.py             # CLI / JSON / HTML
├── config/                 # 规则、关键词、默认忽略项
├── templates/report.html   # 静态报告模板
├── demo_project/           # 仅含人工构造假凭据
├── tests/                  # pytest 自动测试
├── output/                 # 实际演示报告
├── requirements.txt
└── README.md
```

## 安装

推荐 Python 3.11 或更高版本。运行时仅使用标准库；测试需要 pytest。

```powershell
cd "D:\大学\本科课程\大二上\python (pre semester)\project\credscope"
python -m pip install -r requirements.txt
```

## 使用

基础扫描：

```powershell
python main.py scan .\demo_project
```

生成 JSON 或 HTML（每次选择一种）：

```powershell
python main.py scan .\demo_project --report json --output .\output\demo-report.json
python main.py scan .\demo_project --report html --output .\output\demo-report.html
```

其他参数：

```text
--verbose                 输出诊断日志（日志不包含完整 Secret）
--min-level medium        仅展示/保存 MEDIUM 及以上结果
--exclude generated       额外忽略目录；可重复指定
```

CLI 展示扫描目标、文件/行数、耗时、Finding 数、等级统计、位置、类型、脱敏值、分数、依据和修复建议。JSON 提供结构化字段，HTML 适合课程演示；三种输出均不包含原始 Secret。

## Demo 与测试

`demo_project` 覆盖假 GitHub Token、硬编码密码、高熵 Secret、假数据库 URL、安全环境变量写法、Placeholder、UUID、普通字符串和中文文件名。所有值都是人工构造且不可用的测试数据。

运行完整测试：

```powershell
python -m pytest -q
```

测试覆盖规则命中与排除、上下文判断、Entropy 边界、四类过滤、候选融合与评分边界、报告生成与防泄露、错误路径、CLI、Demo 端到端和中文路径。

## 文件扫描策略

默认扫描常见源代码、配置和文本扩展名；跳过 `.git`、虚拟环境、缓存、`node_modules`、构建目录、IDE 目录和 `output`。已知图片、音视频、压缩包、可执行文件、数据库、模型文件和含 NUL 字节的文件会跳过。单文件上限为 2 MiB，支持 UTF-8、UTF-8-SIG 和 GB18030。单个文件不可读或编码失败不会中断整个任务。

## MVP 边界与已知限制

当前版本不包含 GUI、LLM、在线 Token 验证、Git 历史/API 扫描、云平台、pre-commit Hook、Baseline、数据库、Web 后端、机器学习、复杂 AST 分析或自动修改源码。

正则和上下文启发式可能产生漏报或误报；分行检测无法识别跨行拼接的 Secret；Entropy 阈值适合辅助判断而非证明；私钥规则当前识别头部风险，不解析密钥结构。用户应人工复核结果，并对确认泄露的凭据执行撤销和轮换。

## 安全声明

- 核心扫描全程在本地完成，不发起网络请求，也不上传源码。
- CLI、日志、JSON 与 HTML 默认只输出统一脱敏值。
- 工具不会修改被扫描项目的任何源文件。
- 本工具只能辅助发现风险，不能保证发现所有 Secret，也不能证明候选一定有效。
