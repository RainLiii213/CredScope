# CredScope 1.1.0 Final Release

CredScope（Source Code Credential Security Auditor）是一款完全离线的源码凭据审计工具。它会在提交、分享或发布项目之前，找出疑似硬编码的 Token、密码、API Key、私钥头和数据库连接串，并只展示脱敏结果。

一句话使用：进入要检查的目录后运行 `CredScope.exe scan .`。

> CredScope 是辅助审计工具。Risk Score 是可解释的启发式风险分，不是“凭据为真”的概率，也不能保证发现所有 Secret。

## 30 秒快速开始

Windows 普通用户无需安装 Python：

```powershell
# 先看完整安全演示；会自动生成 JSON 和 HTML
.\CredScope.exe demo

# 扫描当前目录
.\CredScope.exe scan .

# 扫描并生成离线 Dashboard；无需填写输出路径
.\CredScope.exe scan . --report html
```

HTML 默认保存为 `output/credscope-report.html`，JSON 默认保存为 `output/credscope-report.json`。

使用源码运行时，统一采用模块入口 `python -m src.main`：

```powershell
python -m pip install -r requirements.txt
python -m src.main demo
python -m src.main scan . --report html
```

推荐 Python 3.11 或更高版本；扫描运行时只依赖标准库。

## 常用命令

| 目的 | 命令 |
| --- | --- |
| 查看版本 | `CredScope.exe --version` |
| 运行完整演示 | `CredScope.exe demo` |
| 扫描当前目录 | `CredScope.exe scan .` |
| 自动生成 JSON | `CredScope.exe scan . --report json` |
| 自动生成 HTML | `CredScope.exe scan . --report html` |
| 只显示中高风险 | `CredScope.exe scan . --min-level medium` |
| 额外忽略目录 | `CredScope.exe scan . --exclude generated` |
| 启用 AI 官方包 | `CredScope.exe scan . --rulepack ai` |
| 启用全部官方包 | `CredScope.exe scan . --rulepack all` |
| 校验自定义规则 | `CredScope.exe rules validate examples\custom_rules.template.json` |
| 列出规则 | `CredScope.exe rules list --rules my-rules.json` |
| 创建 Baseline | `CredScope.exe baseline create .` |
| 与 Baseline 比较 | `CredScope.exe scan . --baseline .credscope-baseline.json` |

`--rules`、`--rulepack` 和 `--exclude` 都可重复指定。`--rules` 与 `--rulepack` 可以组合，内置规则始终生效。

## 如何看懂结果

扫描主链路是：文件发现 → Rule / Context / Entropy → False Positive Filter → Risk Engine → Finding。

- Rule Detector 匹配明确的凭据结构。
- Context Detector 识别 `password = "..."`、`api_key: "..."` 等敏感字段直接赋值。
- Entropy Detector 自行计算 Shannon Entropy，只提供支持证据，绝不单独形成 Finding。
- Filter 排除 Placeholder、UUID、环境变量引用和显式 allowlist。
- Risk Engine 合并同一候选的多项证据，避免重复 Finding。

风险等级：CRITICAL 80–100、HIGH 60–79、MEDIUM 40–59、LOW 20–39。CLI、JSON、HTML 与 Baseline 都只包含类似 `gith********PQ` 的脱敏值，不保存完整候选值。

默认扫描 Python、JavaScript、TypeScript、Java、C/C++、JSON、YAML、TOML、INI、`.env`、文本和常见脚本文件；跳过 Git、虚拟环境、缓存、构建产物、`output`、已知二进制文件和超过 2 MiB 的文件。支持 UTF-8、UTF-8-SIG、GB18030、中文路径与带空格路径。

## 官方 Rule Packs

| 简写 | 文件 | 覆盖范围 |
| --- | --- | --- |
| `ai` | `rulepacks/ai_llm_services.json` | Anthropic、Hugging Face、Replicate |
| `devops` | `rulepacks/devops_registry.json` | GitLab、PyPI、HCP Terraform |
| `web` | `rulepacks/web_saas_services.json` | Stripe 服务端 Key、Shopify Access Token |
| `all` | 上述全部 | 一次启用三个官方包 |

```powershell
CredScope.exe scan . --rulepack ai --report html
CredScope.exe scan . --rulepack ai --rulepack devops
CredScope.exe scan . --rulepack all --rules my-company-rules.json
```

规则包只覆盖有相对稳定公开结构的凭据；第三方格式可能变化。格式依据和有意未加入的类型见 [rulepacks/README.md](rulepacks/README.md)。

## 自定义规则

先复制 [examples/custom_rules.template.json](examples/custom_rules.template.json)，再修改规则 ID、正则、分数和建议：

```powershell
CredScope.exe rules validate examples\custom_rules.template.json
CredScope.exe scan demo_custom_rules --rules examples\custom_rules.template.json
```

最小结构：

```json
{
  "pack_name": "My Rules",
  "version": "1.0",
  "rules": [{
    "id": "service-token",
    "name": "Service Token",
    "pattern": "SERVICE_[A-Za-z0-9]{20,}",
    "keywords": ["service", "token"],
    "severity_base": 60,
    "entropy_threshold": 3.5,
    "recommendation": "Rotate it and use an environment variable."
  }]
}
```

规则包是声明式 JSON，CredScope 不执行其中的 Python、Shell、JavaScript、模板或任意函数。Validator 会检查结构、必填字段、ID 冲突、正则编译、match-all、空字符串匹配、长度、可疑嵌套量词、关键词上限和分数范围；单行正则输入限制为 8192 字符。无效自定义规则被禁用并报告，内置规则仍继续工作。完整字段说明见 [examples/README.md](examples/README.md)。

## Baseline

Baseline 用于把当前风险分成 NEW、EXISTING 和 RESOLVED；EXISTING 不代表安全，也不会被自动忽略或修复。

```powershell
# 默认写到扫描目录下 .credscope-baseline.json
CredScope.exe baseline create .

# 比较并生成 Dashboard
CredScope.exe scan . --baseline .credscope-baseline.json --report html

# 人工确认后更新
CredScope.exe baseline update . --file .credscope-baseline.json
```

Fingerprint 使用 SHA-256，由规范化相对路径、规则或类型、检测器集合和已将原值替换成 `<SECRET>` 的单行上下文组成。行号不参与身份，因此仅移动代码行仍能识别为 EXISTING。Baseline 只保存不可逆指纹、脱敏值、类型、等级、规则和最后行号等安全摘要。

## Dashboard 与报告

JSON 保留扫描目标、统计、Finding 和可选 Baseline Delta，便于自动化处理。HTML 是不使用 CDN、不发起网络请求的单文件离线 Dashboard，包含：

- Findings 与四级风险 Summary Cards；
- Severity、凭据类型、Detector、Top Risk Files、风险分数分布；
- 扫描文件数、行数、耗时和速度；
- Finding 的脱敏详情与修复建议；
- 可选的 NEW / EXISTING / RESOLVED 区域。

最终目录提供三个可直接打开的样例：`output/sample-report.json`、`output/sample-dashboard.html` 和 `output/sample-baseline-dashboard.html`。

## Demo

```powershell
CredScope.exe demo
```

该命令自动扫描内置 `demo_project` 并加载 AI Rule Pack，终端展示脱敏 Finding 和 6 项功能检查，同时生成：

- `output/demo-report.json`
- `output/demo-dashboard.html`

所有 Demo 值都是人工构造且不可用的假数据。其他场景位于 `demo_custom_rules`、`demo_baseline` 和 `demo_statistics`。

## 测试

```powershell
python -m pytest -q
```

src 结构重构后的自动化结果：`67 passed`（迁移前为 `65 passed`）。测试覆盖正常、边界、异常、中文和空格路径、报告、脱敏、Baseline、规则安全、官方包、版本、资源定位、正式模块入口和兼容启动器；正式交付还执行全新虚拟环境与独立 EXE 目录验收。

## Windows EXE

正式交付的 `CredScope.exe` 是 PyInstaller one-file 控制台程序，不要求目标电脑安装 Python。配置、HTML 模板、官方规则包、示例和全部 Demo 资源已打入 EXE；运行时资源从 PyInstaller 临时目录只读加载，报告写到 EXE 所在目录的 `output`。

在源码目录重新构建：

```powershell
python -m pip install -r requirements.txt
python build_exe.py
```

构建结果位于 `dist/CredScope.exe`。`build_exe.py` 从唯一版本源生成 Windows 文件元数据，`CredScope.spec` 声明所有随包数据目录。

本次 src 重构后的正式构建为 8,706,693 字节（8.30 MiB），ProductVersion `1.1.0`，SHA-256：

```text
B48BEDC44C50BAF4781CFA5548DB291E83AB801408E3979CD5BFA8276C588CCD
```

## 项目结构

```text
credscope/
├── main.py                   # 仅保留旧命令兼容启动器
├── src/                      # 全部正式 Python 产品源码
│   ├── __init__.py
│   ├── main.py               # CLI、scan、demo、baseline、rules
│   ├── version.py            # 唯一版本源
│   ├── resource_paths.py     # 源码/EXE 资源与输出路径
│   ├── scanner.py
│   ├── models.py
│   ├── rule_loader.py
│   ├── rule_detector.py
│   ├── context_detector.py
│   ├── entropy_detector.py
│   ├── filters.py
│   ├── risk_engine.py
│   ├── baseline.py
│   ├── audit_statistics.py
│   └── reporter.py
├── config/                   # 内置规则、关键词和忽略配置
├── rulepacks/                # 官方规则扩展包
├── examples/                 # 自定义规则模板
├── templates/                # 离线 HTML 模板
├── demo_project/             # 基础一键演示数据
├── demo_custom_rules/        # 自定义规则演示
├── demo_baseline/            # Baseline 演示
├── demo_statistics/          # Dashboard 统计演示
├── tests/                    # 自动化测试，不属于产品源码
├── output/                   # 三个正式样例报告
├── CredScope.spec
├── build_exe.py
├── CredScope.exe
├── requirements.txt
├── README_FIRST.md
└── README.md
```

正式源码入口是 `python -m src.main`。根目录 `main.py` 仅调用 `src.main.run()`，用于兼容历史命令 `python main.py ...`，不包含任何业务逻辑。包内模块统一使用相对导入；资源路径统一由 `src/resource_paths.py` 处理：源码模式定位到项目根，Frozen 模式定位到 PyInstaller `_MEIPASS`，可写输出则定位到 EXE 所在目录。

## 安全声明与限制

- 所有扫描、规则验证、Baseline 和报告生成都在本地完成；程序没有网络请求代码，不上传源码或候选值。
- CLI、日志、JSON、HTML 和 Baseline 统一使用脱敏值；工具不会修改被扫描项目源码。
- Demo 和测试只使用不可用的人工假数据；规则加载器只解析 JSON，不执行用户代码。
- 启发式与正则检测仍可能误报或漏报；跨行拼接、运行时生成、加密或未知格式可能无法识别。
- Validator 能降低配置错误与部分 ReDoS 风险，但无法数学上证明任意正则绝对安全，未知规则仍需人工复核。
- 本版本不包含 Git Hook、GUI、LLM 判断、Git 历史/API 扫描、在线 Token 验证、云扫描、Web Server、数据库、机器学习或复杂 AST。
