# 先看这里：CredScope 1.1.0

CredScope 是一个完全离线的源码凭据审计工具：扫描代码中的疑似 Token、密码、API Key、私钥头和数据库连接串，输出只保留脱敏值。

## 最快演示

Windows 双击打开终端，在本目录运行：

```powershell
.\CredScope.exe demo
```

它会自动扫描安全 Demo、加载 AI 官方规则包，并生成 `output/demo-report.json` 与 `output/demo-dashboard.html`。

## 最常用命令

```powershell
.\CredScope.exe scan .
.\CredScope.exe scan . --report html
.\CredScope.exe scan . --report json
.\CredScope.exe scan . --rulepack all --report html
.\CredScope.exe baseline create .
.\CredScope.exe scan . --baseline .credscope-baseline.json
```

源码运行统一使用 `python -m src.main`，例如 `python -m src.main demo`。根目录 `python main.py ...` 作为旧命令兼容入口继续可用。

## 交付内容

- `CredScope.exe`：已从新 `src` 架构重新构建，并通过独立目录、无 Python/无源码环境验收的 one-file Windows 程序。
- `src/`：全部正式 Python 产品源码；包内统一使用相对导入。
- `main.py`：仅调用 `src.main` 的超薄兼容启动器，不含业务逻辑。
- `config/`、`rulepacks/`、`examples/`、`templates/`：内置配置、官方包、自定义规则模板和 HTML 模板。
- `demo_*`：基础、规则、Baseline 和统计演示。
- `tests/`：自动化测试，独立于产品源码。
- `output/`：3 个由最终代码生成的正式脱敏样例。
- `CredScope.spec`、`build_exe.py`：可重复 EXE 构建配置。

## 核心功能与核验结果

核心能力包括 Rule / Context / Entropy 三类检测、False Positive Filter、可解释 Risk Score、JSON/离线 HTML Dashboard、官方与自定义 Rule Pack、安全 Baseline、中文及空格路径支持。

src 结构重构后的结果：`67 passed`（迁移前为 `65 passed`）。全新虚拟环境测试、正式模块入口、兼容入口、独立 EXE 命令、版本一致性和报告脱敏均纳入验收。

正式 EXE 大小：8,706,693 字节（8.30 MiB）。SHA-256：

```text
B48BEDC44C50BAF4781CFA5548DB291E83AB801408E3979CD5BFA8276C588CCD
```

详细安装、命令参数、结果说明、自定义规则、安全边界和限制请阅读 [README.md](README.md)。
