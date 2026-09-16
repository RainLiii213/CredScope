# Baseline Demo

两个目录都使用相同相对文件路径 `app.py`。`changed` 中旧密码所在行发生移动，并新增一个假 API Key。

```powershell
python -m src.main baseline create demo_baseline/initial --output output/demo-baseline.json
python -m src.main scan demo_baseline/changed --baseline output/demo-baseline.json
python -m src.main baseline update demo_baseline/changed --file output/demo-baseline.json
```

第二条命令应显示一个 EXISTING 和一个 NEW。所有值均为不可用的课程假数据。
