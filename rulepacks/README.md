# Official Rule Packs

Rule Pack 是一组声明式 JSON 检测规则。内置规则始终加载；官方包推荐用 `--rulepack` 简写，用户包用 `--rules` 追加。重复 ID 会被明确拒绝，绝不静默覆盖。

```powershell
python -m src.main scan . --rulepack ai
python -m src.main scan . --rulepack ai --rulepack devops
python -m src.main scan . --rulepack all --rules my-company-rules.json
```

## 三个官方包

- `ai_llm_services.json`：Anthropic、Hugging Face、Replicate。
- `devops_registry.json`：GitLab、PyPI、HCP Terraform。
- `web_saas_services.json`：Stripe 服务端密钥、Shopify Access Token。

只加入有稳定公开前缀或结构的凭据。OpenAI 当前官方入门文档不承诺固定可检测格式；npm 文档没有给出稳定前缀；Twilio Secret 和 Discord Bot Token 缺少足够独特的公开 Secret 格式；SendGrid 官方文档说明用途但未稳定公开完整结构。因此这些服务没有凭印象加入。公开 Account SID、Stripe publishable key 等也不作为 Secret 报告。

格式依据来自服务商官方文档（核对日期：2026-09-14）：

- Anthropic: https://docs.anthropic.com/en/docs/agents-and-tools/claude-for-sheets
- Hugging Face: https://huggingface.co/docs/hub/en/security-tokens
- Replicate: https://replicate.com/docs/topics/security/api-tokens
- GitLab: https://docs.gitlab.com/security/tokens/
- PyPI: https://docs.pypi.org/trusted-publishers/internals/
- HCP Terraform: https://developer.hashicorp.com/terraform/cli/config/config-file
- Stripe: https://docs.stripe.com/keys
- Shopify: https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens

第三方服务可能更新 Token 格式。用户应复核最新官方文档，并可从 `examples/custom_rules.template.json` 制作自己的包。Rule Validator 通过长度、结构、编译检查和嵌套量词启发式降低错误及 ReDoS 风险，但不能数学上证明任意正则绝对安全。规则匹配还会将单行输入限制为 8192 字符。
