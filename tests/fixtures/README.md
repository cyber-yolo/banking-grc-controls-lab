# Synthetic evidence fixtures

Hand-written envelopes in the format of `collectors/Collect-Evidence.ps1`. No value comes from a real tenant. Domains use `contoso.example`; object IDs are readable labels (`user-bg-01`, `perm-mail-readwrite`) instead of GUIDs. The only GUID is Microsoft Graph's public application ID.

- `pass/`: a well-configured lab; every machine-checked assertion must PASS.
- `fail/`: one deliberate defect per assertion; every assertion must FAIL (except repository-only ones, which read repository files).
