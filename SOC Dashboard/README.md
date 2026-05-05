# SOC Dashboard

The SOC Dashboard is a self-contained PowerShell SOC analyst toolkit; module
reference below.

## Secret storage and Windows profile coupling

The SecIntel modules store API keys via DPAPI (`Set-AppSecret`,
`Get-AppSecret` in `SecIntel.Settings.ps1`). DPAPI ties ciphertext to the
**Windows user profile** that wrote it. A secret set on machine A under
user X cannot be read on machine B, or under user Y on machine A. Roaming
profiles partially mitigate this; cross-platform usage (WSL, Linux) does
not work - re-run `Set-AppSecret` from the target environment.
