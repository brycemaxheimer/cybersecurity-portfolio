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

`Get-AppSecret -Strict` throws when the row is missing OR DPAPI cannot
decrypt; useful for providers where a missing key should surface as a
visible error instead of degrading to "no result". Without `-Strict` the
function returns `$null` on either failure (legacy behavior).

`Test-DpapiSecretsHealth` (also in `SecIntel.Settings.ps1`) probes one
known secret at dashboard launch and surfaces a banner if DPAPI is
broken (e.g. database copied between users). Returns `'ok'`,
`'no-secrets'`, or `'failed'` with the exception reason.

## CSV type coercion (`Import-KqlLabCsv.ps1`)

`Convert-CellValue` decides how each CSV cell becomes a SQLite value
based on the column's KQL type from `__schema__`. Empty cells (and pure
whitespace) always become `NULL`, never empty string. Type-specific
rules:

| KQL type   | Accepted CSV input                                  | Stored as                   |
| ---------- | --------------------------------------------------- | --------------------------- |
| `bool`     | `true`, `1`, `yes`, `y`, `t` (case-insensitive)     | `1`                         |
|            | `false`, `0`, `no`, `n`, `f`                        | `0`                         |
|            | anything else                                       | `NULL`                      |
| `datetime` | any text - kept verbatim                            | TEXT (use ISO-8601, e.g. `2026-04-29T13:55:02Z`, so KQL/ADX can re-parse) |
| `dynamic`  | typically a JSON literal, but any text accepted     | TEXT (no validation)        |
| numeric (`int`, `long`, `real`, ...) | parsed with `InvariantCulture`     | `INTEGER` (int64) or `REAL` (double); unparseable → `NULL` |
| anything else | as-is                                            | TEXT                        |

CSV header names must match table column names case-sensitively. Extra
columns generate a warning and are ignored; missing columns become
`NULL`.
