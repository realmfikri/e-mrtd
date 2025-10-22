# Issuer Manifest Comparison Template

Use this template to record the output from `target/issuer/manifest.json` and quickly compare your run with the reference scenarios in the README.

## Session Context
- **Document number:**
- **Lifecycle targets:**
- **Digest algorithm:**
- **Signature algorithm:**

## Exported Data Groups
| DG | File Path | Length (bytes) |
|----|-----------|----------------|
| 1  | `EF.DG1.bin` | |
| 2  | `EF.DG2.bin` | |
| …  |             | |

## Trust Anchors
- **CSCA certificate:** `CSCA.cer`
- **Document signer certificate:** `DSC.cer`
- **Additional TA chain files:** *(add entries here if Terminal Authentication material was exported)*

## Passive Authentication (optional `--validate`)
- **Verdict:**
- **OK data groups:**
- **Bad data groups:**
- **Missing data groups:**
- **Locked data groups:**
- **Trust store issues:**

## Notes
- Face preview location (if generated):
- EF.CardAccess present: yes / no
- Additional observations:

