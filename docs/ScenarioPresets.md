# Scenario Presets Mapping

The table below captures the curated scenario presets and the CLI invocations the JavaFX UI uses to run them.

| Scenario | CLI Steps |
| --- | --- |
| Happy Path (Issuance + PA) | `ReadDG1Main --seed --require-pa` |
| BAC Only (no PACE) | `ReadDG1Main --seed` |
| PACE (MRZ) | `ReadDG1Main --seed --attempt-pace` |
| PACE (CAN) | `ReadDG1Main --seed --attempt-pace --can=123456` |
| PACE (PIN) | `ReadDG1Main --seed --attempt-pace --pin=123456` |
| PACE (PUK) | `ReadDG1Main --seed --attempt-pace --puk=123456789` |
| PACE Profile Preference (AES128) | `ReadDG1Main --seed --attempt-pace --pace-prefer=AES128` |
| Chip Authentication Upgrade (CA) | `ReadDG1Main --seed --attempt-pace` (DG14 triggers CA automatically) |
| Passive Auth: PASS | `ReadDG1Main --seed --require-pa` |
| Passive Auth: Tamper Detection | `ReadDG1Main --seed --require-pa --corrupt-dg2` |
| Passive Auth: Missing Trust Anchors | `ReadDG1Main --seed --require-pa --trust-store=target/ui-missing-trust` |
| Terminal Auth: Locked Biometrics | `ReadDG1Main --seed --attempt-pace` (no TA credentials) |
| Terminal Auth: DG3 Rights | `GenerateDemoTaChainMain --rights=DG3` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg3/terminal.cvc --ta-key=target/ta-demo/dg3/terminal.key` |
| Terminal Auth: DG4 Rights | `GenerateDemoTaChainMain --rights=DG4` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg4/terminal.cvc --ta-key=target/ta-demo/dg4/terminal.key` |
| Terminal Auth: DG3+DG4 Rights | `GenerateDemoTaChainMain --rights=DG3_DG4` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg34/terminal.cvc --ta-key=target/ta-demo/dg34/terminal.key` |
| Terminal Auth: Date Validity | `GenerateDemoTaChainMain --rights=DG3_DG4 --validity-days=30` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/date/terminal.cvc --ta-key=target/ta-demo/date/terminal.key --ta-date=2035-01-01` |
| Open Reads Policy (COM/SOD) | `ReadDG1Main --seed --open-com-sod --secure-com-sod` |
| Large DG2 (metadata truncation) | `ReadDG1Main --seed --large-dg2` |
| JSON Report Export | `ReadDG1Main --seed` |

> **Note:** The UI automatically injects `--out` for every `ReadDG1Main` invocation so it can display the generated report. Advanced options in the UI append additional CLI arguments on top of the preset defaults.
