# Scenario Presets Mapping

The table below captures the curated scenario presets and the CLI invocations the JavaFX UI uses to run them.

| Scenario | CLI Steps |
| --- | --- |
| Passive Authentication (success) | `ReadDG1Main --seed --require-pa` |
| Issuer: Full LDS | `IssuerMain --output=target/ui-issuer/full --validate` → `ReadDG1Main --seed --attempt-pace --require-pa` |
| Issuer: Minimal DG1/DG2 | `IssuerMain --output=target/ui-issuer/minimal --disable-dg=3 --disable-dg=4 --disable-dg=14 --disable-dg=15 --lifecycle=PERSONALIZED` → `ReadDG1Main --seed --require-pa` |
| Issuer: Corrupt DG2 | `IssuerMain --output=target/ui-issuer/corrupt --corrupt-dg2 --validate` → `ReadDG1Main --seed --attempt-pace --require-pa` |
| BAC secure messaging fallback | `ReadDG1Main --seed` |
| PACE (custom secret) | `ReadDG1Main --seed --attempt-pace` *(secret comes from advanced options: MRZ/CAN/PIN/PUK)* |
| PACE profile preference (AES128) | `ReadDG1Main --seed --attempt-pace --pace-prefer=AES128` |
| Chip Authentication upgrade | `ReadDG1Main --seed --attempt-pace --require-aa` |
| Terminal Authentication without credentials | `ReadDG1Main --seed --attempt-pace --require-pa --require-aa` |
| Passive Authentication (tamper detection) | `ReadDG1Main --seed --require-pa --corrupt-dg2` |
| Passive Authentication (missing trust anchors) | `ReadDG1Main --seed --require-pa --trust-store=target/ui-missing-trust` |
| Open reads policy (COM/SOD) | `ReadDG1Main --seed --open-com-sod --secure-com-sod` |
| Large DG2 (metadata truncation) | `ReadDG1Main --seed --large-dg2` |
| JSON report export | `ReadDG1Main --seed --require-aa` |
| Terminal Auth: DG3 Rights | `GenerateDemoTaChainMain --rights=DG3` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg3/terminal.cvc --ta-key=target/ta-demo/dg3/terminal.key` |
| Terminal Auth: DG4 Rights | `GenerateDemoTaChainMain --rights=DG4` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg4/terminal.cvc --ta-key=target/ta-demo/dg4/terminal.key` |
| Terminal Auth: DG3+DG4 Rights | `GenerateDemoTaChainMain --rights=DG3_DG4` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/dg34/terminal.cvc --ta-key=target/ta-demo/dg34/terminal.key` |
| Terminal Auth: Date Validity | `GenerateDemoTaChainMain --rights=DG3_DG4 --validity-days=30` → `ReadDG1Main --seed --attempt-pace --ta-cvc=target/ta-demo/date/terminal.cvc --ta-key=target/ta-demo/date/terminal.key --ta-date=2035-01-01` |

> **Note:** The UI automatically injects `--out` for every `ReadDG1Main` invocation so it can display the generated report. Advanced options in the UI append additional CLI arguments on top of the preset defaults, including the chosen PACE secret when running the `PACE (custom secret)` preset.

> **MRZ overrides:** Use the Advanced toggles pane to customise the document type, issuing state, nationality, surname (primary identifier), given names (secondary identifier), and gender when running issuer presets so their personalization inputs match your scenario.
