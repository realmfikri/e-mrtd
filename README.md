# eMRTD Simulator

## Table of Contents
- [✨ Overview](#-overview)
- [🧱 Architecture](#-architecture)
- [🛠️ Prerequisites](#️-prerequisites)
- [⚙️ Build Project](#-build-project)
- [🚀 Run Scenarios](#-run-scenarios)
- [📁 Key Directories](#-key-directories)
- [🧪 Test Scenarios](#-test-scenarios)
- [🛡️ Security Features](#️-security-features)
- [🧭 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ Overview
**eMRTD Simulator** is a Java-based emulator of electronic Machine Readable Travel Documents (ePassports). It implements core ICAO 9303 protocols and is intended for educational purposes and integration testing.

Core capabilities include:
- Dynamic personalization for key data groups (EF.COM, EF.DG1, EF.DG2, EF.DG3, EF.DG4, EF.DG15, EF.SOD).
- Host tools for BAC authentication, secure messaging, DG parsing, and passive authentication verification.
- Robust error handling for corrupted or oversized biometric payloads.

## 🧱 Architecture
- **Applet Java Card (`sos.passportapplet`)**
  - Simulates the secure element (chip) behavior.
  - Supports BAC, secure messaging, personalization commands, and LDS file storage.
- **Host-Side Tools (`emu`)**
  - Java terminal applications executing personalization, authentication, and verification flows.
  - Entry point `emu.ReadDG1Main` orchestrates the end-to-end flow (issuance + verification).

## 🛠️ Prerequisites
Install the following tools before working with the project:
```bash
# Ensure Java 17 is installed
java --version

# Verify Maven installation
mvn -version

# Verify Git installation for repository management
git --version
```
- **OpenJDK 17** – primary runtime and compilation target.
- **Apache Maven** – dependency management and build tool.
- **Git** – version control (optional but recommended).

## ⚙️ Build Project
Compile the simulator and prepare artifacts:
```bash
mvn -q -DskipTests clean package
```
- `clean` removes previous build outputs.
- `package` compiles sources, runs checks (tests skipped here), and assembles the application.

## 🚀 Run Scenarios
The main entry point is `emu.ReadDG1Main`, executing personalization + verification.

> ℹ️ **Heads-up:** Run `mvn -q -DskipTests package` once after cloning or editing the project so the CLI classes are compiled
> before invoking any of the scenarios below.

### Happy Path (Issuance + PA Verification)
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa'
```
- `--seed` triggers built-in personalization of LDS files.
- `--require-pa` enforces passive authentication (fails if verification doesn’t pass).

### Corrupted DG2 Scenario
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa --corrupt-dg2'
```
- Introduces corrupted biometric payload to validate error handling.

### Oversized DG2 Scenario
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --large-dg2'
```
- Generates an oversized DG2 to test system safeguards against excessive biometrics.

### PACE with MRZ Secret
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --doc=123456789 --dob=750101 --doe=250101'
```
- Personalises the chip, then authenticates with PACE using the MRZ-derived secret.
- Falls back to BAC automatically if PACE is not available or negotiation fails.

### PACE with Seeded CAN Secret
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --can=123456 --doc=123456789 --dob=750101 --doe=250101'
```
- Seeds the CAN value into the chip via `PUT DATA 0x65` and immediately uses it for PACE.
- Replace `--can` with `--pin` or `--puk` to exercise the alternative credential containers.
- Expect the log line `PUT PACE secrets TLV → SW=9000`. A status word `6A80` means the host is still emitting the old, nested
  TLV format—run `mvn -q -DskipTests package` (or `mvn clean package`) to rebuild the CLI before retrying.

### Prefer a Specific PACE Profile
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --pace-prefer=IM'
```
- `--pace-prefer` accepts friendly labels (`GM`, `IM`, `3DES`, `AES128`, `AES192`, `AES256`) or a dotted OID to force a specific
  PACEInfo entry when multiple mappings are advertised in EF.CardAccess.
- The console reports whether the preference was matched and highlights the negotiated mapping and cipher (`Secure messaging →
  PACE (AES-128) after PACE handshake`).

### Toggle EF.COM/EF.SOD Open Reads
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --open-com-sod'
```
- `--open-com-sod` enables the developer PUT DATA switch that allows EF.COM and EF.SOD to be read without secure messaging once
  the chip is locked, mimicking the policy of many production passports.
- Use `--secure-com-sod` to return to the default "secure-only" behaviour in the same run.

### JSON Session Report Export
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --out target/session-report.json'
```
- Produces a machine-readable summary at the path supplied to `--out` (directories are created on demand).
- The JSON schema is stable and contains:
  - `session`: transport name, active secure messaging mode (`BAC`, `PACE`, `CA_AES`, or `CA_3DES`), and authentication flags.
  - `pa`: passive authentication verdict, signer subject, digest algorithm, and DG hash status.
  - `aa`: Active Authentication toggle (CLI/attempt), card support, key algorithm, and verification result.
  - `dg`: data groups read during the run plus DG3/DG4 accessibility and DG2 face metadata (dimensions, MIME, size).
- `--trust` is accepted as an alias of `--trust-store`, and `--aa` is an alias of `--require-aa` when scripting flows.
- Add multiple Master List inputs with the repeatable `--trust-ml` flag to point passive authentication at additional CSCA
  bundles.
- The run now prints a transition log whenever secure messaging upgrades (BAC → PACE → CA) plus a final summary line showing the
  active mode.

### BAC Fallback after Incorrect CAN
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --can=000000 --doc=123456789 --dob=750101 --doe=250101'
```
- Demonstrates graceful failure when the provided CAN does not match the seeded value.
- Observe the log message `PACE failed` followed by `Falling back to BAC secure messaging.`

### Active Authentication Verification (RSA)
```bash
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --require-aa'
```
- Establishes PACE (or falls back to BAC), reads DG15, performs `INTERNAL AUTHENTICATE`, and verifies the RSA signature using the DG15 public key.
- The run fails with an exception if the card does not prove knowledge of the AA private key (or if DG15 is missing) because `--require-aa` enforces a pass verdict.
- During personalization the log must show `PUT AA modulus TLV → SW=9000` and `PUT AA exponent TLV → SW=9000`; any other status word means the AA key was not provisioned and the subsequent verification will fail.

To exercise Terminal Authentication (TA) you need a certificate chain and the reader's private key.

### Terminal Authentication (DG3/DG4 Unlock)
```bash
mvn -q exec:java -Dexec.mainClass=emu.GenerateDemoTaChainMain
mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main \
  -Dexec.args='--seed --attempt-pace --ta-cvc target/ta-demo/cvca.cvc --ta-cvc target/ta-demo/terminal.cvc --ta-key target/ta-demo/terminal.key'
```
- The generator emits a demo CVCA certificate, a terminal certificate signed by that CVCA, and the matching terminal private key under `target/ta-demo/`.
- Supply the CVCA first and the terminal certificate second via the repeatable `--ta-cvc` flag, and point `--ta-key` at the terminal PKCS#8 PEM.
- Override the simulated "current date" used for Terminal Authentication validity checks with `--ta-date=YYYY-MM-DD` (defaults to the host's current UTC date if omitted).
- With the credentials present the host performs PACE, Chip Authentication, and the protected TA handshake; success is logged as `Terminal Authentication handshake completed.` followed by `EF.DG3`/`EF.DG4` access reports.
- Omit `--ta-key` to stay in passive reporting mode when you only want CVC metadata summaries.
- Synthetic fingerprint (DG3) and iris (DG4) payloads are now provisioned during personalization. Run the same `ReadDG1Main` command without any `--ta-cvc`/`--ta-key` flags to observe `EF.DG3 inaccessible` / `EF.DG4 inaccessible` before TA, then repeat with the credentials above to see both groups become readable under the upgraded secure messaging session.

When running inside a headless shell (e.g. CI), prepend `JAVA_TOOL_OPTIONS=-Djava.awt.headless=true` so the synthetic biometric generator can render without an X server.

Each run logs:
- Personalization steps and LDS writing.
- BAC establishment and secure messaging status.
- DG1 (MRZ) parsing output.
- DG2 metadata (image size, MIME type, quality metrics).
- Passive authentication results, including hash validation, signature verification, and trust chain status.
- Session summary covering PACE attempts, BAC fallback decisions, chip authentication status, and terminal authentication results (including DG3/DG4 access).

## 📁 Key Directories
```bash
src/main/java/sos/passportapplet/   # Applet (chip-side) logic
src/main/java/emu/                  # Host-side Java tooling (simulator, verifier)
```
Use these paths for navigation when inspecting or modifying code.

## 🧪 Test Scenarios

### Automated QA Matrix

Run the integration suite to exercise BAC, PACE, passive authentication edge cases, Active Authentication, and secure-messaging
replay protection:

```bash
mvn -q test
```

The JUnit suite provisions a fresh in-memory card for every test and verifies:

- **BAC happy path** – DG1 is readable via secure messaging established with MRZ-derived BAC keys.
- **PACE establishment** – AES secure messaging is negotiated using the EF.CardAccess GM profile.
- **Passive Authentication tamper detection** – modifying EF.DG1 triggers hash verification failures under PA.
- **Trust chain enforcement** – missing trust anchors yield a PA chain validation failure.
- **Active Authentication** – INTERNAL AUTHENTICATE responses are verified against DG15 public keys and fail when the challenge is
  altered.
- **Secure messaging anti-replay** – re-sending a protected APDU with the same SSC is rejected by the chip emulator.
- **Lifecycle gating** – PRE-PERSONALIZED → PERSONALIZED → LOCKED transitions are enforced, with personalization commands returning `6986`/`6985` outside of PREP.

### Manual Scenarios
| Scenario | Command | Notes |
|----------|---------|-------|
| Issuer personalization CLI | ```bash mvn -q exec:java -Dexec.mainClass=emu.IssuerMain -Dexec.args='--doc-number=123456789 --date-of-birth=750101 --date-of-expiry=250101 --output target/issuer' ``` | Boots a simulator, writes EF.COM/DG1+artifacts, loads MRZ secrets, and exports binaries plus a manifest to `target/issuer`. |
| Happy Path (Issuance + PA) | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa' ``` | Demonstrates full workflow with successful passive authentication. |
| Corrupted DG2 | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa --corrupt-dg2' ``` | Ensures metadata extractor and PA fail closed on tampered biometric data. |
| Oversized DG2 | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --large-dg2' ``` | Validates large-file guardrails; DG2 parsing is skipped with a clear warning. |
| PACE with MRZ | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --doc=123456789 --dob=750101 --doe=250101' ``` | Confirms MRZ-derived PACE succeeds when secrets align. |
| PACE with CAN | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --can=123456 --doc=123456789 --dob=750101 --doe=250101' ``` | Seeds and consumes a CAN credential for PACE; adapt to `--pin/--puk` as needed. |
| BAC Fallback | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --can=000000 --doc=123456789 --dob=750101 --doe=250101' ``` | Illustrates automatic BAC fallback after a failed CAN-based PACE attempt. |
| Active Authentication (RSA) | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --require-aa' ``` | Forces a DG15-backed RSA AA verification; check for both `PUT AA ... → SW=9000` lines during seeding before the signature test. |
| JSON Session Report | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --out target/session-report.json' ``` | Emits `target/session-report.json` with session, PA, AA, and DG summaries for CI ingestion. |
| PACE Profile Preference | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --pace-prefer=IM' ``` | Forces the integrated-mapping profile when both GM and IM are advertised; logs whether the preference was honoured. |
| Open EF.COM/EF.SOD Policy | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --open-com-sod' ``` | Enables the open-read toggle so COM/SOD are accessible without secure messaging after LOCKED. |
| TA Gating (no credentials) | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace' ``` | Shows DG3/DG4 remain blocked (`SW=6985`) when no CVC/terminal key is supplied, even after PACE→CA. |
| Terminal Authentication (DG3/DG4) | ```bash mvn -q exec:java -Dexec.mainClass=emu.GenerateDemoTaChainMain && mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --ta-cvc target/ta-demo/cvca.cvc --ta-cvc target/ta-demo/terminal.cvc --ta-key target/ta-demo/terminal.key' ``` | Performs PACE→CA→TA with the demo chain and reports DG3/DG4 accessibility. |

### UI Issuer Presets

The desktop runner now surfaces issuer-focused presets that drive the in-process `IssuerMain` helper before chaining into familiar read scenarios:

- **Issuer: Full LDS** – seeds the emulator with the default DG set (DG1/DG2/DG3/DG4/DG14/DG15), exports `manifest.json`, EF binaries, and trust anchors to `target/ui-issuer/full/`, then performs a PACE→PA read to confirm integrity.
- **Issuer: Minimal DG1/DG2** – disables DG3/DG4/DG14/DG15 to showcase a lean LDS; the manifest and `EF.COM.bin`/`EF.DG1.bin`/`EF.DG2.bin`/`EF.SOD.bin` land in `target/ui-issuer/minimal/` before a BAC/PA read validates the reduced dataset.
- **Issuer: Corrupt DG2** – produces a tampered DG2 alongside `manifest.json` in `target/ui-issuer/corrupt/` so the follow-up read demonstrates PA failure reporting and artifact capture for negative drills.

### Issuer Simulator Quick Reference

Inspect the issuer CLI switches with:

```bash
mvn -q exec:java -Dexec.mainClass=emu.IssuerMain -Dexec.args='--help'
```

By default artifacts are exported to `target/issuer/` and include:

- `manifest.json` listing lifecycle targets, hash algorithms, and relative paths for each generated file.
- Individual LDS binaries (`EF.COM.bin`, `EF.DG1.bin`, …) alongside the signed `EF.SOD.bin`.
- Trust anchors (`CSCA.cer`) and the document signer certificate (`DSC.cer`) ready for use with `PassiveAuthentication.verify`.
- Optional DG2 preview images under `preview/` when `--face-preview` (or `--face-preview-dir`) is provided.

Representative invocations:

*Full LDS + lock with open reads + validation*
```bash
mvn -q exec:java -Dexec.mainClass=emu.IssuerMain \
  -Dexec.args='--doc-number 123456789 --lifecycle PERSONALIZED --lifecycle LOCKED --open-read=true --validate'
```

*Minimal DG1/DG2 export*
```bash
mvn -q exec:java -Dexec.mainClass=emu.IssuerMain \
  -Dexec.args='--disable-dg 3 --disable-dg 4 --disable-dg 14 --disable-dg 15 --lifecycle PERSONALIZED'
```

*EAC-ready issuance (PACE CAN + TA metadata + preview)*
```bash
mvn -q exec:java -Dexec.mainClass=emu.IssuerMain \
  -Dexec.args='--pace-can 123456 --include-ta --face-preview --lifecycle PERSONALIZED --lifecycle LOCKED'
```

*Negative DG2 corruption for PA failure drills*
```bash
mvn -q exec:java -Dexec.mainClass=emu.IssuerMain \
  -Dexec.args='--corrupt-dg2 --lifecycle PERSONALIZED --validate'
```

Each run prints the absolute `target/issuer/manifest.json` location plus the exported trust-anchor paths so you can feed them directly into the passive-authentication verifier or compare them against the template in `docs/issuer-report-template.md`.

### Lifecycle State Controls

- `ReadDG1Main` now seals the emulator at the end of personalization by issuing `PUT DATA 0xDE/0xAF` (PERSONALIZED) followed by `PUT DATA 0xDE/0xAD` (LOCKED). Look for the log entries `SET LIFECYCLE → PERSONALIZED → SW=9000` and `SET LIFECYCLE → LOCKED → SW=9000` to confirm the transition.
- Any subsequent attempt to personalize (for example re-running `PUT MRZ TLV`) will receive `SW=6986` once the chip is personalized and `SW=6985` after it is locked.
- To exercise the lifecycle logic in isolation run `mvn -q test -Dtest=Module9LifecycleTest`, which drives the state machine and asserts the expected status words.

## 🛡️ Security Features
Implemented hardening features include:
- **Basic Access Control (BAC)** for initial session establishment.
- **PACE-first Negotiation** using EF.CardAccess data, with host CLI options for MRZ, CAN, PIN, or PUK secrets and automatic BAC fallback when negotiation fails.
- **EF.CardAccess/DG14 Provisioning** during personalization so host tooling can exercise PACE/EAC awareness immediately.
- **Chip Authentication Awareness** with DG14 parsing and secure-messaging upgrade when the card advertises CA support.
- **Lifecycle enforcement** with explicit PRE-PERSONALIZED → PERSONALIZED → LOCKED transitions gated by `PUT DATA 0xDE/0xAF` and `PUT DATA 0xDE/0xAD`, preventing any further personalization once the emulator is sealed.
- **Terminal Authentication (TA)** – Host performs PSO:VERIFY CERT, protected GET CHALLENGE, and EXTERNAL AUTHENTICATE to unlock DG3/DG4 when provided with a CVCA→Terminal chain and private key.
- **Active Authentication Verification** – Host performs `INTERNAL AUTHENTICATE` and validates the RSA signature using the DG15 public key when requested with `--require-aa`.
- **PACE GM Implementation** on the applet side enables full AES secure messaging once the correct secret is provided.
- **Demo TA Chain Generator** (`GenerateDemoTaChainMain`) produces a CVCA→Terminal certificate chain and terminal key for quick TA testing.
- **Secure Messaging (AES + MAC)** to protect APDU exchanges.
- **Anti-Replay Protection** through SSC monotonicity checks.
- **LDS Personalization** for EF.COM, EF.DG1, EF.DG2, EF.DG3, EF.DG4, EF.DG15, EF.SOD with synthetic face, fingerprint, and iris assets.
- **Passive Authentication** end-to-end (hash verification, SOD signature validation, DSC→CSCA chain building).
- **DG2 Metadata Extraction** and reporting without exposing raw biometric data.
- **Logging hygiene** – APDU tracer and applet diagnostics avoid printing keys, SSC values, or PACE tokens; only metadata such as lengths/OIDs is emitted.
- **Negative Case Handling** to capture corrupted or oversized biometric payloads gracefully.

## 🧭 Roadmap
Upcoming enhancements (not yet implemented):
- **Additional PACE mappings and Chip Authentication refinements** to broaden interoperability beyond the current GM profile.
- **Active Authentication negative cases and ECDSA support** for broader credential coverage.
- **Extended PACE options** (PIN/PUK/CAN inputs) and richer error-injection scenarios.

## 🤝 Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit changes with clear messages.
4. Run the happy-path scenario to ensure regressions are caught.
5. Open a Pull Request with a descriptive summary.

Please ensure all code is formatted (Maven checks) and includes relevant documentation.

## 📄 License
Project is provided for educational and testing purposes; license terms follow the repository’s LICENSE file (if provided). Respect upstream JMRTD and Bouncy Castle licenses when redistributing.
