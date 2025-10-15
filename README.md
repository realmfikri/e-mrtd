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
- Dynamic personalization for key data groups (EF.COM, EF.DG1, EF.DG2, EF.DG15, EF.SOD).
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

Add the repeatable flag `--ta-cvc <path/to/cvc>` to load terminal authentication certificates for reporting. Supply a valid CVC file (for example, one produced by `GenerateDemoCvcMain`, see below); the host will parse and summarise the supplied CVCs without attempting to sign challenges.

When running inside a headless shell (e.g. CI), prepend `JAVA_TOOL_OPTIONS=-Djava.awt.headless=true` so the synthetic biometric generator can render without an X server.

### Generate Demo TA Certificates
```bash
mvn -q exec:java -Dexec.mainClass=emu.GenerateDemoCvcMain
```
- Produces `target/demo-terminal.cvc` and the matching private key `target/demo-terminal.key` (PKCS#8 PEM).
- Default issuer/holder uses the `UT` test country code; supply `--country <alpha2>` if you need something else.
- Combine the generated certificate with the reader using `--ta-cvc target/demo-terminal.cvc`.

Each run logs:
- Personalization steps and LDS writing.
- BAC establishment and secure messaging status.
- DG1 (MRZ) parsing output.
- DG2 metadata (image size, MIME type, quality metrics).
- Passive authentication results, including hash validation, signature verification, and trust chain status.
- Session summary covering PACE attempts, BAC fallback decisions, chip authentication status, and terminal authentication insights.

## 📁 Key Directories
```bash
src/main/java/sos/passportapplet/   # Applet (chip-side) logic
src/main/java/emu/                  # Host-side Java tooling (simulator, verifier)
```
Use these paths for navigation when inspecting or modifying code.

## 🧪 Test Scenarios
| Scenario | Command | Notes |
|----------|---------|-------|
| Happy Path (Issuance + PA) | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa' ``` | Demonstrates full workflow with successful passive authentication. |
| Corrupted DG2 | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --require-pa --corrupt-dg2' ``` | Ensures metadata extractor and PA fail closed on tampered biometric data. |
| Oversized DG2 | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --large-dg2' ``` | Validates large-file guardrails; DG2 parsing is skipped with a clear warning. |
| PACE with MRZ | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --doc=123456789 --dob=750101 --doe=250101' ``` | Confirms MRZ-derived PACE succeeds when secrets align. |
| PACE with CAN | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --can=123456 --doc=123456789 --dob=750101 --doe=250101' ``` | Seeds and consumes a CAN credential for PACE; adapt to `--pin/--puk` as needed. |
| BAC Fallback | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --can=000000 --doc=123456789 --dob=750101 --doe=250101' ``` | Illustrates automatic BAC fallback after a failed CAN-based PACE attempt. |
| Active Authentication (RSA) | ```bash mvn -q exec:java -Dexec.mainClass=emu.ReadDG1Main -Dexec.args='--seed --attempt-pace --require-aa' ``` | Forces a DG15-backed RSA AA verification; check for both `PUT AA ... → SW=9000` lines during seeding before the signature test. |

## 🛡️ Security Features
Implemented hardening features include:
- **Basic Access Control (BAC)** for initial session establishment.
- **PACE-first Negotiation** using EF.CardAccess data, with host CLI options for MRZ, CAN, PIN, or PUK secrets and automatic BAC fallback when negotiation fails.
- **EF.CardAccess/DG14 Provisioning** during personalization so host tooling can exercise PACE/EAC awareness immediately.
- **Chip Authentication Awareness** with DG14 parsing and secure-messaging upgrade when the card advertises CA support.
- **Terminal Authentication Reporting** – DG14 TA metadata is surfaced and user-supplied CVCs are parsed for inspection (host-side only, no signing yet).
- **Active Authentication Verification** – Host performs `INTERNAL AUTHENTICATE` and validates the RSA signature using the DG15 public key when requested with `--require-aa`.
- **PACE GM Implementation** on the applet side enables full AES secure messaging once the correct secret is provided.
- **Demo TA Certificate Generator** to mint synthetic CVCs for immediate TA inspection testing.
- **Secure Messaging (AES + MAC)** to protect APDU exchanges.
- **Anti-Replay Protection** through SSC monotonicity checks.
- **LDS Personalization** for EF.COM, EF.DG1, EF.DG2, EF.DG15, EF.SOD with synthetic face image generation.
- **Passive Authentication** end-to-end (hash verification, SOD signature validation, DSC→CSCA chain building).
- **DG2 Metadata Extraction** and reporting without exposing raw biometric data.
- **Negative Case Handling** to capture corrupted or oversized biometric payloads gracefully.

## 🧭 Roadmap
Upcoming enhancements (not yet implemented):
- **Additional PACE mappings and Chip Authentication refinements** to broaden interoperability beyond the current GM profile.
- **Terminal Authentication signing** flows to exercise EAC TA challenge/response.
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
