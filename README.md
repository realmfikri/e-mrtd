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

Each run logs:
- Personalization steps and LDS writing.
- BAC establishment and secure messaging status.
- DG1 (MRZ) parsing output.
- DG2 metadata (image size, MIME type, quality metrics).
- Passive authentication results, including hash validation, signature verification, and trust chain status.
- Session summary (BAC/PACE/CA placeholders).

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

## 🛡️ Security Features
Implemented hardening features include:
- **Basic Access Control (BAC)** for initial session establishment.
- **Secure Messaging (AES + MAC)** to protect APDU exchanges.
- **Anti-Replay Protection** through SSC monotonicity checks.
- **LDS Personalization** for EF.COM, EF.DG1, EF.DG2, EF.DG15, EF.SOD with synthetic face image generation.
- **Passive Authentication** end-to-end (hash verification, SOD signature validation, DSC→CSCA chain building).
- **DG2 Metadata Extraction** and reporting without exposing raw biometric data.
- **Negative Case Handling** to capture corrupted or oversized biometric payloads gracefully.

## 🧭 Roadmap
Upcoming enhancements (not yet implemented):
- **PACE-first workflows** with BAC fallback.
- **Chip Authentication (CA)** support.
- **Terminal Authentication (TA)** parsing + optional execution.

## 🤝 Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit changes with clear messages.
4. Run the happy-path scenario to ensure regressions are caught.
5. Open a Pull Request with a descriptive summary.

Please ensure all code is formatted (Maven checks) and includes relevant documentation.

## 📄 License
Project is provided for educational and testing purposes; license terms follow the repository’s LICENSE file (if provided). Respect upstream JMRTD and Bouncy Castle licenses when redistributing.
