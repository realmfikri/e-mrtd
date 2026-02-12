# ICAO Doc 9303 Mapping Notes (Educational Demo Applet)

This note maps selected **Part 10 (LDS logical data structure / file access)** expectations to the behavior currently implemented in `EducationalEmrtdApplet`, and explicitly defines what is **out of scope** for Part 11/12 security protocols.

## 1) Part 10 LDS-related behavior mapping

The implementation is intentionally minimal and supports a tiny, fixed file model:

- `EF.COM` at FID `011E`
- `EF.DG1` at FID `0101`

### Mapping table

| LDS/command expectation (Part 10-oriented) | Implemented behavior in this repo | Where to verify |
|---|---|---|
| Select the applet/DF by AID | `SELECT` (`INS=A4`, `P1=04`) compares incoming AID to applet AID and returns `9000` on match, `6A82` on mismatch. | `applet-src/EducationalEmrtdApplet.java` (`processSelect`, `selectByAid`); smoke test `SELECT AID` step in `tools/pcsc_smoke_read.py`. |
| Select elementary file by file ID | `SELECT` (`INS=A4`, `P1=00` or `02`) accepts 2-byte FID. Known FIDs (`011E`, `0101`) become current EF; unknown FID returns `6A82`. | `applet-src/EducationalEmrtdApplet.java` (`selectByFid`), smoke test `SELECT EF.COM` / `SELECT EF.DG1`. |
| Read data from selected EF | `READ BINARY` (`INS=B0`) returns slices from current EF based on offset and Le. Supports offset-based reads used by host tools. | `applet-src/EducationalEmrtdApplet.java` (`processReadBinary`), smoke test read-slice checks. |
| Status words for malformed/unsupported use | Uses `6700` for wrong length, `6A86` for wrong P1/P2 on unsupported SELECT mode, `6B00` for invalid offset, `6A82` for missing file, and standard `6D00` for unsupported INS. | Constants and throws in `applet-src/EducationalEmrtdApplet.java`. |
| Deterministic sample payloads for EF content checks | EF.COM and EF.DG1 are static in-applet byte arrays; sample-data files mirror expected reads for smoke validation. | `applet-src/EducationalEmrtdApplet.java`; `sample-data/EF_COM.bin`; `sample-data/DG1.bin`; `tools/pcsc_smoke_read.py`. |

### Operational command/file linkage

- Build CAP: `card-applet/Makefile` -> output `card-applet/build/applet.cap`.
- Install CAP to card: GlobalPlatformPro command examples in `card-applet/README.md`.
- Verify Part 10-like command flow: run `python3 card-applet/tools/pcsc_smoke_read.py ...`.

## 2) Explicit Part 11 / Part 12 scope boundaries

The following points are intentional constraints of this educational artifact.

### 2.1 BAC/PACE/SM/EAC

- **BAC**: not implemented.
- **PACE**: not implemented.
- **Secure Messaging (SM)**: not implemented.
- **EAC / terminal-authentication flows**: not implemented.

If any toy/demo hook is added in future, it must remain clearly marked non-compliant and non-secure.

### 2.2 Return/security behavior and rationale

- The applet serves plain APDU command flow for didactic testing.
- There is no cryptographic session establishment and no secure channel protection for reads.
- Optional demo switch `ENFORCE_DG1_READ_POLICY` can force `6982` for DG1 reads to demonstrate policy signaling only; this is not equivalent to BAC/PACE/EAC enforcement.

Rationale: keep implementation compact for APDU/file selection teaching and reproducible smoke tests, while avoiding any implication of production-grade security protocol support.

### 2.3 EF.SOD handling statement

- In this demo, **chip-side PKI validation is out of scope**.
- If/when EF.SOD is exposed, it is treated as **data only** to be read by host tools; passive-authentication trust chain and signature verification are host responsibilities, not card-side validation in this applet.

### 2.4 Non-production disclaimer

This repository content is **demo/test only** and is not suitable for:

- real ePassport issuance,
- real border/identity decisions,
- impersonation-resistant identity proofing,
- security certification or compliance claims.
