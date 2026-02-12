# card-applet

Educational Java Card applet and tooling for a **demo eMRTD-like** command flow.

> **Security scope warning:** this applet is for demonstration/testing only, not for real document issuance, border-control use, or impersonation scenarios.

## Prerequisites

- **Java/JDK**: JDK 8+ with `JAVA_HOME` set (the build flow uses `javac` and `java`).
- **Java Card Development Kit**: set `JCKIT` to your Java Card kit path (legacy `JCPATH` is accepted and mapped to `JCKIT`).
- **GlobalPlatformPro (`gp`)**: required to install/delete applets on card/simulator.
- **OpenSC (`opensc-tool`)**: useful for reader/PCSC troubleshooting.

## Commands

Run from repository root unless noted.

- **Build**

  ```bash
  ./card-applet/build.sh
  # or:
  make -C card-applet
  ```

- **Install**

  ```bash
  ./card-applet/tools/install.sh
  ```

- **Uninstall**

  ```bash
  ./card-applet/tools/uninstall.sh
  ```

- **Smoke test**

  ```bash
  ./card-applet/tools/apdu_smoke.sh
  ```

## Implemented behavior

- `SELECT` by applet AID (`00 A4 04 0C ...`).
- `SELECT FILE` by FID (`00 A4 02 0C 02 <FID>`).
- `READ BINARY` offset-based reads (`00 B0 <offset_hi> <offset_lo> <Le>`).
- `EF.COM` and `DG1` are available for smoke/demo flows.

## Not implemented

- BAC/PACE.
- Secure messaging.
- Real `EF.SOD` signatures or production passport semantics.

## Troubleshooting appendix

Manual APDU examples (hex, spaces optional):

- **Select applet by AID**

  ```text
  00 A4 04 0C 08 A0 00 00 02 47 10 00 01
  ```

  Expected status word: `9000`.

- **Select EF.COM by FID (`011E`)**

  ```text
  00 A4 02 0C 02 01 1E
  ```

  Expected status word: `9000`.

- **Read first bytes from selected EF (offset `0000`, Le `10`)**

  ```text
  00 B0 00 00 10
  ```

  Expected status word: `9000` (with up to `0x10` response bytes).

- **Select DG1 by FID (`0101`)**

  ```text
  00 A4 02 0C 02 01 01
  ```

  Expected status word: `9000`.

- **Read DG1 slice (offset `0010`, Le `20`)**

  ```text
  00 B0 00 10 20
  ```

  Expected status word: `9000` while in range; out-of-range reads may return an error status depending on card/runtime.

If APDUs fail, verify reader visibility first:

```bash
opensc-tool -l
```

## Spec notes

See `card-applet/spec-notes/part10-part11-part12-scope.md` for a mapping of ICAO Part 10 requirements to implemented behavior and explicit Part 11/12 scope boundaries.
