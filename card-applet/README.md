# card-applet

Educational Java Card applet and tooling for a **demo eMRTD-like** command flow.

> **Security scope warning:** this applet is for demonstration/testing only, not for real document issuance, border-control use, or impersonation scenarios.

## Prerequisites

- **Java/JDK**: a JDK with `JAVA_HOME` set (the build invokes `javac` and `java`).
  - The CAP conversion toolchain typically expects **Java 8 classfiles**, so the Makefile compiles with `--release 8` by default.
- **Java Card kit**: set `JCKIT` to your Java Card kit path (legacy `JCPATH` is accepted and mapped to `JCKIT`).
- **GlobalPlatformPro (`gp`)**: required to install/delete applets on card/simulator.
- **OpenSC (`opensc-tool`)**: useful for reader/PCSC troubleshooting.

### Supported Java Card kit layouts

This repo supports two common `JCKIT` layouts:

1. Classic SDK layout (older):
   - `lib/api.jar`
   - `lib/converter.jar`
   - `lib/offcardverifier.jar` (optional here, but common in classic SDKs)
   - `api_export_files/`

2. Tools-only layout (newer, like `java_card_devkit_tools`):
   - `bin/converter.sh`
   - `lib/tools.jar`
   - `lib/api_classic-<version>.jar`
   - export files are embedded inside `tools.jar` (extracted during build into `card-applet/build/jckit_exports/`)

If you have a tools-only kit, set `JCKIT` to the directory that contains `bin/` and `lib/` (not a nested folder name).

## Commands

Run from repository root unless noted.

- **Build**

  ```bash
  export JAVA_HOME=/path/to/jdk
  export JCKIT=/path/to/jckit
  ./card-applet/build.sh
  # or:
  make -C card-applet
  ```

  Useful overrides:

  ```bash
  # If your card is not Java Card 3.2.0, set the target platform version used by converter/export files.
  make -C card-applet JC_TARGET=3.0.5

  # If you want to change the Java classfile level (converter usually wants 8 / classfile 52.0).
  make -C card-applet JAVAC_RELEASE=8
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

## Installing To A Physical Card

1. Build a CAP:

   ```bash
   export JAVA_HOME=/path/to/jdk
   export JCKIT=/path/to/jckit
   ./card-applet/build.sh
   ```

   Output is `card-applet/build/applet.cap`.

2. Install using GlobalPlatformPro:

   ```bash
   # Optional: override reader name (see `gp -r` to list readers)
   export GP_READER="ACR1552 1S CL Reader PICC"

   ./card-applet/tools/install.sh
   ```

3. Run a quick APDU sanity check:

   ```bash
   ./card-applet/tools/apdu_smoke.sh
   ```

4. Uninstall (optional):

   ```bash
   ./card-applet/tools/uninstall.sh
   ```

## Implemented behavior

- `SELECT` by applet AID (`00 A4 04 0C ...`).
- `SELECT FILE` by FID (`00 A4 02 0C 02 <FID>`).
- `SELECT MF` (`3F00`) and a minimal in-memory filesystem demo.
- `CREATE FILE` (`00 E0 00 00 ...`) for one DF and one transparent EF.
- `UPDATE BINARY` (`00 D6 ...`) for writes to the created EF.
- `READ BINARY` offset-based reads (`00 B0 <offset_hi> <offset_lo> <Le>`).
- `EF.COM` and `DG1` are available for smoke/demo flows.

### Filesystem demo scope

This applet now supports a bounded educational filesystem flow:

1. Select MF (`3F00`)
2. Create one DF under MF
3. Create one transparent EF under that DF
4. Write bytes with `UPDATE BINARY`
5. Read bytes back with `READ BINARY`

Boundaries (intentional):

- only one dynamic DF and one dynamic EF slot are supported
- no delete/resize command
- not a full ISO 7816 filesystem implementation

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

- **Select MF (`3F00`)**

  ```text
  00 A4 00 0C 02 3F 00
  ```

  Expected status word: `9000`.

- **Create DF (`FID=1100`)**

  ```text
  00 E0 00 00 07 83 02 11 00 82 01 38
  ```

  Expected status word: `9000` (requires MF selected).

- **Create EF (`FID=1101`, size=0x40)**

  ```text
  00 E0 00 00 0A 83 02 11 01 82 01 01 80 01 40
  ```

  Expected status word: `9000` (requires DF selected).

- **Write EF bytes (offset `0000`)**

  ```text
  00 D6 00 00 10 46 53 44 45 4D 4F 5F 57 52 49 54 45 5F 54 45 53
  ```

  Expected status word: `9000`.

- **Read EF bytes (offset `0000`, Le `10`)**

  ```text
  00 B0 00 00 10
  ```

  Expected status word: `9000` and previously written payload.

Common SW notes for filesystem operations:

- `6985`: wrong selection context (for example creating DF without selecting MF first, or EF without selecting DF first).
- `6A80`: malformed CREATE FILE payload.
- `6A81`: unsupported file descriptor or unsupported write target.
- `6A84`: requested dynamic EF size exceeds implementation limit.

If APDUs fail, verify reader visibility first:

```bash
opensc-tool -l
```

## Spec notes

See `card-applet/spec-notes/part10-part11-part12-scope.md` for a mapping of ICAO Part 10 requirements to implemented behavior and explicit Part 11/12 scope boundaries.
