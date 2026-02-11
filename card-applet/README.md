# card-applet

This directory is the home for card applet workstreams and related assets.

## Structure

- `applet-src/` — source code for the applet implementation.
- `tools/` — helper scripts and utilities used during development.
- `spec-notes/` — notes and references derived from relevant specifications.
- `sample-data/` — example inputs/outputs and test vectors.
- `build/` — local build artifacts output target.

## Reproducible CAP build entrypoint

Use `card-applet/Makefile` to compile Java Card sources and generate a CAP file.

### Compatibility

- Java Card Development Kit: **2.2.1** (recommended, verified layout expected by the Makefile).
- Java runtime for tooling: set `JAVA_HOME` to a JDK that works with your Java Card kit installation (commonly JDK 8 for legacy 2.2.x kits).

### Required environment variables

- `JCPATH` — path to Java Card kit root (must contain `lib/api.jar`, `lib/converter.jar`, and `api_export_files/`).
- `JAVA_HOME` — path to JDK root (must contain `bin/javac` and `bin/java`).

### Build command examples

From repository root:

```bash
JCPATH=/opt/java_card_kit-2_2_1 \
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
make -C card-applet
```

From inside `card-applet/`:

```bash
export JCPATH=/opt/java_card_kit-2_2_1
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
make
```

### Output

- Final CAP artifact: `card-applet/build/applet.cap`.

## PC/SC smoke-check script

A minimal reader-side verification script is available at:

- `tools/pcsc_smoke_read.py`

It performs the following checks against the educational applet:

1. `SELECT` by AID and expects status word `9000`.
2. `SELECT` EF by FID for `EF.COM` (`011E`) and `EF.DG1` (`0101`) and expects `9000`.
3. `READ BINARY` using offsets and verifies the returned bytes against:
   - `sample-data/EF.COM.bin`
   - `sample-data/EF.DG1.bin`
4. Prints each status word and a pass/fail summary.

### Usage examples

```bash
python3 card-applet/tools/pcsc_smoke_read.py --reader-index 0
python3 card-applet/tools/pcsc_smoke_read.py --reader-filter ACS --reader-filter Contact
python3 card-applet/tools/pcsc_smoke_read.py --reader "Identive CLOUD 3700 F Contact Reader 00 00"
```

Optional connection-string selector examples:

```bash
python3 card-applet/tools/pcsc_smoke_read.py --connection-string 'pcsc://index/0'
python3 card-applet/tools/pcsc_smoke_read.py --connection-string 'pcsc://filter/ACS'
python3 card-applet/tools/pcsc_smoke_read.py --connection-string 'pcsc://Identive CLOUD 3700 F Contact Reader 00 00'
```

> Note: the script requires `pyscard` (`pip install pyscard`) and a working PC/SC service/reader.
