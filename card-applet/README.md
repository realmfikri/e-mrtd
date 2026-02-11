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
