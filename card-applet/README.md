# card-applet

Educational Java Card applet and tooling for a **demo eMRTD-like** command flow.

> **Security scope warning:** this applet is for demonstration/testing only, not for real document issuance, border-control use, or impersonation scenarios.

## Build the CAP (exact commands)

The canonical build entrypoint is `card-applet/build.sh` and requires both `JCKIT` and `JAVA_HOME` (legacy `JCPATH` is auto-mapped to `JCKIT` for compatibility).

### 1) Canonical one-command build from repository root

```bash
JCKIT=/opt/java_card_kit-2_2_1 \
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
./card-applet/build.sh
```

### 2) Equivalent build from inside `card-applet/`

```bash
cd card-applet
export JCKIT=/opt/java_card_kit-2_2_1
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
./build.sh
```

### 3) Legacy compatibility (`JCPATH`)

```bash
JCPATH=/opt/java_card_kit-2_2_1 \
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
./card-applet/build.sh
```

### What the Makefile expects

- `JAVA_HOME/bin/javac` and `JAVA_HOME/bin/java`
- `JCKIT/lib/api.jar`
- `JCKIT/lib/converter.jar`
- `JCKIT/lib/offcardverifier.jar`
- `JCKIT/api_export_files/`

## Verify CAP output path

The Makefile copies the converter output to `card-applet/build/applet.cap`.

Run one of these checks:

```bash
test -f card-applet/build/applet.cap && echo "CAP OK: card-applet/build/applet.cap"
```

```bash
ls -l card-applet/build/applet.cap
```

## Install/create with GlobalPlatformPro (`gp`)

Default values from the Makefile:

- Package AID: `A0000002471000`
- Applet AID: `A000000247100001`
- Applet class: `cardapplet.EducationalEmrtdApplet`
- CAP file: `card-applet/build/applet.cap`

### Simple install (uses CAP metadata)

```bash
gp -install card-applet/build/applet.cap
```

### Explicit package/applet/create install

```bash
gp -install card-applet/build/applet.cap \
  -package A0000002471000 \
  -applet A000000247100001 \
  -create A000000247100001
```

### Optional: install then create as separate steps

```bash
gp -install card-applet/build/applet.cap -package A0000002471000 -applet A000000247100001
```

```bash
gp -create A000000247100001
```

> Tip: add your reader selector flags (for example `-r <reader>`) as needed for your environment.

## Run the smoke-test tool

The smoke-test script validates SELECT and READ BINARY behavior against `sample-data/EF_COM.bin` and `sample-data/DG1.bin`.

During build, missing `sample-data/EF_COM.bin` and `sample-data/DG1.bin` are auto-generated with synthetic `TEST ONLY` markers, and demo placeholders are created if absent.

Basic run:

```bash
python3 card-applet/tools/pcsc_smoke_read.py --reader-index 0
```

Alternative selectors:

```bash
python3 card-applet/tools/pcsc_smoke_read.py --reader "Exact Reader Name"
```

```bash
python3 card-applet/tools/pcsc_smoke_read.py --reader-filter ACS --reader-filter Contact
```

Connection-string form:

```bash
python3 card-applet/tools/pcsc_smoke_read.py --connection-string 'pcsc://index/0'
```

## Spec notes

See `card-applet/spec-notes/part10-part11-part12-scope.md` for a mapping of ICAO Part 10 requirements to implemented behavior and explicit Part 11/12 scope boundaries.
