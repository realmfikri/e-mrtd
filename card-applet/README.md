# card-applet

Educational Java Card applet and tooling for a **demo eMRTD-like** command flow.

> **Security scope warning:** this applet is for demonstration/testing only, not for real document issuance, border-control use, or impersonation scenarios.

## Build the CAP (exact commands)

The build is driven by `card-applet/Makefile` and requires both `JCPATH` and `JAVA_HOME`.

### 1) One-shot build from repository root

```bash
JCPATH=/opt/java_card_kit-2_2_1 \
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
make -C card-applet clean all
```

### 2) Build from inside `card-applet/`

```bash
cd card-applet
export JCPATH=/opt/java_card_kit-2_2_1
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
make clean all
```

### What the Makefile expects

- `JAVA_HOME/bin/javac` and `JAVA_HOME/bin/java`
- `JCPATH/lib/api.jar`
- `JCPATH/lib/converter.jar`
- `JCPATH/lib/offcardverifier.jar`
- `JCPATH/api_export_files/`

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

- Package AID: `D2760001240100`
- Applet AID: `D276000124010001`
- Applet class: `cardapplet.EducationalEmrtdApplet`
- CAP file: `card-applet/build/applet.cap`

### Simple install (uses CAP metadata)

```bash
gp -install card-applet/build/applet.cap
```

### Explicit package/applet/create install

```bash
gp -install card-applet/build/applet.cap \
  -package D2760001240100 \
  -applet D276000124010001 \
  -create D276000124010001
```

### Optional: install then create as separate steps

```bash
gp -install card-applet/build/applet.cap -package D2760001240100 -applet D276000124010001
```

```bash
gp -create D276000124010001
```

> Tip: add your reader selector flags (for example `-r <reader>`) as needed for your environment.

## Run the smoke-test tool

The smoke-test script validates SELECT and READ BINARY behavior against `sample-data/EF.COM.bin` and `sample-data/EF.DG1.bin`.

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
