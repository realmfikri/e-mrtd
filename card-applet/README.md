# card-applet

Java Card applet build/install tooling for eMRTD simulation.

> Security scope: this repository is for development/testing only, not production document issuance.

## Applet profiles

`card-applet` supports two profiles:

- `passport` (default): BAC-capable applet (`sos.passportapplet.PassportApplet`) aligned with the existing JMRTD/PassportService reader flow.
- `educational`: minimal plaintext demo applet (`cardapplet.EducationalEmrtdApplet`).

Set with `APPLET_PROFILE` (defaults to `passport`).

## Prerequisites

- `JAVA_HOME` set to a JDK path.
- `JCKIT` set to a Java Card kit path.
- `gp` (GlobalPlatformPro) available in `PATH`.
- PC/SC reader configured (for physical cards).

## Quick start (real reader compatible)

Run from repository root:

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export JCKIT="$HOME/tools"
export APPLET_PROFILE=passport

export GP_READER="ACR1552 1S CL Reader PICC"
export GP_NFC_BLOCK_SIZE=64
export GP_EXTRA_OPTS="--mode ENC --pcsc-exclusive"

make -C card-applet clean all JC_TARGET=3.0.5
./card-applet/tools/uninstall.sh || true
./card-applet/tools/install.sh
./card-applet/tools/personalize_passport.sh
./card-applet/tools/apdu_smoke.sh
```

`apdu_smoke.sh` on `passport` profile is expected to show:
- `SELECT`/`PUT DATA`/`GET CHALLENGE` as `9000`
- direct `READ BINARY` as `6982` (normal before BAC secure messaging)

When switching between `educational` and `passport` profiles, keep `UNINSTALL_ALL_PROFILES=1` (default) so stale packages from the other profile are also removed.

Default personalization values in `personalize_passport.sh`:

- Document number: `C4X9L2Q7<`
- DOB: `030211` (11 Feb 2003)
- DOE: `280211` (11 Feb 2028)
- DG1 identity: `MUHAMAD<<FIKRI`, nationality `IDN`

Override MRZ seed values if needed:

```bash
./card-applet/tools/personalize_passport.sh \
  --doc-number C4X9L2Q7 \
  --dob 030211 \
  --doe 280211
```

Optional DG2 write:

```bash
./card-applet/tools/personalize_passport.sh --with-dg2
# or directly:
./card-applet/tools/load_dg2.sh card-applet/sample-data/passport/EF.DG2.bin
```

For `passport`, the DG2 loader verifies write completion and expects final plain `READ BINARY` to be blocked with `6982` until BAC is performed by the reader stack.

## Test with existing reader UI

Use the existing app reader flow (no reader code changes required):

```bash
mvn -q -DskipTests javafx:run
```

In the UI:

1. Open **Read passport**.
2. Enter MRZ fields:
   - Document number: `C4X9L2Q7` (UI pads to MRZ length)
   - Date of birth: `030211`
   - Date of expiry: `280211`
3. Click **Read passport**.

If card transport fails before APDU (`SCARD_W_UNPOWERED_CARD`), re-seat the card/tag and retry with stable reader contact.

## Troubleshooting install

- If install reports `INSTALL [for load] failed: 0x6985`, run uninstall first (the script now tries CAP-driven uninstall automatically):

```bash
UNINSTALL_ALL_PROFILES=1 ./card-applet/tools/uninstall.sh
./card-applet/tools/install.sh
```

- If you still see reader sharing errors (`SCARD_E_SHARING_VIOLATION`), close other apps using PC/SC (including running JavaFX reader windows) and retry.
- Logs are written under `card-applet/tools/out/`:
  - `gp_uninstall_*.log`
  - `gp_pre_install_*.log`
  - `gp_install_*.log`
  - `gp_post_install_*.log`

## Educational profile (legacy smoke flow)

```bash
export APPLET_PROFILE=educational
make -C card-applet clean all JC_TARGET=3.0.5
./card-applet/tools/install.sh
./card-applet/tools/apdu_smoke.sh
```

## Notes

- `tools/gp_env.sh` switches default AIDs based on `APPLET_PROFILE`.
- `tools/apdu_smoke.sh` and `tools/load_dg2.sh` are profile-aware.
- Build output CAP path is always `card-applet/build/applet.cap`.
