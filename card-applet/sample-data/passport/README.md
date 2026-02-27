# Passport profile sample binaries

These files are ICAO LDS-encoded payloads intended for the `passport` applet profile:

- `EF.COM.bin`
- `EF.DG1.bin`
- `EF.DG2.bin` (optional, used only with `--with-dg2`)

Current placeholder identity in `EF.DG1.bin` / MRZ seed defaults:

- Name: `MUHAMAD<<FIKRI`
- Document number: `C4X9L2Q7<` (auto-padded TD3 length)
- Date of birth: `030211` (11 Feb 2003)
- Date of expiry: `280211` (11 Feb 2028)
- Sex: `M`
- Issuing state / nationality: `IDN`

You can rewrite MRZ keys at personalization time via:

```bash
./card-applet/tools/personalize_passport.sh --doc-number <DOC> --dob <YYMMDD> --doe <YYMMDD>
```

If you change MRZ seed values, keep the reader-side BAC inputs aligned.
