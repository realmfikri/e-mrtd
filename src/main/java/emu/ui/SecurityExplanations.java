package emu.ui;

import java.util.HashMap;
import java.util.Map;

final class SecurityExplanations {

  private static final Map<String, String> BY_NAME = new HashMap<>();

  private SecurityExplanations() {}

  static String forPreset(ScenarioPreset preset) {
    if (preset == null) {
      return defaultText();
    }
    return BY_NAME.getOrDefault(preset.getName(), defaultText());
  }

  private static String defaultText() {
    return "This scenario runs without a tailored security note.\n" +
        "All flows in this tool are designed to reflect ICAO Doc 9303 guidance: \n" +
        "- Passive Authentication validates LDS integrity and signer authenticity.\n" +
        "- PACE/BAC establish secure messaging and resist skimming/eavesdropping.\n" +
        "- Chip/Active Authentication prove chip genuineness.\n" +
        "- Terminal Authentication governs access to protected biometrics (DG3/DG4).";
  }

  static {
    // Passive Authentication (success)
    BY_NAME.put(
        "Passive Authentication (success)",
        String.join("\n",
            "What this demonstrates:",
            "- A seeded read under secure messaging that requires Passive Authentication (PA).",
            "ICAO Doc 9303 alignment:",
            "- PA verifies EF.SOD signature and DG hash values to detect tampering.",
            "- Secure messaging mitigates eavesdropping/replay; BAC used if PACE not negotiated.",
            "Security properties:",
            "- Integrity and authenticity of LDS via PA.",
            "- Confidentiality/integrity of APDUs via SM.",
            "Notes:",
            "- Biometrics (DG3/DG4) remain access‑controlled; no Terminal Authentication in this preset."));

    // Issuer: Full LDS
    BY_NAME.put(
        "Issuer: Full LDS",
        String.join("\n",
            "What this demonstrates:",
            "- In-process issuer personalisation of the default LDS set (DG1/DG2/DG3/DG4/DG14/DG15) followed by a secure read.",
            "ICAO Doc 9303 alignment:",
            "- Mirrors a production issuance flow with digest/signature defaults (" + emu.PersonalizationJob.defaultDigestAlgorithm()
                + " + " + emu.PersonalizationJob.defaultSignatureAlgorithm() + ") and PA validation.",
            "Security properties:",
            "- Exports CSCA/DS certificates, EF.SOD, and biometric groups that can be validated by Passive Authentication.",
            "Exported artefacts:",
            "- target/ui-issuer/full/manifest.json summarises lifecycle targets, algorithms, and file hashes.",
            "- Individual EF.COM/DG*.bin payloads plus EF.SOD.bin and trust anchors ready for reader integration.",
            "Notes:",
            "- The follow-up read exercises PACE→PA against the freshly written artifacts."));

    // Issuer: Minimal DG1/DG2
    BY_NAME.put(
        "Issuer: Minimal DG1/DG2",
        String.join("\n",
            "What this demonstrates:",
            "- Issuance constrained to EF.COM, EF.DG1, EF.DG2, and EF.SOD for lightweight deployments before a BAC read.",
            "ICAO Doc 9303 alignment:",
            "- Shows that PA still succeeds when optional biometrics (DG3/DG4) and EAC metadata (DG14/DG15) are omitted.",
            "Security properties:",
            "- Maintains LDS integrity/signature coverage while minimising data exposure.",
            "Exported artefacts:",
            "- target/ui-issuer/minimal/manifest.json documents the pruned DG list and lifecycle (PERSONALIZED).",
            "- Only EF.COM.bin, EF.DG1.bin, EF.DG2.bin, and EF.SOD.bin are generated alongside the trust anchors.",
            "Notes:",
            "- Reader falls back to BAC because DG14 is absent; PA still verifies EF.SOD hashes."));

    // Issuer: Corrupt DG2
    BY_NAME.put(
        "Issuer: Corrupt DG2",
        String.join("\n",
            "What this demonstrates:",
            "- A negative issuance where DG2 is intentionally corrupted to trigger PA failures immediately after export.",
            "ICAO Doc 9303 alignment:",
            "- Highlights reliance on EF.SOD digests during PA to reject tampered biometric data.",
            "Security properties:",
            "- Integrity breach detection: PA fails closed and the simulator’s own validation reports the mismatch.",
            "Exported artefacts:",
            "- target/ui-issuer/corrupt/manifest.json and EF.DG2.bin flag the corrupted hash for forensic review.",
            "- EF.SOD.bin contains digests that no longer match DG2, demonstrating failure evidence for auditors.",
            "Notes:",
            "- Use the follow-up read’s PA error to brief teams on tamper handling and evidence capture."));

    // BAC secure messaging fallback
    BY_NAME.put(
        "BAC secure messaging fallback",
        String.join("\n",
            "What this demonstrates:",
            "- Establishes secure messaging using BAC (MRZ‑derived keys) without attempting PACE.",
            "ICAO Doc 9303 alignment:",
            "- BAC is the legacy access control; still permitted but PACE is recommended.",
            "Security properties:",
            "- Protects against casual skimming; provides APDU confidentiality and integrity.",
            "Notes:",
            "- PACE offers stronger, modern cryptography and is preferred when available."));

    // PACE (custom secret)
    BY_NAME.put(
        "PACE (custom secret)",
        String.join("\n",
            "What this demonstrates:",
            "- PACE using the secret configured through the advanced options (MRZ/CAN/PIN/PUK).",
            "ICAO Doc 9303 alignment:",
            "- PACE replaces BAC for access control and key establishment.",
            "Security properties:",
            "- Strong resistance to skimming/eavesdropping; forward‑secure key establishment.",
            "Notes:",
            "- Use advanced options to tailor the secret being supplied to PACE."));

    // PACE profile preference (AES128)
    BY_NAME.put(
        "PACE profile preference (AES128)",
        String.join("\n",
            "What this demonstrates:",
            "- Negotiation preference for a PACE profile using AES‑128.",
            "ICAO Doc 9303 alignment:",
            "- PACE supports multiple algorithm suites; final choice is by chip capabilities.",
            "Security properties:",
            "- Modern cipher suite with adequate strength for eMRTD sessions.",
            "Notes:",
            "- Actual profile is negotiated; this sets a preference only."));

    // Chip Authentication upgrade
    BY_NAME.put(
        "Chip Authentication upgrade",
        String.join("\n",
            "What this demonstrates:",
            "- After reading DG14, upgrades SM via Chip Authentication (CA) and performs Active Authentication.",
            "ICAO Doc 9303 alignment:",
            "- CA provides chip genuineness and establishes fresh SM keys; preferred to AA where available.",
            "Security properties:",
            "- Mutual key agreement with the chip; strengthens authenticity and forward secrecy.",
            "Notes:",
            "- CA is functionally a stronger successor to Active Authentication."));

    // Terminal Authentication without credentials
    BY_NAME.put(
        "Terminal Authentication without credentials",
        String.join("\n",
            "What this demonstrates:",
            "- PACE, PA, and AA succeed but DG3/DG4 remain inaccessible without Terminal Authentication (TA).",
            "ICAO Doc 9303 alignment:",
            "- Biometrics are protected by Extended Access Control; TA is required for access.",
            "Security properties:",
            "- Access control enforcement on sensitive biometric EFs.",
            "Notes:",
            "- Provide TA credentials via advanced options to unlock DG3/DG4."));

    // Passive Authentication (tamper detection)
    BY_NAME.put(
        "Passive Authentication (tamper detection)",
        String.join("\n",
            "What this demonstrates:",
            "- A modified LDS (DG2) causes PA to fail due to hash mismatch.",
            "ICAO Doc 9303 alignment:",
            "- PA compares DG digests in EF.SOD with recomputed values.",
            "Security properties:",
            "- Strong integrity protection against post‑issuance modification.",
            "Notes:",
            "- This does not test CRL/ML checks; only integrity/signature validation."));

    // Passive Authentication (missing trust anchors)
    BY_NAME.put(
        "Passive Authentication (missing trust anchors)",
        String.join("\n",
            "What this demonstrates:",
            "- PA fails when the DS/CSCA trust chain cannot be validated.",
            "ICAO Doc 9303 alignment:",
            "- Chain building and policy checks are required for acceptance of EF.SOD.",
            "Security properties:",
            "- Prevents acceptance of data signed by unknown or untrusted issuers.",
            "Notes:",
            "- Populate a trust store with appropriate CSCA/DS certificates to succeed."));

    // Terminal Auth: DG3 Rights
    BY_NAME.put(
        "Terminal Auth: DG3 Rights",
        String.join("\n",
            "What this demonstrates:",
            "- TA with a CVC granting DG3 only; DG3 becomes readable while DG4 remains blocked.",
            "ICAO Doc 9303 alignment:",
            "- TA authorises terminal rights based on CVC privileges chained to CVCA.",
            "Security properties:",
            "- Fine‑grained authorisation for protected EFs.",
            "Notes:",
            "- Validity periods and certificate policies are enforced by the chip."));

    // Terminal Auth: DG4 Rights
    BY_NAME.put(
        "Terminal Auth: DG4 Rights",
        String.join("\n",
            "What this demonstrates:",
            "- TA with a CVC granting DG4 only; DG4 becomes readable while DG3 remains blocked.",
            "ICAO Doc 9303 alignment:",
            "- Same EAC/TA process; rights limited to DG4.",
            "Security properties:",
            "- Authorisation restricts access to sensitive iris data.",
            "Notes:",
            "- Reading DG3 still requires a CVC with DG3 right."));

    // Terminal Auth: DG3+DG4 Rights
    BY_NAME.put(
        "Terminal Auth: DG3+DG4 Rights",
        String.join("\n",
            "What this demonstrates:",
            "- TA with combined DG3 and DG4 privileges; both biometric EFs are readable.",
            "ICAO Doc 9303 alignment:",
            "- TA rights are additive as encoded in the terminal CVC.",
            "Security properties:",
            "- Controlled access to multiple protected data groups.",
            "Notes:",
            "- Ensure terminal key and certificates are valid for the date of use."));

    // Terminal Auth: Date Validity
    BY_NAME.put(
        "Terminal Auth: Date Validity",
        String.join("\n",
            "What this demonstrates:",
            "- TA attempted with a validity date that is not yet valid, leading to denial.",
            "ICAO Doc 9303 alignment:",
            "- TA enforces certificate validity periods and policy constraints.",
            "Security properties:",
            "- Prevents use of expired or not‑yet‑valid terminal credentials.",
            "Notes:",
            "- Adjust date/time to fall within the CVC validity window to succeed."));

    // Open reads policy (COM/SOD)
    BY_NAME.put(
        "Open reads policy (COM/SOD)",
        String.join("\n",
            "What this demonstrates:",
            "- Reading EF.COM/EF.SOD under either open or secure policies.",
            "ICAO Doc 9303 alignment:",
            "- COM/SOD may be read without TA; implementations may still prefer SM.",
            "Security properties:",
            "- Even if read in the clear, SOD must be verified by PA before trusting LDS.",
            "Notes:",
            "- Policy choices impact privacy but not PA’s integrity guarantees."));

    // Large DG2 (metadata truncation)
    BY_NAME.put(
        "Large DG2 (metadata truncation)",
        String.join("\n",
            "What this demonstrates:",
            "- An oversized DG2 to exercise reading/logging around large biometric face data.",
            "ICAO Doc 9303 alignment:",
            "- DG2 format follows LDS; PA verifies its integrity regardless of size.",
            "Security properties:",
            "- Transport protections via SM; integrity via PA.",
            "Notes:",
            "- Truncation here refers to UI/log metadata, not cryptographic truncation."));

    // JSON report export
    BY_NAME.put(
        "JSON report export",
        String.join("\n",
            "What this demonstrates:",
            "- Exporting a JSON report of the session for evidence/debugging.",
            "ICAO Doc 9303 alignment:",
            "- No cryptographic changes; reporting does not alter the security properties.",
            "Security properties:",
            "- Reflects outcomes of PA/SM/EAC performed in the session.",
            "Notes:",
            "- Do not treat exported logs as trust anchors; rely on PA/TA outcomes."));

    // ICAO Doc 9303 end-to-end
    BY_NAME.put(
        "ICAO Doc 9303 end-to-end",
        String.join("\n",
            "What this demonstrates:",
            "- An end‑to‑end flow consistent with ICAO Doc 9303 guidance:",
            "  personalisation → PACE → Passive Authentication → (Chip/Active Authentication) → Terminal Authentication → reads.",
            "ICAO Doc 9303 alignment:",
            "- PA validates LDS integrity and signer authenticity.",
            "- PACE establishes SM and access control.",
            "- CA/AA provide chip genuineness (CA preferred where supported).",
            "- TA authorises access to protected biometrics (DG3/DG4).",
            "Security properties:",
            "- Confidentiality/integrity of APDUs; strong integrity/authenticity of LDS; controlled biometric access.",
            "Notes:",
            "- Exact cryptographic suites depend on chip capabilities and negotiated profiles."));
  }
}

