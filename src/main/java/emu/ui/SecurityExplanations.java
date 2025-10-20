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
    // Happy Path (Issuance + PA)
    BY_NAME.put(
        "Happy Path (Issuance + PA)",
        String.join("\n",
            "What this demonstrates:",
            "- Personalisation then a read under secure messaging, with Passive Authentication (PA).",
            "ICAO Doc 9303 alignment:",
            "- PA verifies EF.SOD signature and DG hash values to detect tampering.",
            "- Secure messaging mitigates eavesdropping/replay; BAC used if PACE not negotiated.",
            "Security properties:",
            "- Integrity and authenticity of LDS via PA.",
            "- Confidentiality/integrity of APDUs via SM.",
            "Notes:",
            "- Biometrics (DG3/DG4) remain access‑controlled; no Terminal Authentication in this preset."));

    // BAC Only (no PACE)
    BY_NAME.put(
        "BAC Only (no PACE)",
        String.join("\n",
            "What this demonstrates:",
            "- Establishes secure messaging using BAC (MRZ‑derived keys) without attempting PACE.",
            "ICAO Doc 9303 alignment:",
            "- BAC is the legacy access control; still permitted but PACE is recommended.",
            "Security properties:",
            "- Protects against casual skimming; provides APDU confidentiality and integrity.",
            "Notes:",
            "- PACE offers stronger, modern cryptography and is preferred when available."));

    // PACE (MRZ)
    BY_NAME.put(
        "PACE (MRZ)",
        String.join("\n",
            "What this demonstrates:",
            "- PACE using MRZ as the knowledge‑based secret to derive session keys.",
            "ICAO Doc 9303 alignment:",
            "- PACE replaces BAC for access control and key establishment.",
            "Security properties:",
            "- Strong resistance to skimming/eavesdropping; forward‑secure key establishment.",
            "Notes:",
            "- Exact algorithm/profile (e.g., AES‑128, ECDH groups) depends on chip capabilities."));

    // PACE (CAN)
    BY_NAME.put(
        "PACE (CAN)",
        String.join("\n",
            "What this demonstrates:",
            "- PACE using a Card Access Number (CAN) as the secret.",
            "ICAO Doc 9303 alignment:",
            "- PACE supports multiple secrets (MRZ, CAN, PIN, PUK) for access control.",
            "Security properties:",
            "- Confidentiality/integrity via secure messaging after PAKE‑based key agreement.",
            "Notes:",
            "- CAN workflows are typical for ID cards with visible CAN on the card."));

    // PACE (PIN)
    BY_NAME.put(
        "PACE (PIN)",
        String.join("\n",
            "What this demonstrates:",
            "- PACE using a user PIN as the secret for access control.",
            "ICAO Doc 9303 alignment:",
            "- PACE with PIN is permitted; protects contactless access with a user‑known secret.",
            "Security properties:",
            "- SM keys established from a PAKE; protects APDUs against eavesdropping and tampering.",
            "Notes:",
            "- PIN retry/lockout policies are chip‑specific and out of scope here."));

    // PACE (PUK)
    BY_NAME.put(
        "PACE (PUK)",
        String.join("\n",
            "What this demonstrates:",
            "- PACE using a PUK (unblock code) as the secret.",
            "ICAO Doc 9303 alignment:",
            "- PUK is an allowed secret type for PACE in some deployments.",
            "Security properties:",
            "- Establishes SM via PAKE; same transport protections as other PACE profiles.",
            "Notes:",
            "- Typically used for recovery/unblock flows; demo does not alter retry counters."));

    // PACE Profile Preference (AES128)
    BY_NAME.put(
        "PACE Profile Preference (AES128)",
        String.join("\n",
            "What this demonstrates:",
            "- Negotiation preference for a PACE profile using AES‑128.",
            "ICAO Doc 9303 alignment:",
            "- PACE supports multiple algorithm suites; final choice is by chip capabilities.",
            "Security properties:",
            "- Modern cipher suite with adequate strength for eMRTD sessions.",
            "Notes:",
            "- Actual profile is negotiated; this sets a preference only."));

    // Chip Authentication Upgrade (CA)
    BY_NAME.put(
        "Chip Authentication Upgrade (CA)",
        String.join("\n",
            "What this demonstrates:",
            "- After reading DG14, upgrades SM via Chip Authentication (CA).",
            "ICAO Doc 9303 alignment:",
            "- CA provides chip genuineness and establishes fresh SM keys; preferred to AA where available.",
            "Security properties:",
            "- Mutual key agreement with the chip; strengthens authenticity and forward secrecy.",
            "Notes:",
            "- CA is functionally a stronger successor to Active Authentication."));

    // Passive Auth: PASS
    BY_NAME.put(
        "Passive Auth: PASS",
        String.join("\n",
            "What this demonstrates:",
            "- Successful Passive Authentication using the default trust anchors.",
            "ICAO Doc 9303 alignment:",
            "- Verifies EF.SOD signature chain to CSCA and DG hash consistency.",
            "Security properties:",
            "- Detects data tampering and fake signers; does not itself provide confidentiality.",
            "Notes:",
            "- Ensure the trust store contains the issuing CSCA/DS certificates."));

    // Passive Auth: Tamper Detection
    BY_NAME.put(
        "Passive Auth: Tamper Detection",
        String.join("\n",
            "What this demonstrates:",
            "- A modified LDS (DG2) causes PA to fail due to hash mismatch.",
            "ICAO Doc 9303 alignment:",
            "- PA compares DG digests in EF.SOD with recomputed values.",
            "Security properties:",
            "- Strong integrity protection against post‑issuance modification.",
            "Notes:",
            "- This does not test CRL/ML checks; only integrity/signature validation."));

    // Passive Auth: Missing Trust Anchors
    BY_NAME.put(
        "Passive Auth: Missing Trust Anchors",
        String.join("\n",
            "What this demonstrates:",
            "- PA fails when the DS/CSCA trust chain cannot be validated.",
            "ICAO Doc 9303 alignment:",
            "- Chain building and policy checks are required for acceptance of EF.SOD.",
            "Security properties:",
            "- Prevents acceptance of data signed by unknown or untrusted issuers.",
            "Notes:",
            "- Populate a trust store with appropriate CSCA/DS certificates to succeed."));

    // Terminal Auth: Locked Biometrics
    BY_NAME.put(
        "Terminal Auth: Locked Biometrics",
        String.join("\n",
            "What this demonstrates:",
            "- Attempting to read DG3/DG4 without Terminal Authentication (TA) is blocked.",
            "ICAO Doc 9303 alignment:",
            "- Biometrics are protected by Extended Access Control; TA is required for access.",
            "Security properties:",
            "- Access control enforcement on sensitive biometric EFs.",
            "Notes:",
            "- TA requires a valid CVC chain and a terminal private key."));

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

    // Open Reads Policy (COM/SOD)
    BY_NAME.put(
        "Open Reads Policy (COM/SOD)",
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

    // JSON Report Export
    BY_NAME.put(
        "JSON Report Export",
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

