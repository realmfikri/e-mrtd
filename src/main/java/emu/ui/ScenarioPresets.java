package emu.ui;

import java.util.ArrayList;
import java.util.List;

final class ScenarioPresets {

  private static final String READ_MAIN = "emu.ReadDG1Main";
  private static final String GENERATE_TA = "emu.GenerateDemoTaChainMain";

  private ScenarioPresets() {
  }

  static List<ScenarioPreset> all() {
    return List.of(
        scenario(
            "Happy Path (Issuance + PA)",
            "Seeds the passport, establishes secure messaging, and requires Passive Authentication.",
            readStep("Run ReadDG1Main", "--seed", "--require-pa")),
        scenario(
            "BAC Only (no PACE)",
            "Demonstrates fallback to BAC secure messaging without attempting PACE.",
            readStep("Run ReadDG1Main", "--seed")),
        scenario(
            "PACE (MRZ)",
            "Attempts PACE using MRZ derived keys.",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace")),
        scenario(
            "PACE (CAN)",
            "Attempts PACE with a CAN secret (customise via advanced toggles).",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace", "--can=123456")),
        scenario(
            "PACE (PIN)",
            "Attempts PACE with a PIN secret (customise via advanced toggles).",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace", "--pin=123456")),
        scenario(
            "PACE (PUK)",
            "Attempts PACE with a PUK secret (customise via advanced toggles).",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace", "--puk=123456789")),
        scenario(
            "PACE Profile Preference (AES128)",
            "Hints the PACE profile preference to AES128.",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace", "--pace-prefer=AES128")),
        scenario(
            "Chip Authentication Upgrade (CA)",
            "Shows the secure messaging upgrade to CA once DG14 is available.",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace")),
        scenario(
            "Passive Auth: PASS",
            "Runs Passive Authentication with the default trust store.",
            readStep("Run ReadDG1Main", "--seed", "--require-pa")),
        scenario(
            "Passive Auth: Tamper Detection",
            "Corrupts DG2 during personalisation to show PA failure.",
            readStep("Run ReadDG1Main", "--seed", "--require-pa", "--corrupt-dg2")),
        scenario(
            "Passive Auth: Missing Trust Anchors",
            "Points PA at an empty trust store to trigger chain validation errors.",
            readStep("Run ReadDG1Main", "--seed", "--require-pa", "--trust-store=target/ui-missing-trust")),
        scenario(
            "Terminal Auth: Locked Biometrics",
            "Attempts to read DG3/DG4 without TA credentials (expect locked).",
            readStep("Run ReadDG1Main", "--seed", "--attempt-pace")),
        scenario(
            "Terminal Auth: DG3 Rights",
            "Generates a TA chain granting DG3 only, then performs a read.",
            generateAndRead("target/ta-demo/dg3", List.of("--rights=DG3"), List.of("--seed", "--attempt-pace", "--ta-cvc=target/ta-demo/dg3/terminal.cvc", "--ta-key=target/ta-demo/dg3/terminal.key"))),
        scenario(
            "Terminal Auth: DG4 Rights",
            "Generates a TA chain granting DG4 only, then performs a read.",
            generateAndRead("target/ta-demo/dg4", List.of("--rights=DG4"), List.of("--seed", "--attempt-pace", "--ta-cvc=target/ta-demo/dg4/terminal.cvc", "--ta-key=target/ta-demo/dg4/terminal.key"))),
        scenario(
            "Terminal Auth: DG3+DG4 Rights",
            "Generates a TA chain granting DG3 and DG4 access.",
            generateAndRead("target/ta-demo/dg34", List.of("--rights=DG3_DG4"), List.of("--seed", "--attempt-pace", "--ta-cvc=target/ta-demo/dg34/terminal.cvc", "--ta-key=target/ta-demo/dg34/terminal.key"))),
        scenario(
            "Terminal Auth: Date Validity",
            "Runs TA with a future date override to show not-yet-valid behaviour.",
            generateAndRead("target/ta-demo/date", List.of("--rights=DG3_DG4", "--validity-days=30"), List.of("--seed", "--attempt-pace", "--ta-cvc=target/ta-demo/date/terminal.cvc", "--ta-key=target/ta-demo/date/terminal.key", "--ta-date=2035-01-01"))),
        scenario(
            "Open Reads Policy (COM/SOD)",
            "Toggles open and secure COM/SOD read policies.",
            readStep("Run ReadDG1Main", "--seed", "--open-com-sod", "--secure-com-sod")),
        scenario(
            "Large DG2 (metadata truncation)",
            "Personalises a large DG2 to exercise metadata truncation logging.",
            readStep("Run ReadDG1Main", "--seed", "--large-dg2")),
        scenario(
            "JSON Report Export",
            "Demonstrates JSON report generation (UI always captures the file).",
            readStep("Run ReadDG1Main", "--seed"))
    );
  }

  private static ScenarioPreset scenario(String name, String description, List<ScenarioStep> steps) {
    return new ScenarioPreset(name, description, steps);
  }

  private static List<ScenarioStep> readStep(String stepName, String... args) {
    return List.of(new ScenarioStep(stepName, READ_MAIN, List.of(args), true));
  }

  private static List<ScenarioStep> generateAndRead(String outDir, List<String> generatorExtraArgs, List<String> readArgs) {
    List<ScenarioStep> steps = new ArrayList<>();
    List<String> generatorStepArgs = new ArrayList<>();
    generatorStepArgs.add("--out-dir=" + outDir);
    generatorStepArgs.addAll(generatorExtraArgs);
    steps.add(new ScenarioStep("Generate TA chain", GENERATE_TA, generatorStepArgs, false));
    steps.add(new ScenarioStep("Run ReadDG1Main", READ_MAIN, readArgs, true));
    return List.copyOf(steps);
  }
}

