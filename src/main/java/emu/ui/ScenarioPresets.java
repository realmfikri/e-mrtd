package emu.ui;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

final class ScenarioPresets {

  private static final String READ_MAIN = "emu.ReadDG1Main";
  private static final String ISSUER_MAIN = "emu.IssuerMain";
  private static final String GENERATE_TA = "emu.GenerateDemoTaChainMain";

  private ScenarioPresets() {
  }

  static List<ScenarioPreset> all() {
    List<ScenarioPreset> presets = new ArrayList<>();
    presets.add(
        scenario(
            "Passive Authentication (success)",
            "Seeds the passport, establishes secure messaging, and requires Passive Authentication.",
            List.of(readStep("Run ReadDG1Main", readArgs(args -> args.seed().requirePa())))));
    presets.add(
        scenario(
            "Issuer: Full LDS",
            "Personalises a full LDS with validation enabled, then exercises a secure read.",
            issuerAndRead(
                "Personalise full LDS",
                List.of("--output=target/ui-issuer/full", "--validate"),
                readArgs(args -> args.seed().attemptPace().requirePa()))));
    presets.add(
        scenario(
            "Issuer: Minimal DG1/DG2",
            "Emits only DG1/DG2 alongside EF.SOD to highlight minimal exports before a BAC read.",
            issuerAndRead(
                "Personalise minimal LDS",
                List.of(
                    "--output=target/ui-issuer/minimal",
                    "--disable-dg=3",
                    "--disable-dg=4",
                    "--disable-dg=14",
                    "--disable-dg=15",
                    "--lifecycle=PERSONALIZED"),
                readArgs(args -> args.seed().requirePa()))));
    presets.add(
        scenario(
            "Issuer: Corrupt DG2",
            "Produces a tampered DG2 for PA-negative testing and immediately performs a failing read.",
            issuerAndRead(
                "Personalise with corrupted DG2",
                List.of("--output=target/ui-issuer/corrupt", "--corrupt-dg2", "--validate"),
                readArgs(args -> args.seed().attemptPace().requirePa()))));
    presets.add(
        readPreset(
            "BAC secure messaging fallback",
            "Demonstrates fallback to BAC secure messaging without attempting PACE.",
            args -> args.seed()));
    presets.add(
        pacePreset(
            "PACE (custom secret)",
            "Attempts PACE using the secret configured via advanced options (MRZ/CAN/PIN/PUK).",
            args -> { }));
    presets.add(
        pacePreset(
            "PACE profile preference (AES128)",
            "Hints the PACE profile preference to AES128 for chips that negotiate multiple suites.",
            args -> args.pacePreference("AES128")));
    presets.add(
        pacePreset(
            "Chip Authentication upgrade",
            "Attempts PACE then requires Active Authentication to highlight the CA secure messaging upgrade.",
            args -> args.requireAa()));
    presets.add(
        pacePreset(
            "Terminal Authentication without credentials",
            "Runs PACE, Passive Authentication, and Active Authentication but omits TA credentials to show biometrics remain locked.",
            args -> args.requirePa().requireAa()));
    presets.add(
        readPreset(
            "Passive Authentication (tamper detection)",
            "Corrupts DG2 during personalisation to show PA failure.",
            args -> args.seed().requirePa().corruptDg2()));
    presets.add(
        readPreset(
            "Passive Authentication (missing trust anchors)",
            "Points PA at an empty trust store to trigger chain validation errors.",
            args -> args.seed().requirePa().trustStore("target/ui-missing-trust")));
    presets.add(
        readPreset(
            "Open reads policy (COM/SOD)",
            "Toggles open and secure COM/SOD read policies.",
            args -> args.seed().openComSod().secureComSod()));
    presets.add(
        readPreset(
            "Large DG2 (metadata truncation)",
            "Personalises a large DG2 to exercise metadata truncation logging.",
            args -> args.seed().largeDg2()));
    presets.add(
        readPreset(
            "JSON report export",
            "Demonstrates JSON report generation (UI always captures the file).",
            args -> args.seed().requireAa()));
    presets.add(
        scenario(
            "Terminal Auth: DG3 Rights",
            "Generates a TA chain granting DG3 only, then performs a read.",
            generateAndRead(
                "target/ta-demo/dg3",
                List.of("--rights=DG3"),
                readArgs(args -> args.seed().attemptPace().taCvc("target/ta-demo/dg3/terminal.cvc").taKey("target/ta-demo/dg3/terminal.key")))));
    presets.add(
        scenario(
            "Terminal Auth: DG4 Rights",
            "Generates a TA chain granting DG4 only, then performs a read.",
            generateAndRead(
                "target/ta-demo/dg4",
                List.of("--rights=DG4"),
                readArgs(args -> args.seed().attemptPace().taCvc("target/ta-demo/dg4/terminal.cvc").taKey("target/ta-demo/dg4/terminal.key")))));
    presets.add(
        scenario(
            "Terminal Auth: DG3+DG4 Rights",
            "Generates a TA chain granting DG3 and DG4 access.",
            generateAndRead(
                "target/ta-demo/dg34",
                List.of("--rights=DG3_DG4"),
                readArgs(args -> args.seed().attemptPace().taCvc("target/ta-demo/dg34/terminal.cvc").taKey("target/ta-demo/dg34/terminal.key")))));
    presets.add(
        scenario(
            "Terminal Auth: Date Validity",
            "Runs TA with a future date override to show not-yet-valid behaviour.",
            generateAndRead(
                "target/ta-demo/date",
                List.of("--rights=DG3_DG4", "--validity-days=30"),
                readArgs(args -> args
                    .seed()
                    .attemptPace()
                    .taCvc("target/ta-demo/date/terminal.cvc")
                    .taKey("target/ta-demo/date/terminal.key")
                    .taDate("2035-01-01")))));
    return List.copyOf(presets);
  }

  static ScenarioPreset icaoDoc9303() {
    Path outputDir = Paths.get("target", "icao-doc9303");
    Path cvcaPath = outputDir.resolve("cvca.cvc");
    Path terminalPath = outputDir.resolve("terminal.cvc");
    Path terminalKeyPath = outputDir.resolve("terminal.key");

    List<ScenarioStep> steps = new ArrayList<>();
    List<String> generatorArgs = new ArrayList<>();
    generatorArgs.add("--out-dir=" + outputDir);
    generatorArgs.add("--rights=DG3_DG4");
    steps.add(new ScenarioStep("Generate demo TA chain", GENERATE_TA, generatorArgs, false));

    List<String> readArgs = new ArrayList<>();
    readArgs.add("--seed");
    readArgs.add("--attempt-pace");
    readArgs.add("--require-pa");
    readArgs.add("--require-aa");
    readArgs.add("--ta-cvc=" + cvcaPath);
    readArgs.add("--ta-cvc=" + terminalPath);
    readArgs.add("--ta-key=" + terminalKeyPath);
    steps.add(new ScenarioStep(
        "Run ICAO Doc 9303 end-to-end",
        READ_MAIN,
        readArgs,
        true));

    return new ScenarioPreset(
        "ICAO Doc 9303 end-to-end",
        "Runs the full ICAO Doc 9303 Part 11 flow: personalization, PACE secure messaging, Passive, Chip, Active, and Terminal Authentication, then reads LDS data groups.",
        List.copyOf(steps));
  }

  private static ScenarioPreset scenario(String name, String description, List<ScenarioStep> steps) {
    return new ScenarioPreset(name, description, steps);
  }

  private static List<ScenarioStep> generateAndRead(
      String outDir, List<String> generatorExtraArgs, List<String> readArgs) {
    List<ScenarioStep> steps = new ArrayList<>();
    List<String> generatorStepArgs = new ArrayList<>();
    generatorStepArgs.add("--out-dir=" + outDir);
    generatorStepArgs.addAll(generatorExtraArgs);
    steps.add(new ScenarioStep("Generate TA chain", GENERATE_TA, generatorStepArgs, false));
    steps.add(readStep("Run ReadDG1Main", readArgs));
    return List.copyOf(steps);
  }

  private static List<ScenarioStep> issuerAndRead(
      String issuerStepName, List<String> issuerArgs, List<String> readArgs) {
    List<ScenarioStep> steps = new ArrayList<>();
    steps.add(new ScenarioStep(issuerStepName, ISSUER_MAIN, issuerArgs, false));
    if (!readArgs.isEmpty()) {
      steps.add(readStep("Run ReadDG1Main", readArgs));
    }
    return List.copyOf(steps);
  }

  private static ScenarioPreset readPreset(
      String name, String description, Consumer<ReadArgsBuilder> argsMutator) {
    return scenario(name, description, List.of(readStep("Run ReadDG1Main", readArgs(argsMutator))));
  }

  private static ScenarioPreset pacePreset(
      String name, String description, Consumer<ReadArgsBuilder> argsMutator) {
    return readPreset(name, description, args -> {
      args.seed().attemptPace();
      argsMutator.accept(args);
    });
  }

  private static ScenarioStep readStep(String stepName, List<String> args) {
    return new ScenarioStep(stepName, READ_MAIN, args, true);
  }

  private static List<String> readArgs(Consumer<ReadArgsBuilder> argsMutator) {
    ReadArgsBuilder builder = new ReadArgsBuilder();
    argsMutator.accept(builder);
    return builder.build();
  }

  private static final class ReadArgsBuilder {
    private final List<String> args = new ArrayList<>();

    ReadArgsBuilder seed() {
      args.add("--seed");
      return this;
    }

    ReadArgsBuilder attemptPace() {
      args.add("--attempt-pace");
      return this;
    }

    ReadArgsBuilder requirePa() {
      args.add("--require-pa");
      return this;
    }

    ReadArgsBuilder requireAa() {
      args.add("--require-aa");
      return this;
    }

    ReadArgsBuilder pacePreference(String value) {
      args.add("--pace-prefer=" + value);
      return this;
    }

    ReadArgsBuilder corruptDg2() {
      args.add("--corrupt-dg2");
      return this;
    }

    ReadArgsBuilder largeDg2() {
      args.add("--large-dg2");
      return this;
    }

    ReadArgsBuilder trustStore(String path) {
      args.add("--trust-store=" + path);
      return this;
    }

    ReadArgsBuilder openComSod() {
      args.add("--open-com-sod");
      return this;
    }

    ReadArgsBuilder secureComSod() {
      args.add("--secure-com-sod");
      return this;
    }

    ReadArgsBuilder taCvc(String path) {
      args.add("--ta-cvc=" + path);
      return this;
    }

    ReadArgsBuilder taKey(String path) {
      args.add("--ta-key=" + path);
      return this;
    }

    ReadArgsBuilder taDate(String value) {
      args.add("--ta-date=" + value);
      return this;
    }

    List<String> build() {
      return List.copyOf(args);
    }
  }
}

