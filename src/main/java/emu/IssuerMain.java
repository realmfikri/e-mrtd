package emu;

import java.util.Arrays;

public final class IssuerMain {

  public static void main(String[] args) throws Exception {
    IssuerJobBuilder builder = new IssuerJobBuilder();
    builder.consumeArguments(Arrays.asList(args));
    if (builder.isHelpRequested()) {
      printUsage();
      return;
    }

    PersonalizationJob job = builder.buildJob();
    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(job, builder.buildSimulatorOptions());
    builder.report(result, System.out::println);
  }

  private static void printUsage() {
    System.out.println("Usage: IssuerMain [options]");
    System.out.println();
    System.out.println("Key options:");
    System.out.println("  -h, --help                 Show this help message");
    System.out.println("  --job-json <path>          Load personalization job from JSON template");
    System.out.println("  --doc-number <value>       Override MRZ document number");
    System.out.println("  --enable-dg <n>            Ensure DG<n> is exported (repeatable)");
    System.out.println("  --disable-dg <n>           Exclude DG<n> from the LDS (repeatable)");
    System.out.println("  --corrupt-dg2              Emit a corrupted DG2 for negative tests");
    System.out.println("  --pace-can/--pace-pin/--pace-puk <value>  Seed PACE credentials");
    System.out.println("  --omit-secrets             Skip installing all issuer secrets");
    System.out.println("  --omit-mrz-secret          Skip the MRZ BAC seed while keeping others");
    System.out.println("  --omit-pace-secrets        Skip PACE CAN/PIN/PUK seeds");
    System.out.println("  --open-read=<true|false>   Toggle EF.COM/EF.SOD open-read policy");
    System.out.println("  --lifecycle <state>        Append lifecycle transition (PERSONALIZED/LOCKED)");
    System.out.println("  --output <dir>             Override artifact directory (default target/issuer)");
    System.out.println("  --face-preview[ -dir <dir>]  Export face preview JPEG from DG2");
    System.out.println("  --validate                 Run Passive Authentication after issuance");
    System.out.println();
    System.out.println("Example:");
    System.out.println("  mvn -q exec:java -Dexec.mainClass=emu.IssuerMain \\");
    System.out.println("    -Dexec.args='--doc-number 123456789 --lifecycle PERSONALIZED --lifecycle LOCKED --open-read=true'");
  }
}

