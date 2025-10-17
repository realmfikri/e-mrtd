package emu;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import emu.SessionReport;

/**
 * CLI entry point that builds a {@link SimConfig} from command line arguments and delegates to
 * {@link SimRunner}.
 */
public final class ReadDG1Main {

  private static final String DEFAULT_DOC = "123456789";
  private static final String DEFAULT_DOB = "750101";
  private static final String DEFAULT_DOE = "250101";

  public static void main(String[] args) throws Exception {
    SimConfig.Builder builder = new SimConfig.Builder()
        .docNumber(DEFAULT_DOC)
        .dateOfBirth(DEFAULT_DOB)
        .dateOfExpiry(DEFAULT_DOE);

    boolean seed = false;
    boolean corruptDg2 = false;
    boolean largeDg2 = false;
    boolean attemptPace = false;
    boolean requirePa = false;
    boolean requireAa = false;
    String pacePreference = null;
    String taDateOverride = null;
    String trustStorePassword = null;
    Path trustStorePath = null;
    Path taKeyPath = null;
    Path jsonOutPath = null;
    Path eventsOutPath = null;
    Path facePreviewDir = null;
    Boolean openComSodReads = null;

    List<Path> taCvcs = new ArrayList<>();
    List<Path> trustMasterLists = new ArrayList<>();

    List<String> argList = Arrays.asList(args);
    for (int i = 0; i < argList.size(); i++) {
      String arg = argList.get(i);
      if ("--seed".equals(arg)) {
        seed = true;
      } else if ("--attempt-pace".equals(arg)) {
        attemptPace = true;
      } else if (arg.startsWith("--pace-prefer=")) {
        pacePreference = arg.substring("--pace-prefer=".length());
      } else if ("--pace-prefer".equals(arg)) {
        i = advanceWithValue(argList, i, "--pace-prefer");
        pacePreference = argList.get(i);
      } else if (arg.startsWith("--trust-store=") || arg.startsWith("--trust=")) {
        String value = arg.contains("--trust-store=")
            ? arg.substring("--trust-store=".length())
            : arg.substring("--trust=".length());
        trustStorePath = Paths.get(value);
      } else if ("--trust-store".equals(arg) || "--trust".equals(arg)) {
        i = advanceWithValue(argList, i, arg);
        trustStorePath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--trust-store-password=") || arg.startsWith("--trust-password=")) {
        trustStorePassword = arg.contains("--trust-store-password=")
            ? arg.substring("--trust-store-password=".length())
            : arg.substring("--trust-password=".length());
      } else if ("--trust-store-password".equals(arg) || "--trust-password".equals(arg)) {
        i = advanceWithValue(argList, i, arg);
        trustStorePassword = argList.get(i);
      } else if (arg.startsWith("--trust-ml=")) {
        trustMasterLists.add(Paths.get(arg.substring("--trust-ml=".length())));
      } else if ("--trust-ml".equals(arg)) {
        i = advanceWithValue(argList, i, "--trust-ml");
        trustMasterLists.add(Paths.get(argList.get(i)));
      } else if ("--require-pa".equals(arg)) {
        requirePa = true;
      } else if ("--require-aa".equals(arg) || "--aa".equals(arg)) {
        requireAa = true;
      } else if ("--corrupt-dg2".equals(arg)) {
        corruptDg2 = true;
      } else if ("--large-dg2".equals(arg)) {
        largeDg2 = true;
      } else if (arg.startsWith("--doc=")) {
        builder.docNumber(arg.substring("--doc=".length()));
      } else if ("--doc".equals(arg)) {
        i = advanceWithValue(argList, i, "--doc");
        builder.docNumber(argList.get(i));
      } else if (arg.startsWith("--dob=")) {
        builder.dateOfBirth(arg.substring("--dob=".length()));
      } else if ("--dob".equals(arg)) {
        i = advanceWithValue(argList, i, "--dob");
        builder.dateOfBirth(argList.get(i));
      } else if (arg.startsWith("--doe=")) {
        builder.dateOfExpiry(arg.substring("--doe=".length()));
      } else if ("--doe".equals(arg)) {
        i = advanceWithValue(argList, i, "--doe");
        builder.dateOfExpiry(argList.get(i));
      } else if (arg.startsWith("--can=")) {
        builder.can(arg.substring("--can=".length()));
      } else if ("--can".equals(arg)) {
        i = advanceWithValue(argList, i, "--can");
        builder.can(argList.get(i));
      } else if (arg.startsWith("--pin=")) {
        builder.pin(arg.substring("--pin=".length()));
      } else if ("--pin".equals(arg)) {
        i = advanceWithValue(argList, i, "--pin");
        builder.pin(argList.get(i));
      } else if (arg.startsWith("--puk=")) {
        builder.puk(arg.substring("--puk=".length()));
      } else if ("--puk".equals(arg)) {
        i = advanceWithValue(argList, i, "--puk");
        builder.puk(argList.get(i));
      } else if (arg.startsWith("--ta-cvc=")) {
        taCvcs.add(Paths.get(arg.substring("--ta-cvc=".length())));
      } else if ("--ta-cvc".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-cvc");
        taCvcs.add(Paths.get(argList.get(i)));
      } else if (arg.startsWith("--ta-key=")) {
        taKeyPath = Paths.get(arg.substring("--ta-key=".length()));
      } else if ("--ta-key".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-key");
        taKeyPath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--ta-date=")) {
        taDateOverride = arg.substring("--ta-date=".length());
      } else if ("--ta-date".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-date");
        taDateOverride = argList.get(i);
      } else if ("--open-com-sod".equals(arg)) {
        openComSodReads = Boolean.TRUE;
      } else if ("--secure-com-sod".equals(arg)) {
        openComSodReads = Boolean.FALSE;
      } else if (arg.startsWith("--out=")) {
        jsonOutPath = Paths.get(arg.substring("--out=".length()));
      } else if ("--out".equals(arg)) {
        i = advanceWithValue(argList, i, "--out");
        jsonOutPath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--events-out=")) {
        eventsOutPath = Paths.get(arg.substring("--events-out=".length()));
      } else if ("--events-out".equals(arg)) {
        i = advanceWithValue(argList, i, "--events-out");
        eventsOutPath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--face-preview-dir=")) {
        facePreviewDir = Paths.get(arg.substring("--face-preview-dir=".length()));
      } else if ("--face-preview-dir".equals(arg)) {
        i = advanceWithValue(argList, i, "--face-preview-dir");
        facePreviewDir = Paths.get(argList.get(i));
      } else {
        System.out.println("Unknown argument: " + arg);
      }
    }

    builder.seed(seed)
        .corruptDg2(corruptDg2)
        .largeDg2(largeDg2)
        .attemptPace(attemptPace)
        .requirePa(requirePa)
        .requireAa(requireAa);
    if (pacePreference != null) {
      builder.pacePreference(pacePreference);
    }
    for (Path cvc : taCvcs) {
      builder.addTaCvc(cvc);
    }
    if (taKeyPath != null) {
      builder.taKey(taKeyPath);
    }
    if (trustStorePath != null) {
      builder.trustStorePath(trustStorePath);
    }
    if (trustStorePassword != null) {
      builder.trustStorePassword(trustStorePassword);
    }
    builder.trustMasterLists(trustMasterLists);
    if (jsonOutPath != null) {
      builder.reportOutput(jsonOutPath);
    }
    if (eventsOutPath != null) {
      builder.eventsOutput(eventsOutPath);
    }
    if (facePreviewDir != null) {
      builder.facePreviewDirectory(facePreviewDir);
    }
    if (openComSodReads != null) {
      builder.openComSodReads(openComSodReads);
    }
    if (taDateOverride != null) {
      builder.terminalAuthDate(resolveTerminalAuthDate(taDateOverride));
    } else {
      builder.terminalAuthDate(LocalDate.now(ZoneOffset.UTC));
    }

    SimRunner runner = new SimRunner();
    SessionReport report = runner.run(builder.build(), new CliEvents());

    System.out.println("=== Session Summary ===");
    System.out.println("Transport: " + report.session.transport);
    System.out.println("Secure messaging: " + report.session.smMode);
    System.out.println("PACE established: " + report.session.paceEstablished);
    System.out.println("Passive Auth verdict: " + report.passiveAuth.verdict);
  }

  private static int advanceWithValue(List<String> args, int index, String option) {
    int next = index + 1;
    if (next >= args.size()) {
      throw new IllegalArgumentException(option + " requires a value");
    }
    return next;
  }

  private static LocalDate resolveTerminalAuthDate(String override) {
    LocalDate defaultDate = LocalDate.now(ZoneOffset.UTC);
    if (!hasText(override)) {
      return defaultDate;
    }
    String trimmed = override.trim();
    try {
      return LocalDate.parse(trimmed, DateTimeFormatter.ISO_LOCAL_DATE);
    } catch (Exception ignored) {
      // continue
    }
    String digitsOnly = trimmed.replaceAll("[^0-9]", "");
    if (digitsOnly.length() == 8) {
      int year = Integer.parseInt(digitsOnly.substring(0, 4));
      int month = Integer.parseInt(digitsOnly.substring(4, 6));
      int day = Integer.parseInt(digitsOnly.substring(6, 8));
      return LocalDate.of(year, month, day);
    }
    if (digitsOnly.length() == 6) {
      int year = Integer.parseInt(digitsOnly.substring(0, 2));
      int month = Integer.parseInt(digitsOnly.substring(2, 4));
      int day = Integer.parseInt(digitsOnly.substring(4, 6));
      int centuryBase = defaultDate.getYear() / 100 * 100;
      int fullYear = centuryBase + year;
      if (fullYear < defaultDate.getYear() - 50) {
        fullYear += 100;
      } else if (fullYear > defaultDate.getYear() + 50) {
        fullYear -= 100;
      }
      return LocalDate.of(fullYear, month, day);
    }
    return defaultDate;
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  private static final class CliEvents implements SimEvents {
    @Override
    public void onPhase(SimPhase phase, String detail) {
      System.out.printf("[%s] %s%n", phase.name(), detail);
    }

    @Override
    public void onLog(SimLogCategory category, String message) {
      switch (category) {
        case APDU:
          System.out.println("[APDU] " + message);
          break;
        case SECURITY:
          System.out.println("[SEC] " + message);
          break;
        default:
          System.out.println(message);
          break;
      }
    }
  }
}
