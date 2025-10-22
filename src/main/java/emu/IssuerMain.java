package emu;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.sf.scuba.data.Gender;

import org.jmrtd.lds.icao.MRZInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import emu.IssuerSimulator;
import emu.IssuerSimulator.Result;

public final class IssuerMain {

  public static void main(String[] args) throws Exception {
    RunOptions options = RunOptions.parse(args);
    if (options.showHelp) {
      RunOptions.printUsage();
      return;
    }
    PersonalizationJob job = options.buildJob();
    new IssuerMain().execute(job, options);
  }

  private void execute(PersonalizationJob job, RunOptions options) throws Exception {
    Objects.requireNonNull(job, "job");
    Objects.requireNonNull(options, "options");

    IssuerSimulator simulator = new IssuerSimulator();
    Result result = simulator.run(job, options.toSimulatorOptions());
    options.report(result);
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class JsonConfig {
    public JsonMrz mrz;
    public JsonBiometric face;
    public JsonBiometric fingerprint;
    public JsonBiometric iris;
    public Boolean corruptDg2;
    public List<Integer> enableDataGroups;
    public List<Integer> disableDataGroups;
    public String digestAlgorithm;
    public String signatureAlgorithm;
    public List<String> paceOids;
    public Boolean includeCardAccess;
    public Boolean includeTerminalAuthentication;
    public String chipAuthenticationCurve;
    public Integer aaKeySize;
    public Integer docSignerKeySize;
    public Integer cscaKeySize;
    public String chipAuthenticationKeyId;
    public Long deterministicSeed;
    public List<String> lifecycleTargets;
    public Boolean validate;
    public Boolean omitSecrets;
    public Boolean omitMrzSecret;
    public Boolean omitPaceSecrets;
    public Boolean leavePersonalized;
    public Boolean openReads;
    public JsonOutput output;
    public JsonPaceSecrets paceSecrets;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class JsonMrz {
    public String documentType;
    public String issuingState;
    public String nationality;
    public String documentNumber;
    public String primaryIdentifier;
    public String secondaryIdentifier;
    public String dateOfBirth;
    public String dateOfExpiry;
    public String gender;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class JsonBiometric {
    public String path;
    public Integer width;
    public Integer height;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class JsonOutput {
    public String directory;
    public Boolean facePreview;
    public String facePreviewDirectory;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class JsonPaceSecrets {
    public String can;
    public String pin;
    public String puk;
    public Boolean includeMrz;
  }

  private static final class BiometricSpec {
    Path path;
    Integer width;
    Integer height;

    void setPath(Path path) {
      this.path = path;
    }

    void setSize(Integer width, Integer height) {
      this.width = width;
      this.height = height;
    }

    void applyToFace(PersonalizationJob.Builder builder) {
      if (path != null) {
        builder.withFaceImagePath(path);
      } else if (width != null && height != null) {
        builder.withFaceSyntheticSize(width, height);
      }
    }

    void applyToFingerprint(PersonalizationJob.Builder builder) {
      if (path != null) {
        builder.withFingerprintImagePath(path);
      } else if (width != null && height != null) {
        builder.withFingerprintSyntheticSize(width, height);
      }
    }

    void applyToIris(PersonalizationJob.Builder builder) {
      if (path != null) {
        builder.withIrisImagePath(path);
      } else if (width != null && height != null) {
        builder.withIrisSyntheticSize(width, height);
      }
    }
  }

  private static final class MrzSpec {
    String documentType = "P<";
    String issuingState = "UTO";
    String nationality = "UTO";
    String documentNumber = "123456789";
    String primaryIdentifier = "HAPPY";
    String secondaryIdentifier = "BEAN";
    String dateOfBirth = "750101";
    String dateOfExpiry = "250101";
    String gender = "M";

    MRZInfo toMrzInfo() {
      return new MRZInfo(
          documentType,
          issuingState,
          primaryIdentifier,
          secondaryIdentifier,
          documentNumber,
          nationality,
          dateOfBirth,
          parseGender(gender),
          dateOfExpiry,
          "");
    }

    private Gender parseGender(String value) {
      if (value == null) {
        return Gender.UNSPECIFIED;
      }
      switch (value.toUpperCase(Locale.ROOT)) {
        case "M":
          return Gender.MALE;
        case "F":
          return Gender.FEMALE;
        case "X":
        case "U":
          return Gender.UNSPECIFIED;
        default:
          return Gender.UNSPECIFIED;
      }
    }
  }

  private static final class RunOptions {
    final MrzSpec mrz = new MrzSpec();
    final BiometricSpec face = new BiometricSpec();
    final BiometricSpec fingerprint = new BiometricSpec();
    final BiometricSpec iris = new BiometricSpec();
    final Set<Integer> enableDataGroups = new LinkedHashSet<>();
    final Set<Integer> disableDataGroups = new LinkedHashSet<>();
    Boolean corruptDg2;
    String digestAlgorithm;
    String signatureAlgorithm;
    final List<String> paceOids = new ArrayList<>();
    Boolean includeCardAccess;
    Boolean includeTerminalAuthentication;
    String chipAuthenticationCurve;
    Integer aaKeySize;
    Integer docSignerKeySize;
    Integer cscaKeySize;
    BigInteger chipAuthenticationKeyId;
    Long deterministicSeed;
    final List<String> lifecycleTargets = new ArrayList<>();
    Boolean openComSodReads;
    boolean omitSecrets;
    boolean omitMrzSecret;
    boolean omitPaceSecrets;
    String paceCan;
    String pacePin;
    String pacePuk;
    boolean leavePersonalized;
    boolean validate;
    Path outputDirectory = Paths.get("target", "issuer");
    boolean facePreview;
    Path facePreviewDirectory;
    List<Path> validationTrustAnchors = List.of();
    boolean showHelp;

    static RunOptions parse(String[] args) throws IOException {
      RunOptions options = new RunOptions();
      List<String> arguments = Arrays.asList(args);
      List<Path> jsonPaths = new ArrayList<>();
      for (int i = 0; i < arguments.size(); i++) {
        String arg = arguments.get(i);
        if (arg.startsWith("--job-json")) {
          String value;
          if (arg.equals("--job-json")) {
            if (i + 1 >= arguments.size()) {
              throw new IllegalArgumentException("--job-json requires a value");
            }
            value = arguments.get(++i);
          } else {
            value = arg.substring(arg.indexOf('=') + 1);
          }
          jsonPaths.add(Paths.get(value));
        }
      }
      for (Path path : jsonPaths) {
        options.applyJson(path);
      }

      for (int i = 0; i < arguments.size(); i++) {
        String arg = arguments.get(i);
        if (arg.equals("--job-json")) {
          i++;
          continue;
        }
        if (arg.startsWith("--job-json=")) {
          continue;
        }
        if (arg.equals("--help") || arg.equals("-h")) {
          options.showHelp = true;
          continue;
        }
        if (arg.startsWith("--doc-number")) {
          options.mrz.documentNumber = consumeValue(arguments, i, "--doc-number");
          if (arg.equals("--doc-number")) {
            i++;
          }
        } else if (arg.startsWith("--issuing-state")) {
          options.mrz.issuingState = consumeValue(arguments, i, "--issuing-state");
          if (arg.equals("--issuing-state")) {
            i++;
          }
        } else if (arg.startsWith("--nationality")) {
          options.mrz.nationality = consumeValue(arguments, i, "--nationality");
          if (arg.equals("--nationality")) {
            i++;
          }
        } else if (arg.startsWith("--primary-id")) {
          options.mrz.primaryIdentifier = consumeValue(arguments, i, "--primary-id");
          if (arg.equals("--primary-id")) {
            i++;
          }
        } else if (arg.startsWith("--secondary-id")) {
          options.mrz.secondaryIdentifier = consumeValue(arguments, i, "--secondary-id");
          if (arg.equals("--secondary-id")) {
            i++;
          }
        } else if (arg.startsWith("--date-of-birth")) {
          options.mrz.dateOfBirth = consumeValue(arguments, i, "--date-of-birth");
          if (arg.equals("--date-of-birth")) {
            i++;
          }
        } else if (arg.startsWith("--date-of-expiry")) {
          options.mrz.dateOfExpiry = consumeValue(arguments, i, "--date-of-expiry");
          if (arg.equals("--date-of-expiry")) {
            i++;
          }
        } else if (arg.startsWith("--gender")) {
          options.mrz.gender = consumeValue(arguments, i, "--gender");
          if (arg.equals("--gender")) {
            i++;
          }
        } else if (arg.startsWith("--document-type")) {
          options.mrz.documentType = consumeValue(arguments, i, "--document-type");
          if (arg.equals("--document-type")) {
            i++;
          }
        } else if (arg.startsWith("--face-path")) {
          Path path = Paths.get(consumeValue(arguments, i, "--face-path"));
          options.face.setPath(path);
          if (arg.equals("--face-path")) {
            i++;
          }
        } else if (arg.startsWith("--face-size")) {
          String value = consumeValue(arguments, i, "--face-size");
          if (arg.equals("--face-size")) {
            i++;
          }
          int[] dims = parseDimensions(value);
          options.face.setSize(dims[0], dims[1]);
        } else if (arg.startsWith("--fingerprint-path")) {
          Path path = Paths.get(consumeValue(arguments, i, "--fingerprint-path"));
          options.fingerprint.setPath(path);
          if (arg.equals("--fingerprint-path")) {
            i++;
          }
        } else if (arg.startsWith("--fingerprint-size")) {
          String value = consumeValue(arguments, i, "--fingerprint-size");
          if (arg.equals("--fingerprint-size")) {
            i++;
          }
          int[] dims = parseDimensions(value);
          options.fingerprint.setSize(dims[0], dims[1]);
        } else if (arg.startsWith("--iris-path")) {
          Path path = Paths.get(consumeValue(arguments, i, "--iris-path"));
          options.iris.setPath(path);
          if (arg.equals("--iris-path")) {
            i++;
          }
        } else if (arg.startsWith("--iris-size")) {
          String value = consumeValue(arguments, i, "--iris-size");
          if (arg.equals("--iris-size")) {
            i++;
          }
          int[] dims = parseDimensions(value);
          options.iris.setSize(dims[0], dims[1]);
        } else if (arg.equals("--corrupt-dg2") || arg.equals("--corrupt-dg=2")) {
          options.corruptDg2 = Boolean.TRUE;
        } else if (arg.startsWith("--digest")) {
          options.digestAlgorithm = consumeValue(arguments, i, "--digest");
          if (arg.equals("--digest")) {
            i++;
          }
        } else if (arg.startsWith("--signature")) {
          options.signatureAlgorithm = consumeValue(arguments, i, "--signature");
          if (arg.equals("--signature")) {
            i++;
          }
        } else if (arg.startsWith("--enable-dg")) {
          int value = Integer.parseInt(consumeValue(arguments, i, "--enable-dg"));
          options.enableDataGroups.add(value);
          if (arg.equals("--enable-dg")) {
            i++;
          }
        } else if (arg.startsWith("--disable-dg")) {
          int value = Integer.parseInt(consumeValue(arguments, i, "--disable-dg"));
          options.disableDataGroups.add(value);
          if (arg.equals("--disable-dg")) {
            i++;
          }
        } else if (arg.startsWith("--pace-can")) {
          options.paceCan = consumeValue(arguments, i, "--pace-can");
          if (arg.equals("--pace-can")) {
            i++;
          }
        } else if (arg.startsWith("--pace-pin")) {
          options.pacePin = consumeValue(arguments, i, "--pace-pin");
          if (arg.equals("--pace-pin")) {
            i++;
          }
        } else if (arg.startsWith("--pace-puk")) {
          options.pacePuk = consumeValue(arguments, i, "--pace-puk");
          if (arg.equals("--pace-puk")) {
            i++;
          }
        } else if (arg.equals("--omit-secrets")) {
          options.omitSecrets = true;
        } else if (arg.equals("--omit-mrz-secret")) {
          options.omitMrzSecret = true;
        } else if (arg.equals("--omit-pace-secrets")) {
          options.omitPaceSecrets = true;
        } else if (arg.startsWith("--lifecycle")) {
          String value = consumeValue(arguments, i, "--lifecycle");
          if (arg.equals("--lifecycle")) {
            i++;
          }
          options.lifecycleTargets.add(value.toUpperCase(Locale.ROOT));
        } else if (arg.startsWith("--open-read")) {
          String value = consumeValue(arguments, i, "--open-read");
          if (arg.equals("--open-read")) {
            i++;
          }
          options.openComSodReads = parseBoolean(value);
        } else if (arg.equals("--leave-personalized")) {
          options.leavePersonalized = true;
        } else if (arg.equals("--validate")) {
          options.validate = true;
        } else if (arg.startsWith("--output")) {
          Path path = Paths.get(consumeValue(arguments, i, "--output"));
          options.outputDirectory = path;
          if (arg.equals("--output")) {
            i++;
          }
        } else if (arg.equals("--face-preview")) {
          options.facePreview = true;
        } else if (arg.startsWith("--face-preview-dir")) {
          Path path = Paths.get(consumeValue(arguments, i, "--face-preview-dir"));
          options.facePreviewDirectory = path;
          options.facePreview = true;
          if (arg.equals("--face-preview-dir")) {
            i++;
          }
        } else if (arg.equals("--no-card-access")) {
          options.includeCardAccess = Boolean.FALSE;
        } else if (arg.equals("--include-card-access")) {
          options.includeCardAccess = Boolean.TRUE;
        } else if (arg.equals("--no-ta")) {
          options.includeTerminalAuthentication = Boolean.FALSE;
        } else if (arg.equals("--include-ta")) {
          options.includeTerminalAuthentication = Boolean.TRUE;
        } else if (arg.startsWith("--pace-oid")) {
          String value = consumeValue(arguments, i, "--pace-oid");
          if (arg.equals("--pace-oid")) {
            i++;
          }
          options.paceOids.add(value);
        } else if (arg.startsWith("--chip-curve")) {
          options.chipAuthenticationCurve = consumeValue(arguments, i, "--chip-curve");
          if (arg.equals("--chip-curve")) {
            i++;
          }
        } else if (arg.startsWith("--aa-bits")) {
          options.aaKeySize = Integer.valueOf(consumeValue(arguments, i, "--aa-bits"));
          if (arg.equals("--aa-bits")) {
            i++;
          }
        } else if (arg.startsWith("--doc-signer-bits")) {
          options.docSignerKeySize = Integer.valueOf(consumeValue(arguments, i, "--doc-signer-bits"));
          if (arg.equals("--doc-signer-bits")) {
            i++;
          }
        } else if (arg.startsWith("--csca-bits")) {
          options.cscaKeySize = Integer.valueOf(consumeValue(arguments, i, "--csca-bits"));
          if (arg.equals("--csca-bits")) {
            i++;
          }
        } else if (arg.startsWith("--chip-key-id")) {
          String value = consumeValue(arguments, i, "--chip-key-id");
          if (arg.equals("--chip-key-id")) {
            i++;
          }
          options.chipAuthenticationKeyId = parseBigInteger(value);
        } else if (arg.startsWith("--seed")) {
          options.deterministicSeed = Long.valueOf(consumeValue(arguments, i, "--seed"));
          if (arg.equals("--seed")) {
            i++;
          }
        }
      }

      if (options.facePreview && options.facePreviewDirectory == null) {
        options.facePreviewDirectory = options.outputDirectory.resolve("preview");
      }

      return options;
    }

    private static String consumeValue(List<String> args, int index, String key) {
      String arg = args.get(index);
      if (arg.equals(key)) {
        if (index + 1 >= args.size()) {
          throw new IllegalArgumentException(key + " requires a value");
        }
        return args.get(index + 1);
      }
      int equals = arg.indexOf('=');
      if (equals < 0) {
        throw new IllegalArgumentException(key + " requires a value");
      }
      return arg.substring(equals + 1);
    }

    private static int[] parseDimensions(String value) {
      String[] parts = value.toLowerCase(Locale.ROOT).split("x");
      if (parts.length != 2) {
        throw new IllegalArgumentException("Invalid dimension format: " + value);
      }
      int width = Integer.parseInt(parts[0]);
      int height = Integer.parseInt(parts[1]);
      return new int[]{width, height};
    }

    private static Boolean parseBoolean(String value) {
      String normalized = value.toLowerCase(Locale.ROOT);
      if (normalized.equals("true") || normalized.equals("enable") || normalized.equals("enabled")) {
        return Boolean.TRUE;
      }
      if (normalized.equals("false") || normalized.equals("disable") || normalized.equals("disabled")) {
        return Boolean.FALSE;
      }
      throw new IllegalArgumentException("Unable to parse boolean value: " + value);
    }

    private static BigInteger parseBigInteger(String value) {
      String normalized = value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;
      int radix = (value.startsWith("0x") || value.startsWith("0X")) ? 16 : 10;
      return new BigInteger(normalized, radix);
    }

    private void applyJson(Path jsonPath) throws IOException {
      ObjectMapper mapper = new ObjectMapper();
      mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
      JsonConfig config = mapper.readValue(jsonPath.toFile(), JsonConfig.class);
      Path baseDir = jsonPath.toAbsolutePath().getParent();
      if (config.mrz != null) {
        if (config.mrz.documentType != null) {
          mrz.documentType = config.mrz.documentType;
        }
        if (config.mrz.issuingState != null) {
          mrz.issuingState = config.mrz.issuingState;
        }
        if (config.mrz.nationality != null) {
          mrz.nationality = config.mrz.nationality;
        }
        if (config.mrz.documentNumber != null) {
          mrz.documentNumber = config.mrz.documentNumber;
        }
        if (config.mrz.primaryIdentifier != null) {
          mrz.primaryIdentifier = config.mrz.primaryIdentifier;
        }
        if (config.mrz.secondaryIdentifier != null) {
          mrz.secondaryIdentifier = config.mrz.secondaryIdentifier;
        }
        if (config.mrz.dateOfBirth != null) {
          mrz.dateOfBirth = config.mrz.dateOfBirth;
        }
        if (config.mrz.dateOfExpiry != null) {
          mrz.dateOfExpiry = config.mrz.dateOfExpiry;
        }
        if (config.mrz.gender != null) {
          mrz.gender = config.mrz.gender;
        }
      }
      if (config.face != null) {
        applyBiometric(face, config.face, baseDir);
      }
      if (config.fingerprint != null) {
        applyBiometric(fingerprint, config.fingerprint, baseDir);
      }
      if (config.iris != null) {
        applyBiometric(iris, config.iris, baseDir);
      }
      if (config.corruptDg2 != null) {
        corruptDg2 = config.corruptDg2;
      }
      if (config.enableDataGroups != null) {
        enableDataGroups.addAll(config.enableDataGroups);
      }
      if (config.disableDataGroups != null) {
        disableDataGroups.addAll(config.disableDataGroups);
      }
      if (config.digestAlgorithm != null) {
        digestAlgorithm = config.digestAlgorithm;
      }
      if (config.signatureAlgorithm != null) {
        signatureAlgorithm = config.signatureAlgorithm;
      }
      if (config.paceOids != null && !config.paceOids.isEmpty()) {
        paceOids.clear();
        paceOids.addAll(config.paceOids);
      }
      if (config.includeCardAccess != null) {
        includeCardAccess = config.includeCardAccess;
      }
      if (config.includeTerminalAuthentication != null) {
        includeTerminalAuthentication = config.includeTerminalAuthentication;
      }
      if (config.chipAuthenticationCurve != null) {
        chipAuthenticationCurve = config.chipAuthenticationCurve;
      }
      if (config.aaKeySize != null) {
        aaKeySize = config.aaKeySize;
      }
      if (config.docSignerKeySize != null) {
        docSignerKeySize = config.docSignerKeySize;
      }
      if (config.cscaKeySize != null) {
        cscaKeySize = config.cscaKeySize;
      }
      if (config.chipAuthenticationKeyId != null) {
        chipAuthenticationKeyId = parseBigInteger(config.chipAuthenticationKeyId);
      }
      if (config.deterministicSeed != null) {
        deterministicSeed = config.deterministicSeed;
      }
      if (config.lifecycleTargets != null && !config.lifecycleTargets.isEmpty()) {
        lifecycleTargets.clear();
        lifecycleTargets.addAll(config.lifecycleTargets.stream()
            .map(value -> value.toUpperCase(Locale.ROOT))
            .collect(Collectors.toList()));
      }
      if (config.validate != null) {
        validate = config.validate;
      }
      if (config.omitSecrets != null) {
        omitSecrets = config.omitSecrets;
      }
      if (config.omitMrzSecret != null) {
        omitMrzSecret = config.omitMrzSecret;
      }
      if (config.omitPaceSecrets != null) {
        omitPaceSecrets = config.omitPaceSecrets;
      }
      if (config.leavePersonalized != null) {
        leavePersonalized = config.leavePersonalized;
      }
      if (config.openReads != null) {
        openComSodReads = config.openReads;
      }
      if (config.output != null) {
        if (config.output.directory != null) {
          outputDirectory = resolve(baseDir, config.output.directory);
        }
        if (config.output.facePreview != null) {
          facePreview = config.output.facePreview;
        }
        if (config.output.facePreviewDirectory != null) {
          facePreviewDirectory = resolve(baseDir, config.output.facePreviewDirectory);
        }
      }
      if (config.paceSecrets != null) {
        if (config.paceSecrets.can != null) {
          paceCan = config.paceSecrets.can;
        }
        if (config.paceSecrets.pin != null) {
          pacePin = config.paceSecrets.pin;
        }
        if (config.paceSecrets.puk != null) {
          pacePuk = config.paceSecrets.puk;
        }
        if (config.paceSecrets.includeMrz != null && !config.paceSecrets.includeMrz) {
          omitMrzSecret = true;
        }
      }
    }

    private Path resolve(Path baseDir, String child) {
      Path base = baseDir != null ? baseDir : Paths.get(".");
      return base.resolve(child).normalize();
    }

    private void applyBiometric(BiometricSpec spec, JsonBiometric config, Path baseDir) {
      if (config.path != null) {
        spec.setPath(resolve(baseDir, config.path));
      }
      if (config.width != null && config.height != null) {
        spec.setSize(config.width, config.height);
      }
    }

    PersonalizationJob buildJob() {
      PersonalizationJob.Builder builder = PersonalizationJob.builder();
      builder.withMrzInfo(mrz.toMrzInfo());
      face.applyToFace(builder);
      fingerprint.applyToFingerprint(builder);
      iris.applyToIris(builder);
      if (corruptDg2 != null) {
        builder.corruptDg2(corruptDg2);
      }
      for (Integer dg : enableDataGroups) {
        builder.enableDataGroup(dg.intValue(), true);
      }
      for (Integer dg : disableDataGroups) {
        builder.enableDataGroup(dg.intValue(), false);
      }
      if (digestAlgorithm != null) {
        builder.digestAlgorithm(digestAlgorithm);
      }
      if (signatureAlgorithm != null) {
        builder.signatureAlgorithm(signatureAlgorithm);
      }
      if (!paceOids.isEmpty()) {
        builder.paceOids(paceOids);
      }
      if (includeCardAccess != null) {
        builder.includeCardAccess(includeCardAccess.booleanValue());
      }
      if (includeTerminalAuthentication != null) {
        builder.includeTerminalAuthentication(includeTerminalAuthentication.booleanValue());
      }
      if (chipAuthenticationCurve != null) {
        builder.chipAuthenticationCurve(chipAuthenticationCurve);
      }
      if (aaKeySize != null) {
        builder.aaKeySize(aaKeySize.intValue());
      }
      if (docSignerKeySize != null) {
        builder.docSignerKeySize(docSignerKeySize.intValue());
      }
      if (cscaKeySize != null) {
        builder.cscaKeySize(cscaKeySize.intValue());
      }
      if (chipAuthenticationKeyId != null) {
        builder.chipAuthenticationKeyId(chipAuthenticationKeyId);
      }
      if (deterministicSeed != null) {
        builder.deterministicSeed(deterministicSeed);
      }
      if (!lifecycleTargets.isEmpty()) {
        builder.lifecycleTargets(lifecycleTargets);
      }
      return builder.build();
    }

    IssuerSimulator.Options toSimulatorOptions() {
      IssuerSimulator.Options opts = new IssuerSimulator.Options()
          .outputDirectory(outputDirectory)
          .omitSecrets(omitSecrets)
          .includeMrzSecret(!omitMrzSecret)
          .includePaceSecrets(!omitPaceSecrets)
          .paceCan(paceCan)
          .pacePin(pacePin)
          .pacePuk(pacePuk)
          .openComSodReads(openComSodReads)
          .leavePersonalized(leavePersonalized)
          .validate(validate)
          .facePreview(facePreview)
          .facePreviewDirectory(facePreviewDirectory)
          .validationTrustAnchors(validationTrustAnchors);
      return opts;
    }

    void report(Result result) {
      Path output = result.getOutputDirectory();
      System.out.println("Issuer output → " + output.toAbsolutePath());
      System.out.println("Manifest      → " + result.getManifestPath().toAbsolutePath());
      Path csca = output.resolve("CSCA.cer");
      if (Files.exists(csca)) {
        System.out.println("CSCA anchor   → " + csca.toAbsolutePath());
      }
      Path dsc = output.resolve("DSC.cer");
      if (Files.exists(dsc)) {
        System.out.println("DSC cert      → " + dsc.toAbsolutePath());
      }
      result.getFacePreviewPath().ifPresent(path ->
          System.out.println("Face preview  → " + path.toAbsolutePath()));
      result.getPassiveAuthenticationResult().ifPresent(pa ->
          System.out.println("Passive Authentication → " + (pa.isPass() ? "PASS" : "FAIL")));
    }

    static void printUsage() {
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
}
