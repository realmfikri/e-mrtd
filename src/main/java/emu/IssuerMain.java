package emu;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sf.scuba.data.Gender;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import emu.PersonalizationSupport.SODArtifacts;

public final class IssuerMain {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

  private static final short EF_COM = PassportService.EF_COM;
  private static final short EF_SOD = PassportService.EF_SOD;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  public static void main(String[] args) throws Exception {
    RunOptions options = RunOptions.parse(args);
    PersonalizationJob job = options.buildJob();
    IssuerMain issuer = new IssuerMain();
    issuer.execute(job, options);
  }

  private void execute(PersonalizationJob job, RunOptions options) throws Exception {
    Objects.requireNonNull(job, "job");
    Objects.requireNonNull(options, "options");

    Path outputDir = options.outputDirectory != null ? options.outputDirectory : Paths.get("target", "issuer");
    Files.createDirectories(outputDir);

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short) 0, (byte) MRTD_AID.length);
    simulator.installApplet(aid, sos.passportapplet.PassportApplet.class);

    CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();

    selectApplet(channel);

    int[] tagList = job.getComTagList().stream().mapToInt(Integer::intValue).toArray();
    COMFile comFile = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = comFile.getEncoded();

    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(job);

    createEf(channel, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEf(channel, EF_COM, "SELECT EF.COM");
    writeBinary(channel, comBytes, "WRITE EF.COM");

    for (Map.Entry<Integer, byte[]> entry : artifacts.getDataGroupBytesMap().entrySet()) {
      int dg = entry.getKey();
      byte[] data = entry.getValue();
      if (data == null || data.length == 0) {
        continue;
      }
      short fid = (short) (0x0100 | (dg & 0xFF));
      createEf(channel, fid, data.length, "CREATE EF.DG" + dg);
      selectEf(channel, fid, "SELECT EF.DG" + dg);
      writeBinary(channel, data, "WRITE EF.DG" + dg);
    }

    byte[] cardAccessBytes = artifacts.getCardAccessBytes();
    if (cardAccessBytes != null && cardAccessBytes.length > 0) {
      createEf(channel, EF_CARD_ACCESS, cardAccessBytes.length, "CREATE EF.CardAccess");
      selectEf(channel, EF_CARD_ACCESS, "SELECT EF.CardAccess");
      writeBinary(channel, cardAccessBytes, "WRITE EF.CardAccess");
    }

    byte[] sodBytes = artifacts.getSodBytes();
    createEf(channel, EF_SOD, sodBytes.length, "CREATE EF.SOD");
    selectEf(channel, EF_SOD, "SELECT EF.SOD");
    writeBinary(channel, sodBytes, "WRITE EF.SOD");

    if (!options.omitSecrets && !options.omitMrzSecret) {
      byte[] mrzSeed = IssuerSecretEncoder.encodeMrzSeed(job.getMrzInfo());
      putData(channel, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
    }
    if (!options.omitSecrets && !options.omitPaceSecrets) {
      byte[] paceSecrets = IssuerSecretEncoder.encodePaceSecrets(options.paceCan, options.pacePin, options.pacePuk);
      if (paceSecrets != null) {
        putData(channel, 0x00, 0x65, paceSecrets, "PUT PACE secrets TLV");
      }
    }

    if (options.openComSodReads != null) {
      byte[] toggle = new byte[]{(byte) (options.openComSodReads ? 0x01 : 0x00)};
      putData(channel, 0xDE, 0xFE, toggle,
          options.openComSodReads ? "ENABLE open COM/SOD reads" : "DISABLE open COM/SOD reads");
    }

    for (String lifecycle : job.getLifecycleTargets()) {
      String normalized = lifecycle.toUpperCase(Locale.ROOT);
      if ("PERSONALIZED".equals(normalized)) {
        putData(channel, 0xDE, 0xAF, new byte[0], "SET LIFECYCLE → PERSONALIZED");
      } else if ("LOCKED".equals(normalized) && !options.leavePersonalized) {
        putData(channel, 0xDE, 0xAD, new byte[0], "SET LIFECYCLE → LOCKED");
      }
    }

    card.disconnect(false);

    Path facePreviewPath = null;
    if (options.facePreview) {
      byte[] dg2Bytes = artifacts.getDataGroupBytes(2);
      if (dg2Bytes != null && dg2Bytes.length > 0) {
        Path previewDir = options.facePreviewDirectory != null ? options.facePreviewDirectory : outputDir.resolve("preview");
        facePreviewPath = exportFacePreview(dg2Bytes, previewDir);
      }
    }

    Map<String, Object> manifest = buildManifest(job, artifacts, comBytes, cardAccessBytes, outputDir, facePreviewPath);
    ValidationSummary validationSummary = null;
    if (options.validate) {
      validationSummary = runValidation(terminal, job, options);
      if (validationSummary != null && validationSummary.passiveAuthentication != null) {
        manifest.put("passiveAuthentication", toManifest(validationSummary.passiveAuthentication));
      }
    }

    writeManifest(outputDir, manifest);
  }

  private ValidationSummary runValidation(CardTerminal terminal, PersonalizationJob job, RunOptions options)
      throws Exception {
    TerminalCardService terminalService = new TerminalCardService(terminal);
    terminalService.open();
    try {
      CardService logging = new LoggingCardService(terminalService, null);
      logging.open();
      try {
        PassportService service = new PassportService(
            logging,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            false,
            false);
        service.open();
        service.sendSelectApplet(false);
        MRZInfo mrz = job.getMrzInfo();
        BACKey bacKey = new BACKey(mrz.getDocumentNumber(), mrz.getDateOfBirth(), mrz.getDateOfExpiry());
        service.doBAC(bacKey);
        PassiveAuthentication.Result result = PassiveAuthentication.verify(service, Collections.emptyList(), null);
        System.out.println("Passive Authentication → " + (result.isPass() ? "PASS" : "FAIL"));
        return new ValidationSummary(result);
      } finally {
        logging.close();
      }
    } finally {
      terminalService.close();
    }
  }

  private Map<String, Object> buildManifest(
      PersonalizationJob job,
      SODArtifacts artifacts,
      byte[] comBytes,
      byte[] cardAccessBytes,
      Path outputDir,
      Path facePreviewPath) throws IOException {
    Map<String, Object> manifest = new LinkedHashMap<>();
    MRZInfo mrz = job.getMrzInfo();
    Map<String, Object> mrzSection = new LinkedHashMap<>();
    mrzSection.put("documentNumber", mrz.getDocumentNumber());
    mrzSection.put("issuingState", mrz.getIssuingState());
    mrzSection.put("nationality", mrz.getNationality());
    mrzSection.put("dateOfBirth", mrz.getDateOfBirth());
    mrzSection.put("dateOfExpiry", mrz.getDateOfExpiry());
    mrzSection.put("primaryIdentifier", mrz.getPrimaryIdentifier());
    mrzSection.put("secondaryIdentifier", mrz.getSecondaryIdentifier());
    manifest.put("mrz", mrzSection);
    manifest.put("digestAlgorithm", artifacts.getDigestAlgorithm());
    manifest.put("signatureAlgorithm", artifacts.getSignatureAlgorithm());
    manifest.put("lifecycleTargets", job.getLifecycleTargets());

    List<Map<String, Object>> dataGroups = new ArrayList<>();
    for (Map.Entry<Integer, byte[]> entry : artifacts.getDataGroupBytesMap().entrySet()) {
      int dg = entry.getKey();
      byte[] data = entry.getValue();
      if (data == null) {
        continue;
      }
      Path file = outputDir.resolve(String.format("EF.DG%d.bin", dg));
      Files.write(file, data);
      Map<String, Object> entryMap = new LinkedHashMap<>();
      entryMap.put("dg", dg);
      entryMap.put("path", outputDir.relativize(file).toString());
      entryMap.put("length", data.length);
      dataGroups.add(entryMap);
    }
    manifest.put("dataGroups", dataGroups);

    Path comPath = outputDir.resolve("EF.COM.bin");
    Files.write(comPath, comBytes);
    manifest.put("efCom", outputDir.relativize(comPath).toString());

    Path sodPath = outputDir.resolve("EF.SOD.bin");
    Files.write(sodPath, artifacts.getSodBytes());
    manifest.put("efSod", outputDir.relativize(sodPath).toString());

    if (cardAccessBytes != null && cardAccessBytes.length > 0) {
      Path caPath = outputDir.resolve("EF.CardAccess.bin");
      Files.write(caPath, cardAccessBytes);
      manifest.put("efCardAccess", outputDir.relativize(caPath).toString());
    }

    Map<String, Object> certificates = new LinkedHashMap<>();
    Path cscaPath = outputDir.resolve("CSCA.cer");
    try {
      Files.write(cscaPath, artifacts.getCscaCert().getEncoded());
    } catch (CertificateEncodingException e) {
      throw new IOException("Failed to encode CSCA certificate", e);
    }
    certificates.put("csca", outputDir.relativize(cscaPath).toString());
    Path dscPath = outputDir.resolve("DSC.cer");
    try {
      Files.write(dscPath, artifacts.getDocSignerCert().getEncoded());
    } catch (CertificateEncodingException e) {
      throw new IOException("Failed to encode DSC certificate", e);
    }
    certificates.put("dsc", outputDir.relativize(dscPath).toString());
    manifest.put("certificates", certificates);

    if (artifacts.getJob().includeTerminalAuthentication()) {
      manifest.put("taChain", Collections.emptyList());
    }
    if (facePreviewPath != null) {
      Path absolutePreview = facePreviewPath.toAbsolutePath();
      Path base = outputDir.toAbsolutePath();
      Path previewRelative = absolutePreview.startsWith(base)
          ? base.relativize(absolutePreview)
          : absolutePreview;
      manifest.put("facePreview", previewRelative.toString());
    }

    return manifest;
  }

  private Map<String, Object> toManifest(PassiveAuthentication.Result result) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("pass", result.isPass());
    map.put("okDataGroups", result.getOkDataGroups());
    map.put("badDataGroups", result.getBadDataGroups());
    map.put("missingDataGroups", result.getMissingDataGroups());
    map.put("lockedDataGroups", result.getLockedDataGroups());
    map.put("trustIssues", result.getTrustStoreIssues());
    return map;
  }

  private Path exportFacePreview(byte[] dg2Bytes, Path directory) throws IOException {
    if (dg2Bytes == null || dg2Bytes.length == 0 || directory == null) {
      return null;
    }
    Files.createDirectories(directory);
    try (ByteArrayInputStream in = new ByteArrayInputStream(dg2Bytes)) {
      DG2File dg2 = new DG2File(in);
      List<FaceInfo> faces = dg2.getFaceInfos();
      for (int i = 0; i < faces.size(); i++) {
        FaceInfo faceInfo = faces.get(i);
        List<FaceImageInfo> images = faceInfo.getFaceImageInfos();
        for (int j = 0; j < images.size(); j++) {
          FaceImageInfo imageInfo = images.get(j);
          String extension = mimeToExtension(imageInfo.getMimeType());
          String fileName = String.format("face-preview-%d-%d.%s", i + 1, j + 1, extension);
          Path target = directory.resolve(fileName);
          try (InputStream imageStream = imageInfo.getImageInputStream()) {
            Files.write(target, imageStream.readAllBytes());
          }
          return target;
        }
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Failed to parse DG2 for face preview", e);
    }
    return null;
  }

  private static String mimeToExtension(String mime) {
    if (mime == null) {
      return "bin";
    }
    String normalized = mime.toLowerCase(Locale.ROOT);
    if (normalized.contains("jpeg") || normalized.contains("jpg")) {
      return "jpg";
    }
    if (normalized.contains("png")) {
      return "png";
    }
    if (normalized.contains("jp2")) {
      return "jp2";
    }
    return "bin";
  }

  private void writeManifest(Path outputDir, Map<String, Object> manifest) throws IOException {
    ObjectMapper mapper = new ObjectMapper();
    Path target = outputDir.resolve("manifest.json");
    mapper.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), manifest);
    System.out.println("Manifest written to " + target.toAbsolutePath());
  }

  private static void selectApplet(CardChannel channel) throws CardException {
    byte[] command = new byte[5 + MRTD_AID.length];
    command[0] = 0x00;
    command[1] = (byte) 0xA4;
    command[2] = 0x04;
    command[3] = 0x0C;
    command[4] = (byte) MRTD_AID.length;
    System.arraycopy(MRTD_AID, 0, command, 5, MRTD_AID.length);
    ResponseAPDU response = channel.transmit(new CommandAPDU(command));
    if (response.getSW() != 0x9000) {
      throw new CardException(String.format("SELECT AID failed: SW=%04X", response.getSW()));
    }
  }

  private static void createEf(CardChannel channel, short fid, int size, String label) throws CardException {
    byte[] fcp = new byte[]{
        (byte) 0x63, 0x04,
        (byte) ((size >> 8) & 0xFF), (byte) (size & 0xFF),
        (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)
    };
    transmit(channel, 0x00, 0xE0, 0x00, 0x00, fcp, label);
  }

  private static void selectEf(CardChannel channel, short fid, String label) throws CardException {
    byte[] cmd = new byte[]{0x00, (byte) 0xA4, 0x02, 0x0C, 0x02, (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)};
    transmit(channel, cmd, label);
  }

  private static void writeBinary(CardChannel channel, byte[] data, String label) throws CardException {
    int offset = 0;
    while (offset < data.length) {
      int len = Math.min(0xFF, data.length - offset);
      byte[] chunk = Arrays.copyOfRange(data, offset, offset + len);
      transmit(channel, 0x00, 0xD6, (offset >> 8) & 0xFF, offset & 0xFF, chunk,
          label + String.format(" [%d..%d]", offset, offset + len));
      offset += len;
    }
  }

  private static void putData(CardChannel channel, int p1, int p2, byte[] data, String label) throws CardException {
    transmit(channel, 0x00, 0xDA, p1, p2, data, label);
  }

  private static void transmit(CardChannel channel, byte[] command, String label) throws CardException {
    ResponseAPDU response = channel.transmit(new CommandAPDU(command));
    if (response.getSW() != 0x9000) {
      throw new CardException(String.format("%s failed: SW=%04X", label, response.getSW()));
    }
  }

  private static void transmit(CardChannel channel, int cla, int ins, int p1, int p2, byte[] data, String label)
      throws CardException {
    ResponseAPDU response = channel.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    if (response.getSW() != 0x9000) {
      throw new CardException(String.format("%s failed: SW=%04X", label, response.getSW()));
    }
  }

  private static final class ValidationSummary {
    final PassiveAuthentication.Result passiveAuthentication;

    ValidationSummary(PassiveAuthentication.Result passiveAuthentication) {
      this.passiveAuthentication = passiveAuthentication;
    }
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
  }
}
