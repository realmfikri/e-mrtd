package emu;

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

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.BACKey;
import org.jmrtd.PassportService;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import emu.PersonalizationSupport.SODArtifacts;
import emu.PassiveAuthentication;

/**
 * Service layer that provisions a simulated MRTD and exports issuance artifacts.
 */
public final class IssuerSimulator {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
  private static final short EF_COM = PassportService.EF_COM;
  private static final short EF_SOD = PassportService.EF_SOD;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  private static final ObjectMapper MAPPER = new ObjectMapper();

  public Result run(PersonalizationJob job, Options options) throws Exception {
    Objects.requireNonNull(job, "job");
    Options opts = options != null ? options : new Options();

    Path outputDir = opts.outputDirectory != null ? opts.outputDirectory : Paths.get("target", "issuer");
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

    boolean includeMrzSecret = !opts.omitSecrets && opts.includeMrzSecret;
    if (includeMrzSecret) {
      byte[] mrzSeed = IssuerSecretEncoder.encodeMrzSeed(job.getMrzInfo());
      putData(channel, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
    }

    boolean includePaceSecrets = !opts.omitSecrets && opts.includePaceSecrets;
    if (includePaceSecrets) {
      byte[] paceSecrets = IssuerSecretEncoder.encodePaceSecrets(opts.paceCan, opts.pacePin, opts.pacePuk);
      if (paceSecrets != null) {
        putData(channel, 0x00, 0x65, paceSecrets, "PUT PACE secrets TLV");
      }
    }

    if (opts.openComSodReads != null) {
      byte[] toggle = new byte[]{(byte) (opts.openComSodReads.booleanValue() ? 0x01 : 0x00)};
      putData(channel, 0xDE, 0xFE, toggle,
          opts.openComSodReads.booleanValue() ? "ENABLE open COM/SOD reads" : "DISABLE open COM/SOD reads");
    }

    for (String lifecycle : job.getLifecycleTargets()) {
      String normalized = lifecycle.toUpperCase(Locale.ROOT);
      if ("PERSONALIZED".equals(normalized)) {
        putData(channel, 0xDE, 0xAF, new byte[0], "SET LIFECYCLE → PERSONALIZED");
      } else if ("LOCKED".equals(normalized) && !opts.leavePersonalized) {
        putData(channel, 0xDE, 0xAD, new byte[0], "SET LIFECYCLE → LOCKED");
      }
    }

    card.disconnect(false);

    Path facePreviewPath = null;
    if (opts.facePreview) {
      byte[] dg2Bytes = artifacts.getDataGroupBytes(2);
      if (dg2Bytes != null && dg2Bytes.length > 0) {
        Path previewDir = opts.facePreviewDirectory != null ? opts.facePreviewDirectory : outputDir.resolve("preview");
        facePreviewPath = exportFacePreview(dg2Bytes, previewDir);
      }
    }

    Map<String, Object> manifest = buildManifest(job, artifacts, comBytes, cardAccessBytes, outputDir, facePreviewPath);
    Path manifestPath = writeManifest(outputDir, manifest);

    PassiveAuthentication.Result paResult = null;
    if (opts.validate) {
      paResult = runValidation(terminal, job, opts.validationTrustAnchors);
      if (paResult != null) {
        manifest.put("passiveAuthentication", toManifest(paResult));
        writeManifest(outputDir, manifest);
      }
    }

    boolean canInstalled = includePaceSecrets && hasText(opts.paceCan);
    boolean pinInstalled = includePaceSecrets && hasText(opts.pacePin);
    boolean pukInstalled = includePaceSecrets && hasText(opts.pacePuk);

    return new Result(
        job,
        artifacts,
        outputDir,
        manifestPath,
        manifest,
        simulator,
        terminal,
        facePreviewPath,
        paResult,
        includeMrzSecret,
        canInstalled,
        pinInstalled,
        pukInstalled,
        opts.paceCan,
        opts.pacePin,
        opts.pacePuk,
        opts.openComSodReads,
        opts.leavePersonalized);
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  private PassiveAuthentication.Result runValidation(CardTerminal terminal,
                                                     PersonalizationJob job,
                                                     List<Path> trustAnchors) throws Exception {
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
        return PassiveAuthentication.verify(service, trustAnchors, null);
      } finally {
        logging.close();
      }
    } finally {
      terminalService.close();
    }
  }

  private static void selectApplet(CardChannel channel) throws CardException {
    byte[] command = new byte[5 + MRTD_AID.length];
    command[0] = 0x00;
    command[1] = (byte) 0xA4;
    command[2] = 0x04;
    command[3] = 0x0C;
    command[4] = (byte) MRTD_AID.length;
    System.arraycopy(MRTD_AID, 0, command, 5, MRTD_AID.length);
    transmit(channel, command, "SELECT AID");
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
      byte[] chunk = java.util.Arrays.copyOfRange(data, offset, offset + len);
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

  private static Path writeManifest(Path outputDir, Map<String, Object> manifest) throws IOException {
    Path target = outputDir.resolve("manifest.json");
    MAPPER.writerWithDefaultPrettyPrinter().writeValue(target.toFile(), manifest);
    return target;
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
    try (java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(dg2Bytes)) {
      org.jmrtd.lds.icao.DG2File dg2 = new org.jmrtd.lds.icao.DG2File(in);
      List<org.jmrtd.lds.iso19794.FaceInfo> faces = dg2.getFaceInfos();
      for (int i = 0; i < faces.size(); i++) {
        org.jmrtd.lds.iso19794.FaceInfo faceInfo = faces.get(i);
        List<org.jmrtd.lds.iso19794.FaceImageInfo> images = faceInfo.getFaceImageInfos();
        for (int j = 0; j < images.size(); j++) {
          org.jmrtd.lds.iso19794.FaceImageInfo imageInfo = images.get(j);
          String extension = mimeToExtension(imageInfo.getMimeType());
          String fileName = String.format("face-preview-%d-%d.%s", i + 1, j + 1, extension);
          Path target = directory.resolve(fileName);
          try (java.io.InputStream imageStream = imageInfo.getImageInputStream()) {
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
    switch (mime.toLowerCase(Locale.ROOT)) {
      case "image/jpeg":
        return "jpg";
      case "image/jp2":
      case "image/jpx":
        return "jp2";
      case "image/png":
        return "png";
      default:
        return "bin";
    }
  }

  public static final class Options {
    private Path outputDirectory;
    private boolean omitSecrets;
    private boolean includeMrzSecret = true;
    private boolean includePaceSecrets = true;
    private String paceCan;
    private String pacePin;
    private String pacePuk;
    private Boolean openComSodReads;
    private boolean leavePersonalized;
    private boolean validate;
    private boolean facePreview;
    private Path facePreviewDirectory;
    private List<Path> validationTrustAnchors = List.of();

    public Options outputDirectory(Path outputDirectory) {
      this.outputDirectory = outputDirectory;
      return this;
    }

    public Options omitSecrets(boolean omitSecrets) {
      this.omitSecrets = omitSecrets;
      return this;
    }

    public Options includeMrzSecret(boolean includeMrzSecret) {
      this.includeMrzSecret = includeMrzSecret;
      return this;
    }

    public Options includePaceSecrets(boolean includePaceSecrets) {
      this.includePaceSecrets = includePaceSecrets;
      return this;
    }

    public Options paceCan(String paceCan) {
      this.paceCan = paceCan;
      return this;
    }

    public Options pacePin(String pacePin) {
      this.pacePin = pacePin;
      return this;
    }

    public Options pacePuk(String pacePuk) {
      this.pacePuk = pacePuk;
      return this;
    }

    public Options openComSodReads(Boolean openComSodReads) {
      this.openComSodReads = openComSodReads;
      return this;
    }

    public Options leavePersonalized(boolean leavePersonalized) {
      this.leavePersonalized = leavePersonalized;
      return this;
    }

    public Options validate(boolean validate) {
      this.validate = validate;
      return this;
    }

    public Options facePreview(boolean facePreview) {
      this.facePreview = facePreview;
      return this;
    }

    public Options facePreviewDirectory(Path facePreviewDirectory) {
      this.facePreviewDirectory = facePreviewDirectory;
      return this;
    }

    public Options validationTrustAnchors(List<Path> validationTrustAnchors) {
      this.validationTrustAnchors = validationTrustAnchors != null ? List.copyOf(validationTrustAnchors) : List.of();
      return this;
    }
  }

  public static final class Result {
    private final PersonalizationJob job;
    private final SODArtifacts artifacts;
    private final Path outputDirectory;
    private final Path manifestPath;
    private final Map<String, Object> manifest;
    private final CardSimulator simulator;
    private final CardTerminal terminal;
    private final Path facePreviewPath;
    private final PassiveAuthentication.Result passiveAuthentication;
    private final boolean mrzSeeded;
    private final boolean paceCanInstalled;
    private final boolean pacePinInstalled;
    private final boolean pacePukInstalled;
    private final String paceCan;
    private final String pacePin;
    private final String pacePuk;
    private final Boolean openComSodReadsPolicy;
    private final boolean leavePersonalized;

    Result(PersonalizationJob job,
           SODArtifacts artifacts,
           Path outputDirectory,
           Path manifestPath,
           Map<String, Object> manifest,
           CardSimulator simulator,
           CardTerminal terminal,
           Path facePreviewPath,
           PassiveAuthentication.Result passiveAuthentication,
           boolean mrzSeeded,
           boolean paceCanInstalled,
           boolean pacePinInstalled,
           boolean pacePukInstalled,
           String paceCan,
           String pacePin,
           String pacePuk,
           Boolean openComSodReadsPolicy,
           boolean leavePersonalized) {
      this.job = job;
      this.artifacts = artifacts;
      this.outputDirectory = outputDirectory;
      this.manifestPath = manifestPath;
      this.manifest = manifest;
      this.simulator = simulator;
      this.terminal = terminal;
      this.facePreviewPath = facePreviewPath;
      this.passiveAuthentication = passiveAuthentication;
      this.mrzSeeded = mrzSeeded;
      this.paceCanInstalled = paceCanInstalled;
      this.pacePinInstalled = pacePinInstalled;
      this.pacePukInstalled = pacePukInstalled;
      this.paceCan = paceCan;
      this.pacePin = pacePin;
      this.pacePuk = pacePuk;
      this.openComSodReadsPolicy = openComSodReadsPolicy;
      this.leavePersonalized = leavePersonalized;
    }

    public PersonalizationJob getJob() {
      return job;
    }

    public SODArtifacts getArtifacts() {
      return artifacts;
    }

    public Path getOutputDirectory() {
      return outputDirectory;
    }

    public Path getManifestPath() {
      return manifestPath;
    }

    public Map<String, Object> getManifest() {
      return manifest;
    }

    public CardTerminal getTerminal() {
      return terminal;
    }

    public Optional<Path> getFacePreviewPath() {
      return Optional.ofNullable(facePreviewPath);
    }

    public Optional<PassiveAuthentication.Result> getPassiveAuthenticationResult() {
      return Optional.ofNullable(passiveAuthentication);
    }

    CardSimulator getSimulator() {
      return simulator;
    }

    public boolean isMrzSeeded() {
      return mrzSeeded;
    }

    public boolean isPaceCanInstalled() {
      return paceCanInstalled;
    }

    public boolean isPacePinInstalled() {
      return pacePinInstalled;
    }

    public boolean isPacePukInstalled() {
      return pacePukInstalled;
    }

    public Optional<String> getPaceCan() {
      return Optional.ofNullable(paceCan).filter(IssuerSimulator::hasText);
    }

    public Optional<String> getPacePin() {
      return Optional.ofNullable(pacePin).filter(IssuerSimulator::hasText);
    }

    public Optional<String> getPacePuk() {
      return Optional.ofNullable(pacePuk).filter(IssuerSimulator::hasText);
    }

    public Optional<Boolean> getOpenComSodReadsPolicy() {
      return Optional.ofNullable(openComSodReadsPolicy);
    }

    public boolean isLeavePersonalized() {
      return leavePersonalized;
    }
  }
}

