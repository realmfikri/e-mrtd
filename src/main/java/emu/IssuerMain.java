package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

import net.sf.scuba.data.Gender;
import org.jmrtd.PassportService;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Issuer simulator: generates LDS and PKI artifacts and personalizes the chip.
 */
public final class IssuerMain {

  // AID MRTD (ICAO 9303)
  private static final byte[] MRTD_AID = new byte[]{(byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01};

  // Standard FIDs
  private static final short EF_COM = (short)0x011E;
  private static final short EF_DG1 = (short)0x0101;
  private static final short EF_DG2 = (short)0x0102;
  private static final short EF_DG3 = (short)0x0103;
  private static final short EF_DG4 = (short)0x0104;
  private static final short EF_DG14 = PassportService.EF_DG14;
  private static final short EF_DG15 = (short)0x010F;
  private static final short EF_SOD = (short)0x011D;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  // PUT DATA tags as implemented by the applet
  private static final int INS_PUT_DATA = 0xDA;
  private static final byte P1_LIFECYCLE = (byte)0xDE;
  private static final byte P2_LC_TO_PERSONALIZED = (byte)0xAF;
  private static final byte P2_LC_TO_LOCKED = (byte)0xAD;
  private static final byte P2_OPEN_READS = (byte)0xFE; // payload 0x00 disable / 0x01 enable
  private static final byte TAG_MRZ = 0x62;
  private static final byte TAG_PACE_SECRET_CONTAINER = 0x65;
  private static final byte TAG_PACE_SECRET_ENTRY = 0x66;

  private IssuerMain() {}

  public static void main(String[] args) throws Exception {
    Config cfg = Config.parse(args);

    // 1) Boot simulator + install applet
    CardSimulator sim = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);
    sim.installApplet(aid, sos.passportapplet.PassportApplet.class);
    CardTerminal term = CardTerminalSimulator.terminal(sim);
    Card card = term.connect("*");
    CardChannel ch = card.getBasicChannel();

    // 2) SELECT AID
    apdu(ch, 0x00, 0xA4, 0x04, 0x0C, MRTD_AID, "SELECT AID");

    // 3) COM + DG1 (MRZ) assembly
    int[] tagList = buildComTagList(cfg);
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();

    MRZInfo mrz = new MRZInfo(
        cfg.docType, cfg.issuingState, cfg.surname, cfg.givenNames,
        cfg.documentNumber, cfg.nationality, cfg.dateOfBirth, cfg.gender, cfg.dateOfExpiry, cfg.optionalData);
    DG1File dg1 = new DG1File(mrz);
    byte[] dg1Bytes = dg1.getEncoded();

    // 4) Build remaining artifacts via helper
    emu.PersonalizationSupport.SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(
        dg1Bytes, cfg.faceWidth, cfg.faceHeight, cfg.corruptDG2);

    // 5) Write EF files
    writeEf(ch, EF_COM, comBytes, "EF.COM");
    writeEf(ch, EF_DG1, dg1Bytes, "EF.DG1");
    if (cfg.includeCardAccess && artifacts.cardAccessBytes != null && artifacts.cardAccessBytes.length > 0) {
      writeEf(ch, EF_CARD_ACCESS, artifacts.cardAccessBytes, "EF.CardAccess");
    }
    writeEf(ch, EF_DG2, artifacts.dg2Bytes, "EF.DG2");
    if (cfg.includeDG3 && artifacts.dg3Bytes != null && artifacts.dg3Bytes.length > 0) {
      writeEf(ch, EF_DG3, artifacts.dg3Bytes, "EF.DG3");
    }
    if (cfg.includeDG4 && artifacts.dg4Bytes != null && artifacts.dg4Bytes.length > 0) {
      writeEf(ch, EF_DG4, artifacts.dg4Bytes, "EF.DG4");
    }
    if (cfg.includeDG14 && artifacts.dg14Bytes != null && artifacts.dg14Bytes.length > 0) {
      writeEf(ch, EF_DG14, artifacts.dg14Bytes, "EF.DG14");
    }
    if (cfg.includeDG15 && artifacts.dg15Bytes != null && artifacts.dg15Bytes.length > 0) {
      writeEf(ch, EF_DG15, artifacts.dg15Bytes, "EF.DG15");
    }
    writeEf(ch, EF_SOD, artifacts.sodBytes, "EF.SOD");

    // 6) Inject MRZ (for BAC and MRZ-based PACE) and optional PACE secrets
    if (cfg.injectMrz) {
      putMrz(ch, mrz);
    }
    if (cfg.canValue != null && !cfg.canValue.isEmpty()) {
      putPaceSecret(ch, (byte)2, cfg.canValue);
    }

    // 7) Lifecycle and open read policy
    if (cfg.toPersonalized) {
      putLifecycle(ch, P2_LC_TO_PERSONALIZED, new byte[0], "LIFECYCLE → PERSONALIZED");
    }
    if (cfg.toLocked) {
      putLifecycle(ch, P2_LC_TO_LOCKED, new byte[0], "LIFECYCLE → LOCKED");
      putLifecycle(ch, P2_OPEN_READS, new byte[]{(byte)(cfg.openComSodReads ? 0x01 : 0x00)},
          cfg.openComSodReads ? "Open reads COM/SOD enabled" : "Open reads COM/SOD disabled");
    }

    // 8) Export artifacts for Passive Authentication
    exportArtifacts(cfg, artifacts, comBytes, dg1Bytes);
    // Keep compatibility with existing trust-store location
    Path trustDir = Paths.get("target", "trust-store");
    try {
      Files.createDirectories(trustDir);
      Files.write(trustDir.resolve("csca.cer"), artifacts.cscaCert.getEncoded());
      System.out.println("Trust store updated -> " + trustDir.toAbsolutePath());
    } catch (IOException ignore) {
    }

    System.out.println("\n✅ Issuer personalization complete.");
  }

  private static int[] buildComTagList(Config cfg) {
    List<Integer> list = new ArrayList<>();
    list.add(LDSFile.EF_DG1_TAG);
    list.add(LDSFile.EF_DG2_TAG);
    if (cfg.includeDG3) list.add(LDSFile.EF_DG3_TAG);
    if (cfg.includeDG4) list.add(LDSFile.EF_DG4_TAG);
    if (cfg.includeDG14) list.add(LDSFile.EF_DG14_TAG);
    if (cfg.includeDG15) list.add(LDSFile.EF_DG15_TAG);
    return list.stream().mapToInt(Integer::intValue).toArray();
  }

  private static void exportArtifacts(Config cfg,
                                      PersonalizationSupport.SODArtifacts artifacts,
                                      byte[] comBytes,
                                      byte[] dg1Bytes) throws IOException {
    Path out = cfg.outDir;
    Files.createDirectories(out);
    Files.write(out.resolve("EF.COM.bin"), comBytes);
    Files.write(out.resolve("EF.DG1.bin"), dg1Bytes);
    Files.write(out.resolve("EF.DG2.bin"), artifacts.dg2Bytes);
    if (artifacts.dg3Bytes != null) Files.write(out.resolve("EF.DG3.bin"), artifacts.dg3Bytes);
    if (artifacts.dg4Bytes != null) Files.write(out.resolve("EF.DG4.bin"), artifacts.dg4Bytes);
    if (artifacts.dg14Bytes != null) Files.write(out.resolve("EF.DG14.bin"), artifacts.dg14Bytes);
    if (artifacts.dg15Bytes != null) Files.write(out.resolve("EF.DG15.bin"), artifacts.dg15Bytes);
    if (artifacts.cardAccessBytes != null) Files.write(out.resolve("EF.CardAccess.bin"), artifacts.cardAccessBytes);
    Files.write(out.resolve("EF.SOD.bin"), artifacts.sodBytes);
    Files.write(out.resolve("csca.cer"), artifacts.cscaCert.getEncoded());
    Files.write(out.resolve("dsc.cer"), artifacts.docSignerCert.getEncoded());
    // minimal manifest
    String manifest = String.join("\n",
        "issuer=IssuerMain",
        "docNumber=" + cfg.documentNumber,
        "dob=" + cfg.dateOfBirth,
        "doe=" + cfg.dateOfExpiry,
        "gender=" + cfg.gender.toString(),
        "includeDG3=" + cfg.includeDG3,
        "includeDG4=" + cfg.includeDG4,
        "includeDG14=" + cfg.includeDG14,
        "includeDG15=" + cfg.includeDG15);
    Files.write(out.resolve("manifest.properties"), manifest.getBytes(StandardCharsets.UTF_8));
    System.out.println("Artifacts exported to → " + out.toAbsolutePath());
  }

  private static void writeEf(CardChannel ch, short fid, byte[] data, String label) throws Exception {
    createEF(ch, fid, data.length, "CREATE " + label);
    selectEF(ch, fid, "SELECT " + label + " before WRITE");
    writeBinary(ch, data, "WRITE " + label);
  }

  private static void putMrz(CardChannel ch, MRZInfo mrz) throws Exception {
    // Encode MRZ as: [62 TLV [01 TLV docNr][02 TLV dob][03 TLV doe]]
    byte[] docNr = mrz.getDocumentNumber().getBytes(StandardCharsets.US_ASCII);
    byte[] dob = mrz.getDateOfBirth().getBytes(StandardCharsets.US_ASCII);
    byte[] doe = mrz.getDateOfExpiry().getBytes(StandardCharsets.US_ASCII);
    byte[] inner = concat(
        tlv((byte)0x01, docNr),
        tlv((byte)0x02, dob),
        tlv((byte)0x03, doe));
    byte[] body = tlv(TAG_MRZ, inner);
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, INS_PUT_DATA, 0x00, TAG_MRZ & 0xFF, body));
    System.out.printf("PUT DATA MRZ → SW=%04X%n", r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException("PUT DATA MRZ failed");
  }

  private static void putPaceSecret(CardChannel ch, byte keyRef, String ascii) throws Exception {
    byte[] value = ascii.getBytes(StandardCharsets.US_ASCII);
    byte[] entry = new byte[value.length + 1];
    entry[0] = keyRef;
    System.arraycopy(value, 0, entry, 1, value.length);
    byte[] inner = tlv(TAG_PACE_SECRET_ENTRY, entry);
    byte[] body = tlv(TAG_PACE_SECRET_CONTAINER, inner);
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, INS_PUT_DATA, 0x00, TAG_PACE_SECRET_CONTAINER & 0xFF, body));
    System.out.printf("PUT DATA PACE secret (ref=%d) → SW=%04X%n", keyRef, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException("PUT DATA PACE secret failed");
  }

  private static void putLifecycle(CardChannel ch, byte p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, INS_PUT_DATA, P1_LIFECYCLE & 0xFF, p2 & 0xFF, data));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed");
  }

  // ======= util APDU =======

  private static void createEF(CardChannel ch, short fid, int size, String label) throws Exception {
    byte[] fcp = new byte[]{
        (byte)0x63, 0x04,
        (byte)((size >> 8) & 0xFF), (byte)(size & 0xFF),
        (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)
    };
    apdu(ch, 0x00, 0xE0, 0x00, 0x00, fcp, label);
  }

  private static void writeBinary(CardChannel ch, byte[] data, String label) throws Exception {
    int off = 0;
    while (off < data.length) {
      int len = Math.min(0xFF, data.length - off);
      byte[] chunk = Arrays.copyOfRange(data, off, off + len);
      apdu(ch, 0x00, 0xD6, (off >> 8) & 0xFF, off & 0xFF, chunk,
          label + " (ofs=" + off + ", len=" + len + ")");
      off += len;
    }
  }

  private static void selectEF(CardChannel ch, short fid, String label) throws Exception {
    byte[] cmd = new byte[]{0x00, (byte)0xA4, 0x02, 0x0C, 0x02, (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)};
    ResponseAPDU r = ch.transmit(new CommandAPDU(cmd));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
  }

  private static ResponseAPDU apdu(CardChannel ch, int cla, int ins, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
    return r;
  }

  private static byte[] tlv(byte tag, byte[] value) {
    byte[] out;
    if (value.length < 0x80) {
      out = new byte[2 + value.length];
      out[0] = tag;
      out[1] = (byte)(value.length & 0xFF);
      System.arraycopy(value, 0, out, 2, value.length);
    } else {
      out = new byte[3 + value.length];
      out[0] = tag;
      out[1] = (byte)0x81;
      out[2] = (byte)(value.length & 0xFF);
      System.arraycopy(value, 0, out, 3, value.length);
    }
    return out;
  }

  private static byte[] concat(byte[]... parts) {
    int total = 0;
    for (byte[] p : parts) total += p.length;
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  private static final class Config {
    // MRZ fields
    String docType = "P<";
    String issuingState = "UTO";
    String surname = "BEAN";
    String givenNames = "HAPPY";
    String documentNumber = "123456789";
    String nationality = "UTO";
    String dateOfBirth = "750101"; // YYMMDD
    Gender gender = Gender.MALE;
    String dateOfExpiry = "250101"; // YYMMDD
    String optionalData = "";

    // Options
    boolean includeDG3 = true;
    boolean includeDG4 = true;
    boolean includeDG14 = true;
    boolean includeDG15 = true;
    boolean includeCardAccess = true;
    boolean corruptDG2 = false;
    int faceWidth = 480;
    int faceHeight = 600;
    boolean injectMrz = true; // to enable BAC + PACE(MRZ)
    String canValue = null;   // optional PACE CAN
    boolean toPersonalized = true;
    boolean toLocked = false;
    boolean openComSodReads = true;
    Path outDir = Paths.get("target", "issuer-out");

    static Config parse(String[] args) {
      Config c = new Config();
      List<String> as = new ArrayList<>(List.of(args));
      for (int i = 0; i < as.size(); i++) {
        String a = as.get(i);
        switch (a) {
          case "--doc-type": c.docType = next(as, ++i, "--doc-type"); break;
          case "--issuing-state": c.issuingState = next(as, ++i, "--issuing-state"); break;
          case "--surname": c.surname = next(as, ++i, "--surname"); break;
          case "--given-names": c.givenNames = next(as, ++i, "--given-names"); break;
          case "--doc-number": c.documentNumber = next(as, ++i, "--doc-number"); break;
          case "--nationality": c.nationality = next(as, ++i, "--nationality"); break;
          case "--dob": c.dateOfBirth = next(as, ++i, "--dob"); break;
          case "--doe": c.dateOfExpiry = next(as, ++i, "--doe"); break;
          case "--gender": c.gender = parseGender(next(as, ++i, "--gender")); break;
          case "--optional": c.optionalData = next(as, ++i, "--optional"); break;
          case "--no-dg3": c.includeDG3 = false; break;
          case "--no-dg4": c.includeDG4 = false; break;
          case "--no-dg14": c.includeDG14 = false; break;
          case "--no-dg15": c.includeDG15 = false; break;
          case "--no-cardaccess": c.includeCardAccess = false; break;
          case "--corrupt-dg2": c.corruptDG2 = true; break;
          case "--face-w": c.faceWidth = Integer.parseInt(next(as, ++i, "--face-w")); break;
          case "--face-h": c.faceHeight = Integer.parseInt(next(as, ++i, "--face-h")); break;
          case "--no-mrz-put": c.injectMrz = false; break;
          case "--can": c.canValue = next(as, ++i, "--can"); break;
          case "--to-personalized": c.toPersonalized = true; break;
          case "--to-locked": c.toLocked = true; break;
          case "--open-reads": c.openComSodReads = true; break;
          case "--no-open-reads": c.openComSodReads = false; break;
          case "--out-dir": c.outDir = Paths.get(next(as, ++i, "--out-dir")); break;
          case "--help":
          case "-h":
            printUsageAndExit();
            break;
          default:
            if (a.startsWith("--out-dir=")) c.outDir = Paths.get(a.substring("--out-dir=".length()));
            else if (a.startsWith("--can=")) c.canValue = a.substring("--can=".length());
            else if (a.startsWith("--gender=")) c.gender = parseGender(a.substring("--gender=".length()));
            else if (a.startsWith("--doc-number=")) c.documentNumber = a.substring("--doc-number=".length());
            break;
        }
      }
      return c;
    }

    private static String next(List<String> args, int idx, String opt) {
      if (idx >= args.size()) {
        System.err.println(opt + " requires a value");
        printUsageAndExit();
      }
      return args.get(idx);
    }

    private static Gender parseGender(String v) {
      String s = v.trim().toUpperCase(Locale.ROOT);
      if (s.startsWith("M")) return Gender.MALE;
      if (s.startsWith("F")) return Gender.FEMALE;
      return Gender.UNSPECIFIED;
    }

    private static void printUsageAndExit() {
      System.out.println(
          "Usage: IssuerMain [options]\n" +
              "  --doc-type <P<|ID|...>        MRZ document type (default P<)\n" +
              "  --issuing-state <A2>          Issuing state (default UTO)\n" +
              "  --surname <text>              Surname (default BEAN)\n" +
              "  --given-names <text>         Given names (default HAPPY)\n" +
              "  --doc-number <text>          Document number (default 123456789)\n" +
              "  --nationality <A2>           Nationality (default UTO)\n" +
              "  --dob <yymmdd>               Date of birth (default 750101)\n" +
              "  --doe <yymmdd>               Date of expiry (default 250101)\n" +
              "  --gender <M|F|X>             Gender (default M)\n" +
              "  --no-dg3|--no-dg4|--no-dg14|--no-dg15  Exclude DGs\n" +
              "  --no-cardaccess              Skip EF.CardAccess\n" +
              "  --corrupt-dg2                Corrupt DG2 bytes (test PA failure)\n" +
              "  --face-w <px> --face-h <px>  Synthetic face size (default 480x600)\n" +
              "  --no-mrz-put                 Do not PUT-DATA MRZ to chip\n" +
              "  --can <digits>               Set PACE CAN secret\n" +
              "  --to-personalized            Set lifecycle to PERSONALIZED (default)\n" +
              "  --to-locked                  Then set lifecycle to LOCKED\n" +
              "  --open-reads|--no-open-reads Open COM/SOD reads in LOCKED (default on)\n" +
              "  --out-dir <path>             Export artifacts directory (default target/issuer-out)\n");
      System.exit(0);
    }
  }
}
