package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

import net.sf.scuba.data.Gender;
import net.sf.scuba.smartcards.TerminalCardService;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationField;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.jmrtd.BACKey;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.TerminalAuthenticationInfo;
import org.jmrtd.lds.icao.COMFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.PACEResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import emu.PersonalizationSupport.SODArtifacts;

public class ReadDG1Main {
  private static final byte[] MRTD_AID = new byte[]{(byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01};
  private static final short EF_COM = (short)0x011E;
  private static final short EF_DG1 = (short)0x0101;
  private static final short EF_DG2 = (short)0x0102;
  private static final short EF_DG14 = PassportService.EF_DG14;
  private static final short EF_DG15 = (short)0x010F;
  private static final short EF_SOD = (short)0x011D;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  // >>> samakan MRZ ini dengan yang kamu tulis ke EF.DG1 saat "PersoMain"
  private static final String DOC = "123456789";
  private static final String DOB = "750101";
  private static final String DOE = "250101";

  public static void main(String[] args) throws Exception {
    boolean seed = false;
    boolean corruptDG2 = false;
    boolean largeDG2 = false;
    Path trustStorePath = null;
    String trustStorePassword = null;
    boolean requirePA = false;
    List<Path> taCvcPaths = new ArrayList<>();

    List<String> argList = Arrays.asList(args);
    for (int i = 0; i < argList.size(); i++) {
      String arg = argList.get(i);
      if ("--seed".equals(arg)) {
        seed = true;
      } else if (arg.startsWith("--trust-store=")) {
        trustStorePath = Paths.get(arg.substring("--trust-store=".length()));
      } else if ("--trust-store".equals(arg)) {
        i = advanceWithValue(argList, i, "--trust-store");
        trustStorePath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--trust-store-password=")) {
        trustStorePassword = arg.substring("--trust-store-password=".length());
      } else if ("--trust-store-password".equals(arg)) {
        i = advanceWithValue(argList, i, "--trust-store-password");
        trustStorePassword = argList.get(i);
      } else if ("--require-pa".equals(arg)) {
        requirePA = true;
      } else if ("--corrupt-dg2".equals(arg)) {
        corruptDG2 = true;
      } else if ("--large-dg2".equals(arg)) {
        largeDG2 = true;
      } else if (arg.startsWith("--ta-cvc=")) {
        taCvcPaths.add(Paths.get(arg.substring("--ta-cvc=".length())));
      } else if ("--ta-cvc".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-cvc");
        taCvcPaths.add(Paths.get(argList.get(i)));
      }
    }

    // Boot emulator & install applet
    CardSimulator sim = new CardSimulator();
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);
    sim.installApplet(aid, sos.passportapplet.PassportApplet.class);

    CardTerminal term = CardTerminalSimulator.terminal(sim);
    Card card = term.connect("*");
    CardChannel ch = card.getBasicChannel();

    // SELECT AID
    apdu(ch, 0x00, 0xA4, 0x04, 0x0C, MRTD_AID, "SELECT AID");

    // --- tulis data minimal (COM + DG1 + DG2) ke chip ---
    SODArtifacts personalizationArtifacts = personalize(ch, corruptDG2, largeDG2);

    // --- langkah penting: tanam kunci BAC di applet ---
    if (seed) {
      byte[] mrzSeed = buildMrzSeed(DOC, DOB, DOE);
      boolean ok = putData(ch, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
      if (!ok) throw new RuntimeException("SET BAC via PUT DATA gagal. Cek format TLV.");
    }

    // --- sekarang baca via PassportService + BAC ---
    byte[] rawCardAccess = readEfPlain(ch, EF_CARD_ACCESS);
    if ((rawCardAccess == null || rawCardAccess.length == 0) && personalizationArtifacts != null) {
      rawCardAccess = personalizationArtifacts.cardAccessBytes;
    }
    if (rawCardAccess != null) {
      System.out.printf("EF.CardAccess length=%d bytes%n", rawCardAccess.length);
    }
    List<PACEInfo> paceInfos = parsePaceInfos(rawCardAccess);

    PassportService svc = new PassportService(
        new TerminalCardService(term),
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false, false);
    svc.open();
    svc.sendSelectApplet(false);

    BACKey bacKey = new BACKey(DOC, DOB, DOE);

    PaceOutcome paceOutcome = attemptPACE(svc, bacKey, paceInfos);
    if (paceOutcome.attempted) {
      logPaceOutcome(paceOutcome);
    } else {
      System.out.println("PACE not attempted (EF.CardAccess missing or no PACE info).");
    }

    if (!paceOutcome.established) {
      System.out.println("Falling back to BAC secure messaging.");
      svc.doBAC(bacKey);
    }

    System.out.printf("paceAttempted=%s, paceEstablished=%s%n", paceOutcome.attempted, paceOutcome.established);
    byte[] cardAccessPostAuth = readEf(svc, PassportService.EF_CARD_ACCESS);
    if (cardAccessPostAuth != null && (rawCardAccess == null || rawCardAccess.length == 0)) {
      System.out.printf("EF.CardAccess (post-auth) length=%d bytes%n", cardAccessPostAuth.length);
      rawCardAccess = cardAccessPostAuth;
    }

    DG14File dg14 = readDG14(svc);
    ChipAuthOutcome chipAuthOutcome = performChipAuthenticationIfSupported(svc, dg14);
    System.out.printf("caEstablished=%s%n", chipAuthOutcome.established);

    List<CvcBundle> taCertificates = loadCvcCertificates(taCvcPaths);
    reportTerminalAuthentication(dg14, taCertificates);

    // baca DG1 (MRZ)
    try (InputStream in = svc.getInputStream(PassportService.EF_DG1)) {
      DG1File dg1 = new DG1File(in);
      MRZInfo info = dg1.getMRZInfo();
      System.out.println("==== DG1 ====");
      System.out.println("Doc#: " + info.getDocumentNumber());
      System.out.println("DOB  : " + info.getDateOfBirth());
      System.out.println("DOE  : " + info.getDateOfExpiry());
      System.out.println("Name : " + info.getSecondaryIdentifier() + ", " + info.getPrimaryIdentifier());
      System.out.println("Gender: " + info.getGender()); // jmrtd 0.8.x
    }

    if (trustStorePath == null) {
      Path defaultTrust = Paths.get("target", "trust-store");
      if (Files.isDirectory(defaultTrust)) {
        trustStorePath = defaultTrust;
      }
    }

    boolean runPA = trustStorePath != null || requirePA;
    if (runPA) {
      char[] passwordChars = trustStorePassword != null ? trustStorePassword.toCharArray() : null;
      PassiveAuthentication.Result paResult = PassiveAuthentication.verify(svc, trustStorePath, passwordChars);
      paResult.printReport();
      if (requirePA && !paResult.isPass()) {
        throw new RuntimeException("Passive Authentication failed but was required");
      }
      if (passwordChars != null) {
        Arrays.fill(passwordChars, '\0');
      }
    }

    printDG2Summary(svc, largeDG2);
  }

  private static int advanceWithValue(List<String> args, int index, String option) {
    int next = index + 1;
    if (next >= args.size()) {
      throw new IllegalArgumentException(option + " requires a value");
    }
    return next;
  }

  private static SODArtifacts personalize(CardChannel ch, boolean corruptDG2, boolean largeDG2) throws Exception {
    int[] tagList = new int[]{LDSFile.EF_DG1_TAG, LDSFile.EF_DG2_TAG, LDSFile.EF_DG14_TAG, LDSFile.EF_DG15_TAG};
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();

    MRZInfo mrz = new MRZInfo("P<", "UTO", "BEAN", "HAPPY",
        DOC, "UTO", DOB, Gender.MALE, DOE, "");
    DG1File dg1 = new DG1File(mrz);
    byte[] dg1Bytes = dg1.getEncoded();

    createEF(ch, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEF(ch, EF_COM, "SELECT EF.COM before WRITE");
    writeBinary(ch, comBytes, "WRITE EF.COM");

    createEF(ch, EF_DG1, dg1Bytes.length, "CREATE EF.DG1");
    selectEF(ch, EF_DG1, "SELECT EF.DG1 before WRITE");
    writeBinary(ch, dg1Bytes, "WRITE EF.DG1");

    int faceWidth = largeDG2 ? 720 : 480;
    int faceHeight = largeDG2 ? 960 : 600;
    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(dg1Bytes, faceWidth, faceHeight, corruptDG2);

    if (artifacts.cardAccessBytes != null && artifacts.cardAccessBytes.length > 0) {
      createEF(ch, EF_CARD_ACCESS, artifacts.cardAccessBytes.length, "CREATE EF.CardAccess");
      selectEF(ch, EF_CARD_ACCESS, "SELECT EF.CardAccess before WRITE");
      writeBinary(ch, artifacts.cardAccessBytes, "WRITE EF.CardAccess");
    }

    createEF(ch, EF_DG15, artifacts.dg15Bytes.length, "CREATE EF.DG15");
    selectEF(ch, EF_DG15, "SELECT EF.DG15 before WRITE");
    writeBinary(ch, artifacts.dg15Bytes, "WRITE EF.DG15");

    if (artifacts.dg14Bytes != null && artifacts.dg14Bytes.length > 0) {
      createEF(ch, EF_DG14, artifacts.dg14Bytes.length, "CREATE EF.DG14");
      selectEF(ch, EF_DG14, "SELECT EF.DG14 before WRITE");
      writeBinary(ch, artifacts.dg14Bytes, "WRITE EF.DG14");
    }

    createEF(ch, EF_DG2, artifacts.dg2Bytes.length, "CREATE EF.DG2");
    selectEF(ch, EF_DG2, "SELECT EF.DG2 before WRITE");
    writeBinary(ch, artifacts.dg2Bytes, "WRITE EF.DG2");

    createEF(ch, EF_SOD, artifacts.sodBytes.length, "CREATE EF.SOD");
    selectEF(ch, EF_SOD, "SELECT EF.SOD before WRITE");
    writeBinary(ch, artifacts.sodBytes, "WRITE EF.SOD");

    Path trustDir = Paths.get("target", "trust-store");
    Files.createDirectories(trustDir);
    try (var stream = Files.list(trustDir)) {
      stream.filter(Files::isRegularFile).forEach(path -> {
        try {
          Files.delete(path);
        } catch (Exception ignore) {
        }
      });
    }
    Files.deleteIfExists(trustDir.resolve("dsc.cer"));
    Files.write(trustDir.resolve("csca.cer"), artifacts.cscaCert.getEncoded());
    return artifacts;
  }

  private static List<PACEInfo> parsePaceInfos(byte[] cardAccessBytes) {
    if (cardAccessBytes == null || cardAccessBytes.length == 0) {
      return List.of();
    }
    try (ByteArrayInputStream in = new ByteArrayInputStream(cardAccessBytes)) {
      CardAccessFile cardAccess = new CardAccessFile(in);
      List<PACEInfo> paceInfos = new ArrayList<>();
      Collection<SecurityInfo> securityInfos = cardAccess.getSecurityInfos();
      if (securityInfos != null) {
        for (SecurityInfo securityInfo : securityInfos) {
          if (securityInfo instanceof PACEInfo) {
            paceInfos.add((PACEInfo) securityInfo);
          }
        }
      }
      return paceInfos;
    } catch (IOException e) {
      System.out.println("Failed to parse EF.CardAccess: " + e.getMessage());
      return List.of();
    }
  }

  private static byte[] readEfPlain(CardChannel ch, short fid) {
    byte[] cmd = new byte[]{0x00, (byte) 0xA4, 0x02, 0x0C, 0x02, (byte) ((fid >> 8) & 0xFF), (byte) (fid & 0xFF)};
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      ResponseAPDU select = ch.transmit(new CommandAPDU(cmd));
      if (select.getSW() != 0x9000) {
        System.out.printf("EF %04X select failed SW=%04X%n", fid & 0xFFFF, select.getSW());
        return null;
      }
      int offset = 0;
      while (offset < 4096) {
        int le = Math.min(0xFF, 4096 - offset);
        ResponseAPDU read = ch.transmit(new CommandAPDU(0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, le));
        int sw = read.getSW();
        if ((sw & 0xFF00) == 0x6C00) {
          int suggested = sw & 0xFF;
          if (suggested == 0) {
            suggested = 256;
          }
          read = ch.transmit(new CommandAPDU(0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, suggested));
          sw = read.getSW();
        }
        if (sw != 0x9000 && sw != 0x6282) {
          System.out.printf("EF %04X read SW=%04X at offset=%d%n", fid & 0xFFFF, sw, offset);
          if (offset == 0) {
            return null;
          }
          break;
        }
        byte[] chunk = read.getData();
        if (chunk.length > 0) {
          out.write(chunk);
          offset += chunk.length;
        }
        if (chunk.length < le || sw == 0x6282 || chunk.length == 0) {
          break;
        }
      }
      return out.toByteArray();
    } catch (Exception ignore) {
      return null;
    } finally {
      try {
        ch.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x0C, MRTD_AID));
      } catch (Exception ignored) {
      }
    }
  }

  private static PaceOutcome attemptPACE(PassportService svc, BACKey bacKey, List<PACEInfo> paceInfos) {
    PaceOutcome outcome = new PaceOutcome();
    if (paceInfos == null || paceInfos.isEmpty()) {
      return outcome;
    }
    outcome.availableOptions = paceInfos.size();
    outcome.attempted = true;
    outcome.selectedInfo = selectPreferredPACEInfo(paceInfos);
    try {
      AlgorithmParameterSpec parameterSpec = buildPaceParameterSpec(outcome.selectedInfo);
      PACEResult result = svc.doPACE(
          PACEKeySpec.createMRZKey(bacKey),
          outcome.selectedInfo.getProtocolOIDString(),
          parameterSpec,
          outcome.selectedInfo.getParameterId());
      outcome.result = result;
      outcome.established = result != null && result.getWrapper() != null;
    } catch (Exception e) {
      outcome.failure = e;
    }
    return outcome;
  }

  private static void logPaceOutcome(PaceOutcome outcome) {
    System.out.printf("PACE entries advertised: %d%n", outcome.availableOptions);
    if (outcome.selectedInfo != null) {
      BigInteger parameterId = outcome.selectedInfo.getParameterId();
      System.out.printf("Selected PACE OID=%s version=%d paramId=%s keyLength=%d%n",
          outcome.selectedInfo.getProtocolOIDString(),
          outcome.selectedInfo.getVersion(),
          parameterId != null ? parameterId.toString(16) : "default",
          resolvePaceKeyLength(outcome.selectedInfo));
    }
    if (outcome.result != null) {
      System.out.printf("PACE mapping=%s agreement=%s cipher=%s digest=%s keyLength=%d%n",
          outcome.result.getMappingType(),
          outcome.result.getAgreementAlg(),
          outcome.result.getCipherAlg(),
          outcome.result.getDigestAlg(),
          outcome.result.getKeyLength());
    }
    if (outcome.established) {
      System.out.println("PACE secure messaging established.");
    } else if (outcome.failure != null) {
      System.out.println("PACE failed: " + outcome.failure.getMessage());
    } else if (outcome.attempted) {
      System.out.println("PACE did not establish secure messaging.");
    }
  }

  private static PACEInfo selectPreferredPACEInfo(List<PACEInfo> paceInfos) {
    return paceInfos.stream()
        .max(Comparator.comparingInt(ReadDG1Main::resolvePaceKeyLength))
        .orElse(paceInfos.get(0));
  }

  private static int resolvePaceKeyLength(PACEInfo info) {
    if (info == null) {
      return 0;
    }
    String oid = info.getProtocolOIDString();
    if (oid == null) {
      return 0;
    }
    try {
      return PACEInfo.toKeyLength(oid);
    } catch (Exception e) {
      return 0;
    }
  }

  private static AlgorithmParameterSpec buildPaceParameterSpec(PACEInfo info) {
    if (info == null) {
      return null;
    }
    BigInteger parameterId = info.getParameterId();
    if (parameterId != null) {
      return PACEInfo.toParameterSpec(parameterId);
    }
    return null;
  }

  private static DG14File readDG14(PassportService svc) {
    byte[] dg14Bytes = readEf(svc, PassportService.EF_DG14);
    if (dg14Bytes == null || dg14Bytes.length == 0) {
      System.out.println("DG14 not present or unreadable.");
      return null;
    }
    try (ByteArrayInputStream in = new ByteArrayInputStream(dg14Bytes)) {
      return new DG14File(in);
    } catch (IOException e) {
      System.out.println("DG14 parse failed: " + e.getMessage());
      return null;
    }
  }

  private static ChipAuthOutcome performChipAuthenticationIfSupported(PassportService svc, DG14File dg14) {
    ChipAuthOutcome outcome = new ChipAuthOutcome();
    if (dg14 == null) {
      System.out.println("Chip Authentication info unavailable (DG14 missing).");
      return outcome;
    }
    List<ChipAuthenticationInfo> chipInfos = dg14.getChipAuthenticationInfos();
    List<ChipAuthenticationPublicKeyInfo> publicKeyInfos = dg14.getChipAuthenticationPublicKeyInfos();
    outcome.advertised = chipInfos != null && !chipInfos.isEmpty();
    if (!outcome.advertised) {
      System.out.println("Chip Authentication not advertised in DG14.");
      return outcome;
    }

    System.out.printf("Chip Authentication entries advertised: %d%n", chipInfos.size());
    for (ChipAuthenticationInfo info : chipInfos) {
      BigInteger keyId = info.getKeyId();
      System.out.printf("  CA OID=%s version=%d keyId=%s keyLength=%d%n",
          info.getProtocolOIDString(),
          info.getVersion(),
          keyId != null ? keyId.toString(16) : "n/a",
          resolveChipKeyLength(info));
    }

    Map<BigInteger, ChipAuthenticationPublicKeyInfo> publicKeysById = new HashMap<>();
    ChipAuthenticationPublicKeyInfo fallbackKey = null;
    if (publicKeyInfos != null) {
      for (ChipAuthenticationPublicKeyInfo keyInfo : publicKeyInfos) {
        BigInteger keyId = keyInfo.getKeyId();
        if (keyId != null) {
          publicKeysById.put(keyId, keyInfo);
        }
        if (fallbackKey == null) {
          fallbackKey = keyInfo;
        }
      }
    }

    outcome.selectedInfo = selectPreferredChipAuth(chipInfos);
    if (outcome.selectedInfo == null) {
      System.out.println("Unable to select Chip Authentication profile.");
      return outcome;
    }

    BigInteger keyId = outcome.selectedInfo.getKeyId();
    ChipAuthenticationPublicKeyInfo publicKeyInfo = keyId != null ? publicKeysById.get(keyId) : null;
    if (publicKeyInfo == null) {
      publicKeyInfo = fallbackKey;
    }

    if (publicKeyInfo == null) {
      System.out.println("Chip Authentication public key not found; skipping CA handshake.");
      return outcome;
    }

    outcome.publicKeyInfo = publicKeyInfo;
    try {
      String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(outcome.selectedInfo.getProtocolOIDString());
      String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(outcome.selectedInfo.getProtocolOIDString());
      EACCAResult result = svc.doEACCA(keyId, agreementAlg, cipherAlg, publicKeyInfo.getSubjectPublicKey());
      outcome.result = result;
      outcome.established = result != null && result.getWrapper() != null;
      if (outcome.established) {
        System.out.printf("Chip Authentication established (agreement=%s cipher=%s keyId=%s).%n",
            agreementAlg, cipherAlg, keyId != null ? keyId.toString(16) : "n/a");
      } else {
        System.out.println("Chip Authentication handshake did not upgrade secure messaging.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      System.out.println("Chip Authentication failed: " + e.getMessage());
    }
    return outcome;
  }

  private static ChipAuthenticationInfo selectPreferredChipAuth(List<ChipAuthenticationInfo> chipInfos) {
    return chipInfos.stream()
        .max(Comparator.comparingInt(ReadDG1Main::resolveChipKeyLength))
        .orElse(chipInfos.get(0));
  }

  private static int resolveChipKeyLength(ChipAuthenticationInfo info) {
    if (info == null) {
      return 0;
    }
    String oid = info.getProtocolOIDString();
    if (oid == null) {
      return 0;
    }
    try {
      return ChipAuthenticationInfo.toKeyLength(oid);
    } catch (Exception e) {
      return 0;
    }
  }

  private static List<CvcBundle> loadCvcCertificates(List<Path> paths) {
    List<CvcBundle> bundles = new ArrayList<>();
    for (Path path : paths) {
      try {
        byte[] encoded = Files.readAllBytes(path);
        CVCertificate certificate = CertificateParser.parseCertificate(encoded);
        bundles.add(new CvcBundle(path, certificate, null));
      } catch (IOException | ParseException | ConstructionException e) {
        bundles.add(new CvcBundle(path, null, e));
      }
    }
    return bundles;
  }

  private static void reportTerminalAuthentication(DG14File dg14, List<CvcBundle> cvcBundles) {
    if (dg14 == null) {
      System.out.println("Terminal Authentication info unavailable (DG14 missing).");
    } else {
      List<TerminalAuthenticationInfo> taInfos = dg14.getTerminalAuthenticationInfos();
      if (taInfos == null || taInfos.isEmpty()) {
        System.out.println("Terminal Authentication not advertised in DG14.");
      } else {
        System.out.println("Terminal Authentication advertised entries:");
        for (TerminalAuthenticationInfo info : taInfos) {
          int fileId = info.getFileId();
          byte sfi = info.getShortFileId();
          System.out.printf("  TA OID=%s version=%d fileId=%04X (SFI=%02X)%n",
              info.getProtocolOIDString(),
              info.getVersion(),
              fileId,
              sfi & 0xFF);
        }
      }
    }

    if (cvcBundles == null || cvcBundles.isEmpty()) {
      System.out.println("No terminal authentication CVCs supplied.");
      return;
    }

    System.out.printf("Terminal Authentication CVCs processed: %d%n", cvcBundles.size());
    for (CvcBundle bundle : cvcBundles) {
      if (bundle.certificate == null) {
        System.out.printf("  %s → parse failed: %s%n",
            bundle.path,
            bundle.error != null ? bundle.error.getMessage() : "unknown error");
        continue;
      }
      describeCvc(bundle);
    }
  }

  private static void describeCvc(CvcBundle bundle) {
    try {
      CVCertificateBody body = bundle.certificate.getCertificateBody();
      HolderReferenceField holder = null;
      CAReferenceField authority = null;
      CVCAuthorizationTemplate authorizationTemplate = null;
      AuthorizationField authorizationField = null;
      Date validFrom = null;
      Date validTo = null;
      try {
        holder = body.getHolderReference();
      } catch (NoSuchFieldException ignore) {
      }
      try {
        authority = body.getAuthorityReference();
      } catch (NoSuchFieldException ignore) {
      }
      try {
        authorizationTemplate = body.getAuthorizationTemplate();
      } catch (NoSuchFieldException ignore) {
      }
      try {
        validFrom = body.getValidFrom();
      } catch (NoSuchFieldException ignore) {
      }
      try {
        validTo = body.getValidTo();
      } catch (NoSuchFieldException ignore) {
      }
      if (authorizationTemplate != null) {
        try {
          authorizationField = authorizationTemplate.getAuthorizationField();
        } catch (NoSuchFieldException ignore) {
        }
      }
      AuthorizationRoleEnum role = authorizationField != null ? authorizationField.getRole() : null;
      AccessRightEnum rights = authorizationField != null ? authorizationField.getAccessRight() : null;

      System.out.printf("  %s → holder=%s issuer=%s role=%s rights=%s valid=%s..%s%n",
          bundle.path,
          holder != null ? holder.getConcatenated() : "-",
          authority != null ? authority.getConcatenated() : "-",
          role != null ? role.name() : "-",
          rights != null ? rights.name() : "-",
          formatDate(validFrom),
          formatDate(validTo));
    } catch (Exception e) {
      System.out.printf("  %s → unable to summarise: %s%n", bundle.path, e.getMessage());
    }
  }

  private static String formatDate(Date date) {
    if (date == null) {
      return "-";
    }
    return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(date.toInstant().atOffset(ZoneOffset.UTC));
  }

  private static byte[] readEf(PassportService svc, short fid) {
    try (InputStream in = svc.getInputStream(fid)) {
      if (in == null) {
        return null;
      }
      return in.readAllBytes();
    } catch (Exception e) {
      return null;
    }
  }

  private static final class PaceOutcome {
    boolean attempted;
    boolean established;
    int availableOptions;
    PACEInfo selectedInfo;
    PACEResult result;
    Exception failure;
  }

  private static final class ChipAuthOutcome {
    boolean advertised;
    boolean established;
    ChipAuthenticationInfo selectedInfo;
    ChipAuthenticationPublicKeyInfo publicKeyInfo;
    EACCAResult result;
    Exception failure;
  }

  private static final class CvcBundle {
    final Path path;
    final CVCertificate certificate;
    final Exception error;

    private CvcBundle(Path path, CVCertificate certificate, Exception error) {
      this.path = path;
      this.certificate = certificate;
      this.error = error;
    }
  }

  private static boolean putData(CardChannel ch, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, 0xDA, p1, p2, data)); // ISO7816 PUT DATA
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    return r.getSW() == 0x9000;
  }

  private static ResponseAPDU apdu(CardChannel ch, int cla, int ins, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(cla, ins, p1, p2, data));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
    return r;
  }

  private static void createEF(CardChannel ch, short fid, int size, String label) throws Exception {
    byte[] fcp = new byte[]{
        (byte)0x63, 0x04,
        (byte)((size >> 8) & 0xFF), (byte)(size & 0xFF),
        (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)
    };
    apdu(ch, 0x00, 0xE0, 0x00, 0x00, fcp, label);
  }

  private static void selectEF(CardChannel ch, short fid, String label) throws Exception {
    byte[] cmd = new byte[]{0x00, (byte)0xA4, 0x02, 0x0C, 0x02, (byte)((fid >> 8) & 0xFF), (byte)(fid & 0xFF)};
    ResponseAPDU r = ch.transmit(new CommandAPDU(cmd));
    System.out.printf("%s → SW=%04X%n", label, r.getSW());
    if (r.getSW() != 0x9000) throw new RuntimeException(label + " failed SW=" + Integer.toHexString(r.getSW()));
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

  private static void printDG2Summary(PassportService svc, boolean largeScenario) {
    byte[] dg2Bytes;
    try (InputStream in = svc.getInputStream(PassportService.EF_DG2)) {
      if (in == null) {
        System.out.println("DG2 not present");
        return;
      }
      dg2Bytes = in.readAllBytes();
    } catch (Exception e) {
      System.out.println("DG2 read error: " + e.getMessage());
      return;
    }

    final int warningThreshold = 120_000;
    if (dg2Bytes.length > warningThreshold) {
      System.out.printf("DG2 size %d bytes exceeds safe threshold (%d). Skipping detailed parse.%n",
          dg2Bytes.length, warningThreshold);
      return;
    }

    try (ByteArrayInputStream in = new ByteArrayInputStream(dg2Bytes)) {
      DG2File dg2 = new DG2File(in);
      List<FaceInfo> faceInfos = dg2.getFaceInfos();
      int faceCount = 0;
      System.out.println("---- DG2 Metadata ----");
      for (int i = 0; i < faceInfos.size(); i++) {
        FaceInfo faceInfo = faceInfos.get(i);
        List<FaceImageInfo> images = faceInfo.getFaceImageInfos();
        for (int j = 0; j < images.size(); j++) {
          faceCount++;
          FaceImageInfo img = images.get(j);
          System.out.printf("Face %d.%d: %dx%d px, %s, %d bytes, quality=%d, type=%s%n",
              i + 1, j + 1,
              img.getWidth(), img.getHeight(),
              img.getMimeType(), img.getImageLength(),
              img.getQuality(), describeImageType(img.getImageDataType()));
        }
      }
      System.out.printf("Total faces: %d%n", faceCount);
      if (faceCount == 0) {
        System.out.println("DG2 contains no face images.");
      }
      if (largeScenario) {
        System.out.println("(DG2 generated in large-image scenario)");
      }
      System.out.println("----------------------");
    } catch (IOException | RuntimeException e) {
      System.out.println("DG2 parse error: " + e.getMessage());
    }
  }

  private static String describeImageType(int imageDataType) {
    if (imageDataType == FaceImageInfo.IMAGE_DATA_TYPE_JPEG) {
      return "JPEG";
    }
    if (imageDataType == FaceImageInfo.IMAGE_DATA_TYPE_JPEG2000) {
      return "JPEG2000";
    }
    return "type=" + imageDataType;
  }

  private static byte[] buildMrzSeed(String doc, String dob, String doe) {
    byte[] docBytes = doc.getBytes(StandardCharsets.US_ASCII);
    byte[] dobBytes = dob.getBytes(StandardCharsets.US_ASCII);
    byte[] doeBytes = doe.getBytes(StandardCharsets.US_ASCII);

    ByteArrayOutputStream inner = new ByteArrayOutputStream();
    writeTag(inner, 0x5F1F); // Document number
    writeLength(inner, docBytes.length);
    inner.write(docBytes, 0, docBytes.length);

    writeTag(inner, 0x5F18); // Date of birth
    writeLength(inner, dobBytes.length);
    inner.write(dobBytes, 0, dobBytes.length);

    writeTag(inner, 0x5F19); // Date of expiry
    writeLength(inner, doeBytes.length);
    inner.write(doeBytes, 0, doeBytes.length);

    byte[] innerBytes = inner.toByteArray();
    ByteArrayOutputStream outer = new ByteArrayOutputStream();
    outer.write(0x62); // MRZ_TAG
    writeLength(outer, innerBytes.length);
    outer.write(innerBytes, 0, innerBytes.length);

    return outer.toByteArray();
  }

  private static void writeTag(ByteArrayOutputStream out, int tag) {
    if (tag > 0xFF) {
      out.write((tag >> 8) & 0xFF);
    }
    out.write(tag & 0xFF);
  }

  private static void writeLength(ByteArrayOutputStream out, int length) {
    if (length < 0x80) {
      out.write(length);
    } else {
      // simple long-form length support (not expected here but keeps it correct)
      int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
      out.write(0x80 | numBytes);
      for (int i = numBytes - 1; i >= 0; i--) {
        out.write((length >> (8 * i)) & 0xFF);
      }
    }
  }
}
