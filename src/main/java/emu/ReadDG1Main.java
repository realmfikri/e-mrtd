package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;

import javax.crypto.Cipher;
import javax.smartcardio.*;

import net.sf.scuba.data.Gender;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.ISO7816;
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
import org.jmrtd.cert.CardVerifiableCertificate;
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
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.EACTAResult;
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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
import java.util.Base64;

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
  private static final String DEFAULT_DOC = "123456789";
  private static final String DEFAULT_DOB = "750101";
  private static final String DEFAULT_DOE = "250101";

  private static final byte KEY_REF_CAN = 0x02;
  private static final byte KEY_REF_PIN = 0x03;
  private static final byte KEY_REF_PUK = 0x04;

  private static final int AA_CHALLENGE_LENGTH = 8;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public static void main(String[] args) throws Exception {
    boolean seed = false;
    boolean corruptDG2 = false;
    boolean largeDG2 = false;
    boolean attemptPace = false;
    boolean paceCam = false;
    Path trustStorePath = null;
    String trustStorePassword = null;
    boolean requirePA = false;
    boolean requireAA = false;
    List<Path> taCvcPaths = new ArrayList<>();
    Path taKeyPath = null;
    String doc = DEFAULT_DOC;
    String dob = DEFAULT_DOB;
    String doe = DEFAULT_DOE;
    String can = null;
    String pin = null;
    String puk = null;

    List<String> argList = Arrays.asList(args);
    for (int i = 0; i < argList.size(); i++) {
      String arg = argList.get(i);
      if ("--seed".equals(arg)) {
        seed = true;
      } else if ("--attempt-pace".equals(arg)) {
        attemptPace = true;
      } else if ("--pace-cam".equals(arg)) {
        paceCam = true;
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
      } else if ("--require-aa".equals(arg)) {
        requireAA = true;
      } else if ("--corrupt-dg2".equals(arg)) {
        corruptDG2 = true;
      } else if ("--large-dg2".equals(arg)) {
        largeDG2 = true;
      } else if (arg.startsWith("--doc=")) {
        doc = arg.substring("--doc=".length());
      } else if ("--doc".equals(arg)) {
        i = advanceWithValue(argList, i, "--doc");
        doc = argList.get(i);
      } else if (arg.startsWith("--dob=")) {
        dob = arg.substring("--dob=".length());
      } else if ("--dob".equals(arg)) {
        i = advanceWithValue(argList, i, "--dob");
        dob = argList.get(i);
      } else if (arg.startsWith("--doe=")) {
        doe = arg.substring("--doe=".length());
      } else if ("--doe".equals(arg)) {
        i = advanceWithValue(argList, i, "--doe");
        doe = argList.get(i);
      } else if (arg.startsWith("--can=")) {
        can = normalizeSecret(arg.substring("--can=".length()));
      } else if ("--can".equals(arg)) {
        i = advanceWithValue(argList, i, "--can");
        can = normalizeSecret(argList.get(i));
      } else if (arg.startsWith("--pin=")) {
        pin = normalizeSecret(arg.substring("--pin=".length()));
      } else if ("--pin".equals(arg)) {
        i = advanceWithValue(argList, i, "--pin");
        pin = normalizeSecret(argList.get(i));
      } else if (arg.startsWith("--puk=")) {
        puk = normalizeSecret(arg.substring("--puk=".length()));
      } else if ("--puk".equals(arg)) {
        i = advanceWithValue(argList, i, "--puk");
        puk = normalizeSecret(argList.get(i));
      } else if (arg.startsWith("--ta-cvc=")) {
        taCvcPaths.add(Paths.get(arg.substring("--ta-cvc=".length())));
      } else if ("--ta-cvc".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-cvc");
        taCvcPaths.add(Paths.get(argList.get(i)));
      } else if (arg.startsWith("--ta-key=")) {
        taKeyPath = Paths.get(arg.substring("--ta-key=".length()));
      } else if ("--ta-key".equals(arg)) {
        i = advanceWithValue(argList, i, "--ta-key");
        taKeyPath = Paths.get(argList.get(i));
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
    SODArtifacts personalizationArtifacts = personalize(ch, corruptDG2, largeDG2, doc, dob, doe);

    // --- langkah penting: tanam kunci BAC di applet ---
    if (seed) {
      byte[] mrzSeed = buildMrzSeed(doc, dob, doe);
      int sw = putData(ch, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
      if (sw != 0x9000) {
        throw new RuntimeException(String.format(
            "SET BAC via PUT DATA gagal (SW=%04X). Cek format TLV.", sw));
      }
      byte[] paceSecretsTlv = buildPaceSecretsTlv(can, pin, puk);
      if (paceSecretsTlv != null) {
        sw = putData(ch, 0x00, 0x65, paceSecretsTlv, "PUT PACE secrets TLV");
        if (sw != 0x9000) {
          throw new RuntimeException(String.format(
              "SET PACE secrets via PUT DATA gagal (SW=%04X). Cek format TLV (tag 0x66 entries berisi [keyRef||secret]).",
              sw));
        }
      }
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

    CardService baseService = new TerminalCardService(term);
    CardService loggingService = new LoggingCardService(baseService);
    PassportService svc = new PassportService(
        loggingService,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false, false);
    svc.open();
    svc.sendSelectApplet(false);

    BACKey bacKey = new BACKey(doc, dob, doe);

    PaceKeySelection paceKeySelection = buildPaceKeySelection(can, pin, puk, bacKey);
    PaceOutcome paceOutcome = attemptPACE(svc, attemptPace, paceKeySelection, paceInfos);
    if (paceOutcome.attempted) {
      logPaceOutcome(paceOutcome);
    } else {
      System.out.println("PACE not attempted (--attempt-pace not specified).");
    }

    if (!paceOutcome.established) {
      System.out.println("Falling back to BAC secure messaging.");
      svc.doBAC(bacKey);
    }

    System.out.printf(
        "paceAttempted=%s, paceEstablished=%s, paceCamRequested=%s%n",
        paceOutcome.attempted,
        paceOutcome.established,
        paceCam);
    byte[] cardAccessPostAuth = readEf(svc, PassportService.EF_CARD_ACCESS);
    if (cardAccessPostAuth != null && (rawCardAccess == null || rawCardAccess.length == 0)) {
      System.out.printf("EF.CardAccess (post-auth) length=%d bytes%n", cardAccessPostAuth.length);
      rawCardAccess = cardAccessPostAuth;
    }

    DG14File dg14 = readDG14(svc);
    ChipAuthOutcome chipAuthOutcome = performChipAuthenticationIfSupported(svc, dg14);
    if (paceCam) {
      if (!paceOutcome.established) {
        if (!paceOutcome.attempted) {
          throw new RuntimeException("--pace-cam requires --attempt-pace and a successful PACE session");
        }
        throw new RuntimeException("--pace-cam requires a successful PACE session");
      }
      if (dg14 == null) {
        throw new RuntimeException("--pace-cam requires DG14 to advertise Chip Authentication");
      }
      if (!chipAuthOutcome.established) {
        String message = "Chip Authentication did not establish secure messaging while --pace-cam was set";
        if (chipAuthOutcome.failure != null && chipAuthOutcome.failure.getMessage() != null) {
          message += ": " + chipAuthOutcome.failure.getMessage();
        }
        throw new RuntimeException(message);
      }
    }
    System.out.printf("caEstablished=%s%n", chipAuthOutcome.established);

    DG15File dg15 = readDG15(svc);
    ActiveAuthOutcome activeAuthOutcome = performActiveAuthentication(loggingService, svc, dg15, requireAA);
    System.out.printf("aaAvailable=%s, aaVerified=%s%n", activeAuthOutcome.available, activeAuthOutcome.verified);
    if (requireAA && !activeAuthOutcome.verified) {
      throw new RuntimeException("Active Authentication failed but was required");
    }

    List<CvcBundle> taCertificates = loadCvcCertificates(taCvcPaths);
    reportTerminalAuthentication(dg14, taCertificates);
    TerminalAuthOutcome terminalAuthOutcome = performTerminalAuthentication(
        svc,
        paceOutcome,
        chipAuthOutcome,
        taCertificates,
        taKeyPath,
        doc);
    System.out.printf(
        "taCertificatesSupplied=%d, taAttempted=%s, taSucceeded=%s, dg3Readable=%s, dg4Readable=%s%n",
        terminalAuthOutcome.suppliedCertificates,
        terminalAuthOutcome.attempted,
        terminalAuthOutcome.succeeded,
        terminalAuthOutcome.dg3Readable,
        terminalAuthOutcome.dg4Readable);
    if (terminalAuthOutcome.failure != null) {
      System.out.println("Terminal Authentication failure: " + terminalAuthOutcome.failure.getMessage());
    }

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

  private static SODArtifacts personalize(
      CardChannel ch,
      boolean corruptDG2,
      boolean largeDG2,
      String doc,
      String dob,
      String doe) throws Exception {
    int[] tagList = new int[]{LDSFile.EF_DG1_TAG, LDSFile.EF_DG2_TAG, LDSFile.EF_DG14_TAG, LDSFile.EF_DG15_TAG};
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();

    MRZInfo mrz = new MRZInfo("P<", "UTO", "BEAN", "HAPPY",
        doc, "UTO", dob, Gender.MALE, doe, "");
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

    if (artifacts.docSignerKeyPair != null && artifacts.docSignerKeyPair.getPrivate() != null) {
      seedActiveAuthenticationKey(ch, artifacts.docSignerKeyPair.getPrivate());
    }

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

  private static void seedActiveAuthenticationKey(CardChannel ch, PrivateKey privateKey) throws Exception {
    if (!(privateKey instanceof RSAPrivateKey)) {
      System.out.println("Skipping AA key seed: private key is not RSA.");
      return;
    }
    RSAPrivateKey rsaKey = (RSAPrivateKey) privateKey;
    byte[] modulus = stripLeadingZero(rsaKey.getModulus().toByteArray());
    byte[] exponent = stripLeadingZero(rsaKey.getPrivateExponent().toByteArray());

    byte[] modulusTlv = buildRsaPrivateKeyTlv(0x60, modulus);
    int sw = putData(ch, 0x00, 0x60, modulusTlv, "PUT AA modulus TLV");
    if (sw != 0x9000) {
      throw new RuntimeException(String.format("Failed to seed AA modulus (SW=%04X)", sw));
    }

    byte[] exponentTlv = buildRsaPrivateKeyTlv(0x61, exponent);
    sw = putData(ch, 0x00, 0x61, exponentTlv, "PUT AA exponent TLV");
    if (sw != 0x9000) {
      throw new RuntimeException(String.format("Failed to seed AA exponent (SW=%04X)", sw));
    }
  }

  private static byte[] buildRsaPrivateKeyTlv(int containerTag, byte[] keyBytes) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTag(out, containerTag);
    // The applet expects the outer container length to be zero and treats the nested
    // OCTET STRING as a sibling TLV (legacy PUT DATA layout).
    writeLength(out, 0);
    writeTag(out, 0x04);
    writeLength(out, keyBytes.length);
    out.write(keyBytes, 0, keyBytes.length);
    return out.toByteArray();
  }

  private static byte[] stripLeadingZero(byte[] input) {
    if (input.length <= 1 || input[0] != 0x00) {
      return input;
    }
    int index = 0;
    while (index < input.length - 1 && input[index] == 0x00) {
      index++;
    }
    return Arrays.copyOfRange(input, index, input.length);
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

  private static PaceKeySelection buildPaceKeySelection(String can, String pin, String puk, BACKey bacKey) {
    String sanitizedCan = normalizeSecret(can);
    if (hasText(sanitizedCan)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createCANKey(sanitizedCan), "CAN", null);
      } catch (Exception e) {
        return new PaceKeySelection(null, "CAN", e);
      }
    }
    String sanitizedPin = normalizeSecret(pin);
    if (hasText(sanitizedPin)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createPINKey(sanitizedPin), "PIN", null);
      } catch (Exception e) {
        return new PaceKeySelection(null, "PIN", e);
      }
    }
    String sanitizedPuk = normalizeSecret(puk);
    if (hasText(sanitizedPuk)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createPUKKey(sanitizedPuk), "PUK", null);
      } catch (Exception e) {
        return new PaceKeySelection(null, "PUK", e);
      }
    }
    try {
      return new PaceKeySelection(PACEKeySpec.createMRZKey(bacKey), "MRZ", null);
    } catch (Exception e) {
      return new PaceKeySelection(null, "MRZ", e);
    }
  }

  private static PaceOutcome attemptPACE(
      PassportService svc,
      boolean attemptPace,
      PaceKeySelection keySelection,
      List<PACEInfo> paceInfos) {
    PaceOutcome outcome = new PaceOutcome();
    outcome.attempted = attemptPace;
    outcome.keySelection = keySelection;
    if (!attemptPace) {
      return outcome;
    }
    if (paceInfos == null || paceInfos.isEmpty()) {
      return outcome;
    }
    outcome.availableOptions = paceInfos.size();
    outcome.selectedInfo = selectPreferredPACEInfo(paceInfos);
    if (keySelection == null) {
      outcome.failure = new IllegalStateException("PACE key not configured");
      return outcome;
    }
    if (keySelection.error != null) {
      outcome.failure = keySelection.error;
      return outcome;
    }
    if (keySelection.keySpec == null) {
      outcome.failure = new IllegalStateException("PACE key spec unavailable");
      return outcome;
    }
    try {
      AlgorithmParameterSpec parameterSpec = buildPaceParameterSpec(outcome.selectedInfo);
      String protocolOid = outcome.selectedInfo.getObjectIdentifier();
      PACEResult result = svc.doPACE(
          keySelection.keySpec,
          protocolOid,
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
    if (outcome.keySelection != null && outcome.keySelection.label != null) {
      System.out.printf("PACE key source: %s%n", outcome.keySelection.label);
    }
    if (outcome.keySelection != null && outcome.keySelection.error != null) {
      System.out.println("PACE key preparation failed: " + outcome.keySelection.error.getMessage());
    }
    if (outcome.selectedInfo != null) {
      BigInteger parameterId = outcome.selectedInfo.getParameterId();
      String displayOid = outcome.selectedInfo.getProtocolOIDString();
      String dottedOid = outcome.selectedInfo.getObjectIdentifier();
      System.out.printf("Selected PACE OID=%s version=%d paramId=%s keyLength=%d%n",
          displayOid != null ? displayOid : dottedOid,
          outcome.selectedInfo.getVersion(),
          parameterId != null ? parameterId.toString(16) : "default",
          resolvePaceKeyLength(outcome.selectedInfo));
      if (displayOid != null && dottedOid != null && !displayOid.equals(dottedOid)) {
        System.out.printf("  (OID dotted=%s)%n", dottedOid);
      }
    }
    if (outcome.result != null) {
      System.out.printf("PACE mapping=%s agreement=%s cipher=%s digest=%s keyLength=%d%n",
          outcome.result.getMappingType(),
          outcome.result.getAgreementAlg(),
          outcome.result.getCipherAlg(),
          outcome.result.getDigestAlg(),
          outcome.result.getKeyLength());
    }
    if (outcome.availableOptions == 0) {
      System.out.println("PACE info not present in EF.CardAccess.");
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

  private static DG15File readDG15(PassportService svc) {
    byte[] dg15Bytes = readEf(svc, PassportService.EF_DG15);
    if (dg15Bytes == null || dg15Bytes.length == 0) {
      System.out.println("DG15 not present or unreadable.");
      return null;
    }
    try (ByteArrayInputStream in = new ByteArrayInputStream(dg15Bytes)) {
      return new DG15File(in);
    } catch (IOException e) {
      System.out.println("DG15 parse failed: " + e.getMessage());
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
      String caDisplay = info.getProtocolOIDString();
      String caDotted = info.getObjectIdentifier();
      System.out.printf("  CA OID=%s version=%d keyId=%s keyLength=%d%n",
          caDisplay != null ? caDisplay : caDotted,
          info.getVersion(),
          keyId != null ? keyId.toString(16) : "n/a",
          resolveChipKeyLength(info));
      if (caDisplay != null && caDotted != null && !caDisplay.equals(caDotted)) {
        System.out.printf("    (OID dotted=%s)%n", caDotted);
      }
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
      String caOid = outcome.selectedInfo.getObjectIdentifier();
      String agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(caOid);
      String cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(caOid);
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

  private static ActiveAuthOutcome performActiveAuthentication(
      CardService rawService,
      PassportService svc,
      DG15File dg15,
      boolean requireAA) {
    ActiveAuthOutcome outcome = new ActiveAuthOutcome();
    if (dg15 == null) {
      System.out.println("Active Authentication skipped: DG15 not present.");
      return outcome;
    }
    outcome.available = true;
    outcome.publicKey = dg15.getPublicKey();
    if (outcome.publicKey == null) {
      System.out.println("Active Authentication skipped: DG15 does not contain a public key.");
      return outcome;
    }

    byte[] challenge = new byte[AA_CHALLENGE_LENGTH];
    SECURE_RANDOM.nextBytes(challenge);
    outcome.challenge = challenge.clone();
    int expectedResponseLength = expectedAaResponseLength(outcome.publicKey);
    try {
      String digestAlgorithm = resolveAADigestAlgorithm(outcome.publicKey);
      String signatureAlgorithm = resolveAASignatureAlgorithm(outcome.publicKey);
      AAResult result = svc.doAA(outcome.publicKey, digestAlgorithm, signatureAlgorithm, challenge);
      outcome.attempted = result != null;
      if (result != null) {
        outcome.response = result.getResponse();
        if (shouldRetryPlainActiveAuth(outcome.response, expectedResponseLength)) {
          System.out.println(
              "Active Authentication response missing under secure messaging, retrying without protection.");
          outcome.response = tryPlainInternalAuthenticate(rawService, challenge);
        }
        try {
          outcome.verified = verifyActiveAuthenticationSignature(outcome.publicKey, challenge, outcome.response);
        } catch (GeneralSecurityException e) {
          outcome.failure = e;
          System.out.println("Active Authentication verification error: " + e.getMessage());
        }
      }

      if (outcome.verified) {
        int keyLength = resolveKeyLength(outcome.publicKey);
        if (keyLength > 0) {
          System.out.printf("Active Authentication verified (%s %d-bit).%n",
              outcome.publicKey.getAlgorithm(), keyLength);
        } else {
          System.out.printf("Active Authentication verified (%s).%n",
              outcome.publicKey.getAlgorithm());
        }
      } else if (requireAA) {
        System.out.println("Active Authentication verification failed.");
      } else {
        System.out.println("Active Authentication attempt did not verify signature.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      System.out.println("Active Authentication failed: " + e.getMessage());
    } finally {
      Arrays.fill(challenge, (byte) 0x00);
    }
    return outcome;
  }

  private static byte[] tryPlainInternalAuthenticate(CardService rawService, byte[] challenge)
      throws CardServiceException {
    net.sf.scuba.smartcards.CommandAPDU command = new net.sf.scuba.smartcards.CommandAPDU(
        ISO7816.CLA_ISO7816,
        ISO7816.INS_INTERNAL_AUTHENTICATE,
        0x00,
        0x00,
        challenge,
        256);
    net.sf.scuba.smartcards.ResponseAPDU response = rawService.transmit(command);
    int sw = response.getSW();
    if (sw != ISO7816.SW_NO_ERROR) {
      throw new CardServiceException("INTERNAL AUTHENTICATE failed", (short) sw);
    }
    return response.getData();
  }

  private static boolean shouldRetryPlainActiveAuth(byte[] response, int expectedResponseLength) {
    if (response == null || response.length == 0) {
      return true;
    }
    return expectedResponseLength > 0 && response.length != expectedResponseLength;
  }

  private static int resolveKeyLength(PublicKey key) {
    if (key instanceof RSAPublicKey) {
      return ((RSAPublicKey) key).getModulus().bitLength();
    }
    return -1;
  }

  private static int expectedAaResponseLength(PublicKey key) {
    int keyBits = resolveKeyLength(key);
    return keyBits > 0 ? keyBits / Byte.SIZE : -1;
  }

  private static String resolveAADigestAlgorithm(PublicKey key) {
    if (key == null) {
      return null;
    }
    if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return "SHA-1";
    }
    return null;
  }

  private static String resolveAASignatureAlgorithm(PublicKey key) {
    if (key == null) {
      return null;
    }
    if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return "SHA1withRSA";
    }
    return key.getAlgorithm();
  }

  private static boolean verifyActiveAuthenticationSignature(
      PublicKey key, byte[] challenge, byte[] response) throws GeneralSecurityException {
    if (!(key instanceof RSAPublicKey)) {
      throw new GeneralSecurityException("Unsupported AA key algorithm: " + key.getAlgorithm());
    }
    if (response == null || response.length == 0) {
      return false;
    }

    Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] plain = cipher.doFinal(response);
    if (plain.length < 1 + 20 + 1) {
      return false;
    }

    if ((plain[0] & 0xFF) != 0x6A || (plain[plain.length - 1] & 0xFF) != 0xBC) {
      return false;
    }

    int digestLength = 20;
    int digestOffset = plain.length - 1 - digestLength;
    if (digestOffset <= 1) {
      return false;
    }
    int m1Offset = 1;
    int m1Length = digestOffset - m1Offset;

    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.update(plain, m1Offset, m1Length);
    sha1.update(challenge);
    byte[] expectedDigest = sha1.digest();
    byte[] actualDigest = Arrays.copyOfRange(plain, digestOffset, digestOffset + digestLength);
    return MessageDigest.isEqual(expectedDigest, actualDigest);
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
        CardVerifiableCertificate cardCertificate = new WrappedCardVerifiableCertificate(certificate);
        bundles.add(new CvcBundle(path, certificate, cardCertificate, null));
      } catch (IOException | ParseException | ConstructionException e) {
        bundles.add(new CvcBundle(path, null, null, e));
      }
    }
    return bundles;
  }

  private static TerminalAuthOutcome performTerminalAuthentication(
      PassportService svc,
      PaceOutcome paceOutcome,
      ChipAuthOutcome chipOutcome,
      List<CvcBundle> cvcBundles,
      Path taKeyPath,
      String documentNumber) {
    TerminalAuthOutcome outcome = new TerminalAuthOutcome();
    outcome.suppliedCertificates = cvcBundles != null ? cvcBundles.size() : 0;

    if (cvcBundles == null || cvcBundles.isEmpty()) {
      System.out.println("Terminal Authentication skipped: provide at least one --ta-cvc file.");
      return outcome;
    }
    if (chipOutcome == null || chipOutcome.result == null) {
      System.out.println("Terminal Authentication skipped: Chip Authentication was not established.");
      return outcome;
    }
    if (taKeyPath == null) {
      System.out.println("Terminal Authentication skipped: --ta-key not provided.");
      return outcome;
    }

    List<CardVerifiableCertificate> certificateChain = new ArrayList<>();
    for (CvcBundle bundle : cvcBundles) {
      if (bundle.error != null) {
        System.out.printf("  %s → cannot use certificate: %s%n",
            bundle.path,
            bundle.error.getMessage() != null ? bundle.error.getMessage() : "unknown error");
        outcome.failure = bundle.error;
        return outcome;
      }
      if (bundle.cardCertificate == null) {
        System.out.printf("  %s → parsed certificate but could not build CardVerifiableCertificate.%n", bundle.path);
        outcome.failure = new IllegalStateException("Unable to build CVC certificate wrapper");
        return outcome;
      }
      certificateChain.add(bundle.cardCertificate);
    }

    PrivateKey terminalKey;
    try {
      terminalKey = loadPrivateKey(taKeyPath);
    } catch (Exception e) {
      System.out.println("Terminal Authentication skipped: unable to load terminal private key (" + e.getMessage() + ").");
      outcome.failure = e;
      return outcome;
    }

    outcome.attempted = true;
    try {
      PACEResult paceResult = paceOutcome != null ? paceOutcome.result : null;
      EACTAResult taResult;
      if (paceResult != null) {
        taResult = svc.doEACTA(null, certificateChain, terminalKey, null, chipOutcome.result, paceResult);
      } else {
        taResult = svc.doEACTA(null, certificateChain, terminalKey, null, chipOutcome.result, documentNumber);
      }
      outcome.succeeded = taResult != null;
      if (outcome.succeeded) {
        System.out.println("Terminal Authentication handshake completed.");
      } else {
        System.out.println("Terminal Authentication did not return a success indicator.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      System.out.println("Terminal Authentication failed: " + e.getMessage());
    }

    outcome.dg3Readable = attemptDataGroupRead(svc, PassportService.EF_DG3, "DG3");
    outcome.dg4Readable = attemptDataGroupRead(svc, PassportService.EF_DG4, "DG4");
    return outcome;
  }

  private static PrivateKey loadPrivateKey(Path path) throws IOException, GeneralSecurityException {
    byte[] pemBytes = Files.readAllBytes(path);
    String pem = new String(pemBytes, StandardCharsets.UTF_8);
    String sanitized = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replaceAll("\\s", "");
    byte[] der;
    try {
      der = Base64.getMimeDecoder().decode(sanitized);
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("Invalid private key PEM", e);
    }
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    try {
      return KeyFactory.getInstance("RSA").generatePrivate(spec);
    } catch (InvalidKeySpecException ignore) {
      // fall through
    }
    try {
      return KeyFactory.getInstance("EC").generatePrivate(spec);
    } catch (InvalidKeySpecException ignore) {
      // fall through
    }
    throw new GeneralSecurityException("Unsupported private key algorithm (expected RSA or EC)");
  }

  private static boolean attemptDataGroupRead(PassportService svc, short fid, String label) {
    try (InputStream in = svc.getInputStream(fid)) {
      if (in == null) {
        System.out.printf("EF.%s not present or zero length.%n", label);
        return false;
      }
      int total = 0;
      byte[] buffer = new byte[256];
      int read;
      while ((read = in.read(buffer)) > 0) {
        total += read;
      }
      System.out.printf("EF.%s readable (%d bytes).%n", label, total);
      return total > 0;
    } catch (CardServiceException e) {
      String message = e.getMessage();
      if (message == null || message.isBlank()) {
        message = String.format("SW=%04X", e.getSW());
      }
      System.out.printf("EF.%s inaccessible: %s%n", label, message);
      return false;
    } catch (IOException e) {
      System.out.printf("EF.%s read error: %s%n", label, e.getMessage());
      return false;
    }
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
    PaceKeySelection keySelection;
    PACEInfo selectedInfo;
    PACEResult result;
    Exception failure;
  }

  private static final class PaceKeySelection {
    final PACEKeySpec keySpec;
    final String label;
    final Exception error;

    private PaceKeySelection(PACEKeySpec keySpec, String label, Exception error) {
      this.keySpec = keySpec;
      this.label = label;
      this.error = error;
    }
  }

  private static final class ChipAuthOutcome {
    boolean advertised;
    boolean established;
    ChipAuthenticationInfo selectedInfo;
    ChipAuthenticationPublicKeyInfo publicKeyInfo;
    EACCAResult result;
    Exception failure;
  }

  private static final class ActiveAuthOutcome {
    boolean available;
    boolean attempted;
    boolean verified;
    PublicKey publicKey;
    byte[] challenge;
    byte[] response;
    Exception failure;
  }

  private static final class CvcBundle {
    final Path path;
    final CVCertificate certificate;
    final CardVerifiableCertificate cardCertificate;
    final Exception error;

    private CvcBundle(
        Path path,
        CVCertificate certificate,
        CardVerifiableCertificate cardCertificate,
        Exception error) {
      this.path = path;
      this.certificate = certificate;
      this.cardCertificate = cardCertificate;
      this.error = error;
    }
  }

  private static final class TerminalAuthOutcome {
    int suppliedCertificates;
    boolean attempted;
    boolean succeeded;
    boolean dg3Readable;
    boolean dg4Readable;
    Exception failure;
  }

  private static final class WrappedCardVerifiableCertificate extends CardVerifiableCertificate {
    WrappedCardVerifiableCertificate(CVCertificate certificate) throws ConstructionException {
      super(certificate);
    }
  }

  private static int putData(CardChannel ch, int p1, int p2, byte[] data, String label) throws Exception {
    ResponseAPDU r = ch.transmit(new CommandAPDU(0x00, 0xDA, p1, p2, data)); // ISO7816 PUT DATA
    int sw = r.getSW();
    System.out.printf("%s → SW=%04X%n", label, sw);
    return sw;
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

  private static byte[] buildPaceSecretsTlv(String can, String pin, String puk) {
    ByteArrayOutputStream entries = new ByteArrayOutputStream();
    appendPaceSecretEntry(entries, KEY_REF_CAN, can);
    appendPaceSecretEntry(entries, KEY_REF_PIN, pin);
    appendPaceSecretEntry(entries, KEY_REF_PUK, puk);

    byte[] entryBytes = entries.toByteArray();
    if (entryBytes.length == 0) {
      return null;
    }

    // PassportApplet expects the APDU body to be a sequence of 0x66 entries
    // (with the key reference as the first byte of each value).  Do not wrap
    // them in an extra 0x65 TLV, because P2 already encodes that container.
    return entryBytes;
  }

  private static void appendPaceSecretEntry(ByteArrayOutputStream out, byte keyReference, String value) {
    String sanitized = normalizeSecret(value);
    if (!hasText(sanitized)) {
      return;
    }
    byte[] valueBytes = sanitized.getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream entry = new ByteArrayOutputStream();
    entry.write(keyReference);
    entry.write(valueBytes, 0, valueBytes.length);
    byte[] entryBytes = entry.toByteArray();
    writeTag(out, 0x66);
    writeLength(out, entryBytes.length);
    out.write(entryBytes, 0, entryBytes.length);
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

  private static String normalizeSecret(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private static boolean hasText(String value) {
    return normalizeSecret(value) != null;
  }
}
