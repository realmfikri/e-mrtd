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
import org.ejbca.cvc.CVCPublicKey;
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
import java.io.PrintStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.security.cert.CertificateEncodingException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import emu.PersonalizationSupport.SODArtifacts;
import emu.SimLogCategory;

public final class SimRunner {
  private static final byte[] MRTD_AID = new byte[]{(byte)0xA0,0x00,0x00,0x02,0x47,0x10,0x01};
  private static final short EF_COM = (short)0x011E;
  private static final short EF_DG1 = (short)0x0101;
  private static final short EF_DG2 = (short)0x0102;
  private static final short EF_DG3 = (short)0x0103;
  private static final short EF_DG4 = (short)0x0104;
  private static final short EF_DG14 = PassportService.EF_DG14;
  private static final short EF_DG15 = (short)0x010F;
  private static final short EF_SOD = (short)0x011D;
  private static final short EF_CARD_ACCESS = PassportService.EF_CARD_ACCESS;

  // >>> samakan MRZ ini dengan yang kamu tulis ke EF.DG1 saat "PersoMain"
  private static final String DEFAULT_DOC = "123456789";
  private static final String DEFAULT_DOB = "750101";
  private static final String DEFAULT_DOE = "250101";

  private static final int PUT_DATA_P2_CURRENT_DATE = 0x67;

  private static final int AA_CHALLENGE_LENGTH = 8;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final ThreadLocal<SimLogCategory> NEXT_STDOUT_CATEGORY = new ThreadLocal<>();

  public SessionReport run(SimConfig config, SimEvents events) throws Exception {
    Objects.requireNonNull(config, "config");
    SimEvents sink = events != null ? events : new SimEvents() {};

    boolean seed = config.seed;
    boolean corruptDG2 = config.corruptDg2;
    boolean largeDG2 = config.largeDg2;
    boolean attemptPace = config.attemptPace;
    String pacePreference = config.pacePreference;
    Path trustStorePath = config.trustStorePath;
    List<Path> trustMasterListPaths = new ArrayList<>(config.trustMasterListPaths);
    String trustStorePassword = config.trustStorePassword;
    boolean requirePA = config.requirePa;
    boolean requireAA = config.requireAa;
    List<Path> taCvcPaths = new ArrayList<>(config.taCvcPaths);
    Path taKeyPath = config.taKeyPath;
    Path jsonOutPath = config.reportOutput;
    Path eventsOutPath = config.eventsOutput;
    IssuerSimulator.Result issuerResult = config.issuerResult;
    PersonalizationJob issuerJob = issuerResult != null ? issuerResult.getJob() : null;
    List<String> issuerLifecycleTargets = issuerJob != null ? issuerJob.getLifecycleTargets() : List.of();
    boolean issuerSpecifiesLifecycle = issuerResult != null;
    boolean applyPersonalizedLifecycle = issuerSpecifiesLifecycle
        ? containsLifecycleTarget(issuerLifecycleTargets, "PERSONALIZED")
        : true;
    boolean applyLockedLifecycle = issuerSpecifiesLifecycle
        ? (!issuerResult.isLeavePersonalized()
            && containsLifecycleTarget(issuerLifecycleTargets, "LOCKED"))
        : true;
    String doc = hasText(config.docNumber) ? config.docNumber : DEFAULT_DOC;
    String dob = hasText(config.dateOfBirth) ? config.dateOfBirth : DEFAULT_DOB;
    String doe = hasText(config.dateOfExpiry) ? config.dateOfExpiry : DEFAULT_DOE;
    if (issuerJob != null && issuerJob.getMrzInfo() != null) {
      MRZInfo mrzInfo = issuerJob.getMrzInfo();
      doc = mrzInfo.getDocumentNumber();
      dob = mrzInfo.getDateOfBirth();
      doe = mrzInfo.getDateOfExpiry();
    }
    String can = config.can;
    String pin = config.pin;
    String puk = config.puk;
    Boolean openComSodReads = config.openComSodReads;
    LocalDate terminalAuthDate = config.terminalAuthDate != null
        ? config.terminalAuthDate
        : LocalDate.now(ZoneOffset.UTC);

    PrintStream originalOut = System.out;
    SimOutputRouter router = new SimOutputRouter(sink, originalOut);
    PrintStream eventStream = new PrintStream(router, true, StandardCharsets.UTF_8);
    System.setOut(eventStream);
    try {
      sink.onPhase(SimPhase.CONNECTING, "Bootstrapping virtual passport");

    // Boot emulator & install applet
    SessionReport report = new SessionReport();
    boolean createdSimulator = config.cardSimulator == null;
    CardSimulator sim = createdSimulator ? new CardSimulator() : config.cardSimulator;
    AID aid = new AID(MRTD_AID, (short)0, (byte)MRTD_AID.length);
    if (createdSimulator) {
      sim.installApplet(aid, sos.passportapplet.PassportApplet.class);
    }

    CardTerminal term;
    if (!createdSimulator && issuerResult != null && issuerResult.getTerminal() != null
        && config.cardSimulator == issuerResult.getSimulator()) {
      term = issuerResult.getTerminal();
    } else {
      term = CardTerminalSimulator.terminal(sim);
    }
    Card card = term.connect("*");
    CardChannel ch = card.getBasicChannel();
    report.session.transport = resolveTransport(term, card);

    // SELECT AID
    apdu(ch, 0x00, 0xA4, 0x04, 0x0C, MRTD_AID, "SELECT AID");

    // --- tulis data minimal (COM + DG1 + DG2) ke chip ---
    SODArtifacts personalizationArtifacts;
    boolean createdFromIssuerArtifacts = issuerResult != null && createdSimulator;
    if (createdFromIssuerArtifacts) {
      personalizationArtifacts = issuerResult.getArtifacts();
      hydrateFromArtifacts(ch, personalizationArtifacts);
    } else if (createdSimulator) {
      personalizationArtifacts = personalize(ch, corruptDG2, largeDG2, doc, dob, doe);
    } else if (issuerResult != null) {
      personalizationArtifacts = issuerResult.getArtifacts();
    } else {
      personalizationArtifacts = null;
    }

    // --- langkah penting: tanam kunci BAC di applet ---
    boolean reuseIssuerCard = issuerResult != null && !createdSimulator
        && config.cardSimulator == issuerResult.getSimulator();
    boolean mrzSeedRequested = (seed && !reuseIssuerCard)
        || (issuerResult != null && createdSimulator && issuerResult.isMrzSeeded());
    boolean paceSeedRequested = (seed && !reuseIssuerCard)
        || (issuerResult != null && createdSimulator
            && (issuerResult.isPaceCanInstalled()
                || issuerResult.isPacePinInstalled()
                || issuerResult.isPacePukInstalled()));

    if (mrzSeedRequested) {
      byte[] mrzSeed = IssuerSecretEncoder.encodeMrzSeed(doc, dob, doe);
      int sw = putData(ch, 0x00, 0x62, mrzSeed, "PUT MRZ TLV");
      if (sw != 0x9000) {
        throw new RuntimeException(String.format(
            "SET BAC via PUT DATA gagal (SW=%04X). Cek format TLV.", sw));
      }
    }
    if (paceSeedRequested) {
      byte[] paceSecretsTlv = IssuerSecretEncoder.encodePaceSecrets(can, pin, puk);
      if (paceSecretsTlv != null) {
        int sw = putData(ch, 0x00, 0x65, paceSecretsTlv, "PUT PACE secrets TLV");
        if (sw != 0x9000) {
          throw new RuntimeException(String.format(
              "SET PACE secrets via PUT DATA gagal (SW=%04X). Cek format TLV (tag 0x66 entries berisi [keyRef||secret]).",
              sw));
        }
      }
    }

    if (openComSodReads != null) {
      byte[] toggle = new byte[]{(byte) (openComSodReads ? 0x01 : 0x00)};
      int openSw = putData(ch, 0xDE, 0xFE, toggle,
          openComSodReads ? "ENABLE open COM/SOD reads" : "DISABLE open COM/SOD reads");
      if (openSw != 0x9000) {
        throw new RuntimeException(String.format("Gagal mengatur kebijakan COM/SOD (SW=%04X).", openSw));
      }
    }

    boolean shouldProgramLifecycle = createdSimulator || (seed && !reuseIssuerCard);
    if (shouldProgramLifecycle) {
      byte[] currentDateTlv = encodeCurrentDate(terminalAuthDate);
      int dateSw = putData(ch, 0x00, PUT_DATA_P2_CURRENT_DATE, currentDateTlv, "PUT current date digits");
      if (dateSw != 0x9000) {
        throw new RuntimeException(String.format("Gagal menetapkan tanggal saat ini untuk TA (SW=%04X).", dateSw));
      }

      if (applyPersonalizedLifecycle || createdSimulator) {
        int lifecycleSw = putData(ch, 0xDE, 0xAF, new byte[0], "SET LIFECYCLE → PERSONALIZED");
        if (lifecycleSw != 0x9000) {
          throw new RuntimeException(String.format(
              "Gagal mengatur state PERSONALIZED (SW=%04X).", lifecycleSw));
        }
      }
      if ((applyLockedLifecycle || createdSimulator)
          && !(issuerResult != null && issuerResult.isLeavePersonalized())) {
        int lifecycleSw = putData(ch, 0xDE, 0xAD, new byte[0], "SET LIFECYCLE → LOCKED");
        if (lifecycleSw != 0x9000) {
          throw new RuntimeException(String.format(
              "Gagal mengunci chip (SW=%04X).", lifecycleSw));
        }
      }
    }

    // --- sekarang baca via PassportService + BAC ---
    byte[] rawCardAccess = readEfPlain(ch, EF_CARD_ACCESS);
    if ((rawCardAccess == null || rawCardAccess.length == 0) && personalizationArtifacts != null) {
      rawCardAccess = personalizationArtifacts.getCardAccessBytes();
    }
    if (rawCardAccess != null) {
      System.out.printf("EF.CardAccess length=%d bytes%n", rawCardAccess.length);
    }
    List<PACEInfo> paceInfos = parsePaceInfos(rawCardAccess);

    CardService baseService = new TerminalCardService(term);
    CardService loggingService = new LoggingCardService(baseService, sink);
    PassportService svc = new PassportService(
        loggingService,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false, false);
    svc.open();
    svc.sendSelectApplet(false);
    sink.onPhase(SimPhase.AUTHENTICATING, "Establishing secure messaging");

    BACKey bacKey = new BACKey(doc, dob, doe);

    PaceKeySelection paceKeySelection = buildPaceKeySelection(can, pin, puk, bacKey);
    PaceOutcome paceOutcome = attemptPACE(
        svc,
        attemptPace,
        paceKeySelection,
        paceInfos,
        pacePreference,
        sink);
    report.session.paceAttempted = paceOutcome.attempted;
    report.session.paceEstablished = paceOutcome.established;
    if (paceOutcome.attempted) {
      logPaceOutcome(paceOutcome);
    } else {
      securityPrintln("PACE not attempted (--attempt-pace not specified).");
    }

    if (!paceOutcome.established) {
      securityPrintln("Falling back to BAC secure messaging.");
      svc.doBAC(bacKey);
      logSecureMessagingTransition("BAC fallback", "BAC", "3DES");
    }

    System.out.printf("paceAttempted=%s, paceEstablished=%s%n", paceOutcome.attempted, paceOutcome.established);
    byte[] cardAccessPostAuth = readEf(svc, PassportService.EF_CARD_ACCESS);
    if (cardAccessPostAuth != null && (rawCardAccess == null || rawCardAccess.length == 0)) {
      System.out.printf("EF.CardAccess (post-auth) length=%d bytes%n", cardAccessPostAuth.length);
      rawCardAccess = cardAccessPostAuth;
    }

    DG14File dg14 = readDG14(svc);
    if (dg14 != null) {
      report.dataGroups.addPresent(14);
    }
    ChipAuthOutcome chipAuthOutcome = performChipAuthenticationIfSupported(svc, dg14);
    report.session.caEstablished = chipAuthOutcome.established;
    System.out.printf("caEstablished=%s%n", chipAuthOutcome.established);

    DG15File dg15 = readDG15(svc);
    if (dg15 != null) {
      report.dataGroups.addPresent(15);
    }
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
        doc,
        terminalAuthDate);
    System.out.printf(
        "taCertificatesSupplied=%d, taAttempted=%s, taSucceeded=%s, dg3Readable=%s, dg4Readable=%s%n",
        terminalAuthOutcome.suppliedCertificates,
        terminalAuthOutcome.attempted,
        terminalAuthOutcome.succeeded,
        terminalAuthOutcome.dg3Readable,
        terminalAuthOutcome.dg4Readable);
    if (terminalAuthOutcome.failure != null) {
      securityPrintln("Terminal Authentication failure: " + terminalAuthOutcome.failure.getMessage());
    }
    if (terminalAuthOutcome.terminalRights != null) {
      securityPrintln(String.format("taRights=%s (DG3 allowed=%s, DG4 allowed=%s)",
          terminalAuthOutcome.terminalRights.name(),
          terminalAuthOutcome.dg3AllowedByRights,
          terminalAuthOutcome.dg4AllowedByRights));
    }
    report.setTerminalAuthentication(terminalAuthOutcome.report);
    report.dataGroups.setDg3Readable(terminalAuthOutcome.dg3Readable);
    report.dataGroups.setDg4Readable(terminalAuthOutcome.dg4Readable);

    // baca DG1 (MRZ)
    sink.onPhase(SimPhase.READING, "Reading logical data structure");
    boolean dg1Read = false;
    try (InputStream in = svc.getInputStream(PassportService.EF_DG1)) {
      if (in != null) {
        DG1File dg1 = new DG1File(in);
        MRZInfo info = dg1.getMRZInfo();
        System.out.println("==== DG1 ====");
        System.out.println("Doc#: " + info.getDocumentNumber());
        System.out.println("DOB  : " + info.getDateOfBirth());
        System.out.println("DOE  : " + info.getDateOfExpiry());
        System.out.println("Name : " + info.getSecondaryIdentifier() + ", " + info.getPrimaryIdentifier());
        System.out.println("Gender: " + info.getGender()); // jmrtd 0.8.x
        report.dataGroups.addPresent(1);
        report.dataGroups.setDg1Mrz(new SessionReport.MrzSummary(
            info.getDocumentNumber(),
            info.getDateOfBirth(),
            info.getDateOfExpiry(),
            info.getPrimaryIdentifier(),
            info.getSecondaryIdentifier(),
            info.getIssuingState(),
            info.getNationality()));
        dg1Read = true;
      }
    } catch (Exception readFailure) {
      System.out.println("DG1 read error: " + readFailure.getMessage());
    }
    if (!dg1Read && personalizationArtifacts != null) {
      byte[] dg1Bytes = personalizationArtifacts.getDataGroupBytes(1);
      if (dg1Bytes != null && dg1Bytes.length > 0) {
        try (ByteArrayInputStream fallback = new ByteArrayInputStream(dg1Bytes)) {
          DG1File dg1 = new DG1File(fallback);
          MRZInfo info = dg1.getMRZInfo();
          System.out.println("==== DG1 (artifact fallback) ====");
          System.out.println("Doc#: " + info.getDocumentNumber());
          System.out.println("DOB  : " + info.getDateOfBirth());
          System.out.println("DOE  : " + info.getDateOfExpiry());
          System.out.println("Name : " + info.getSecondaryIdentifier() + ", " + info.getPrimaryIdentifier());
          System.out.println("Gender: " + info.getGender());
          report.dataGroups.addPresent(1);
          report.dataGroups.setDg1Mrz(new SessionReport.MrzSummary(
              info.getDocumentNumber(),
              info.getDateOfBirth(),
              info.getDateOfExpiry(),
              info.getPrimaryIdentifier(),
              info.getSecondaryIdentifier(),
              info.getIssuingState(),
              info.getNationality()));
          dg1Read = true;
        } catch (IOException fallbackError) {
          System.out.println("DG1 artifact fallback failed: " + fallbackError.getMessage());
        }
      }
    }
    if (!dg1Read) {
      throw new RuntimeException("Failed to read DG1 from card or issuer artifacts");
    }

    sink.onPhase(SimPhase.VERIFYING, "Validating Passive/Active/Terminal auth");
    List<Path> trustSources = new ArrayList<>();
    if (trustStorePath != null) {
      trustSources.add(trustStorePath);
    }
    if (trustMasterListPaths != null) {
      trustSources.addAll(trustMasterListPaths);
    }
    if (trustSources.isEmpty()) {
      Path defaultTrust = Paths.get("target", "trust-store");
      if (Files.isDirectory(defaultTrust)) {
        trustSources.add(defaultTrust);
      }
    }

    boolean runPA = !trustSources.isEmpty() || requirePA;
    if (runPA) {
      char[] passwordChars = trustStorePassword != null ? trustStorePassword.toCharArray() : null;
      PassiveAuthentication.Result paResult = PassiveAuthentication.verify(svc, trustSources, passwordChars);
      paResult.printReport();
      report.setPassiveAuthentication(paResult);
      if (requirePA && !paResult.isPass()) {
        throw new RuntimeException("Passive Authentication failed but was required");
      }
      if (passwordChars != null) {
        Arrays.fill(passwordChars, '\0');
      }
    } else {
      report.setPassiveAuthentication(null);
    }

    SessionReport.Dg2Metadata dg2Metadata = summarizeDG2(svc, largeDG2, config, sink, personalizationArtifacts);
    if (dg2Metadata != null) {
      report.dataGroups.addPresent(2);
      report.dataGroups.setDg2Metadata(dg2Metadata);
    }
    report.setActiveAuthentication(activeAuthOutcome, requireAA);
    String sessionSecureMessagingMode = resolveSecureMessagingMode(paceOutcome, chipAuthOutcome);
    report.session.smMode = sessionSecureMessagingMode;
    System.out.printf("Secure messaging final mode: %s%n", sessionSecureMessagingMode);

    report.session.completedAt = Instant.now();
    sink.onPhase(SimPhase.COMPLETE, "Scenario complete");

    if (jsonOutPath != null) {
      try {
        report.write(jsonOutPath);
        System.out.println("JSON report written to " + jsonOutPath.toAbsolutePath());
      } catch (IOException e) {
        System.out.println("Failed to write JSON report: " + e.getMessage());
      }
    }
    return report;
    } catch (Exception e) {
      sink.onPhase(SimPhase.FAILED, e.getMessage());
      throw e;
    } finally {
      router.finish();
      eventStream.flush();
      System.setOut(originalOut);
    }
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
    MRZInfo mrz = new MRZInfo("P<", "UTO", "BEAN", "HAPPY",
        doc, "UTO", dob, Gender.MALE, doe, "");
    int faceWidth = largeDG2 ? 720 : 480;
    int faceHeight = largeDG2 ? 960 : 600;
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .withFaceSyntheticSize(faceWidth, faceHeight)
        .corruptDg2(corruptDG2)
        .build();

    int[] tagList = job.getComTagList().stream().mapToInt(Integer::intValue).toArray();
    COMFile com = new COMFile("1.7", "4.0.0", tagList);
    byte[] comBytes = com.getEncoded();
    byte[] dg1Bytes = job.getDg1Bytes();

    createEF(ch, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEF(ch, EF_COM, "SELECT EF.COM before WRITE");
    writeBinary(ch, comBytes, "WRITE EF.COM");

    createEF(ch, EF_DG1, dg1Bytes.length, "CREATE EF.DG1");
    selectEF(ch, EF_DG1, "SELECT EF.DG1 before WRITE");
    writeBinary(ch, dg1Bytes, "WRITE EF.DG1");

    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(job);
    System.out.printf("Synthetic biometrics → DG3=%d bytes, DG4=%d bytes.%n",
        artifacts.getDg3Bytes() != null ? artifacts.getDg3Bytes().length : 0,
        artifacts.getDg4Bytes() != null ? artifacts.getDg4Bytes().length : 0);

    byte[] cardAccessBytes = artifacts.getCardAccessBytes();
    if (cardAccessBytes != null && cardAccessBytes.length > 0) {
      createEF(ch, EF_CARD_ACCESS, cardAccessBytes.length, "CREATE EF.CardAccess");
      selectEF(ch, EF_CARD_ACCESS, "SELECT EF.CardAccess before WRITE");
      writeBinary(ch, cardAccessBytes, "WRITE EF.CardAccess");
    }

    byte[] dg15Bytes = artifacts.getDg15Bytes();
    createEF(ch, EF_DG15, dg15Bytes.length, "CREATE EF.DG15");
    selectEF(ch, EF_DG15, "SELECT EF.DG15 before WRITE");
    writeBinary(ch, dg15Bytes, "WRITE EF.DG15");

    byte[] dg14Bytes = artifacts.getDg14Bytes();
    if (dg14Bytes != null && dg14Bytes.length > 0) {
      createEF(ch, EF_DG14, dg14Bytes.length, "CREATE EF.DG14");
      selectEF(ch, EF_DG14, "SELECT EF.DG14 before WRITE");
      writeBinary(ch, dg14Bytes, "WRITE EF.DG14");
    }

    byte[] dg2Bytes = artifacts.getDg2Bytes();
    createEF(ch, EF_DG2, dg2Bytes.length, "CREATE EF.DG2");
    selectEF(ch, EF_DG2, "SELECT EF.DG2 before WRITE");
    writeBinary(ch, dg2Bytes, "WRITE EF.DG2");

    byte[] dg3Bytes = artifacts.getDg3Bytes();
    if (dg3Bytes != null && dg3Bytes.length > 0) {
      createEF(ch, EF_DG3, dg3Bytes.length, "CREATE EF.DG3");
      selectEF(ch, EF_DG3, "SELECT EF.DG3 before WRITE");
      writeBinary(ch, dg3Bytes, "WRITE EF.DG3");
    }

    byte[] dg4Bytes = artifacts.getDg4Bytes();
    if (dg4Bytes != null && dg4Bytes.length > 0) {
      createEF(ch, EF_DG4, dg4Bytes.length, "CREATE EF.DG4");
      selectEF(ch, EF_DG4, "SELECT EF.DG4 before WRITE");
      writeBinary(ch, dg4Bytes, "WRITE EF.DG4");
    }

    byte[] sodBytes = artifacts.getSodBytes();
    createEF(ch, EF_SOD, sodBytes.length, "CREATE EF.SOD");
    selectEF(ch, EF_SOD, "SELECT EF.SOD before WRITE");
    writeBinary(ch, sodBytes, "WRITE EF.SOD");

    if (artifacts.getAaKeyPair() != null && artifacts.getAaKeyPair().getPrivate() != null) {
      seedActiveAuthenticationKey(ch, artifacts.getAaKeyPair().getPrivate());
    }

    if (artifacts.getChipAuthKeyPair() != null) {
      seedChipAuthenticationKey(ch, artifacts.getChipAuthKeyPair());
    }

    seedCvcaCertificate(ch);

    writeDefaultTrustAnchors(artifacts);
    return artifacts;
  }

  private static void hydrateFromArtifacts(CardChannel ch, SODArtifacts artifacts) throws Exception {
    PersonalizationJob job = artifacts.getJob();
    List<Integer> comTags = job != null ? job.getComTagList() : new ArrayList<>();
    if (comTags.isEmpty()) {
      comTags.add(LDSFile.EF_DG1_TAG);
      for (Integer dg : artifacts.getPresentDataGroupNumbers()) {
        comTags.add(Integer.valueOf(0x0100 | (dg.intValue() & 0xFF)));
      }
      Collections.sort(comTags);
    }
    int[] tagArray = comTags.stream().mapToInt(Integer::intValue).toArray();
    COMFile comFile = new COMFile("1.7", "4.0.0", tagArray);
    byte[] comBytes = comFile.getEncoded();
    createEF(ch, EF_COM, comBytes.length, "CREATE EF.COM");
    selectEF(ch, EF_COM, "SELECT EF.COM before WRITE");
    writeBinary(ch, comBytes, "WRITE EF.COM");

    List<Map.Entry<Integer, byte[]>> dataGroups = new ArrayList<>(artifacts.getDataGroupBytesMap().entrySet());
    dataGroups.sort(Comparator.comparingInt(Map.Entry::getKey));
    for (Map.Entry<Integer, byte[]> entry : dataGroups) {
      Integer dg = entry.getKey();
      byte[] bytes = entry.getValue();
      if (dg == null || bytes == null || bytes.length == 0) {
        continue;
      }
      short fid = (short) (0x0100 | (dg.intValue() & 0xFF));
      createEF(ch, fid, bytes.length, String.format("CREATE EF.DG%d", dg));
      selectEF(ch, fid, String.format("SELECT EF.DG%d before WRITE", dg));
      writeBinary(ch, bytes, String.format("WRITE EF.DG%d", dg));
    }

    byte[] cardAccessBytes = artifacts.getCardAccessBytes();
    if (cardAccessBytes != null && cardAccessBytes.length > 0) {
      createEF(ch, EF_CARD_ACCESS, cardAccessBytes.length, "CREATE EF.CardAccess");
      selectEF(ch, EF_CARD_ACCESS, "SELECT EF.CardAccess before WRITE");
      writeBinary(ch, cardAccessBytes, "WRITE EF.CardAccess");
    }

    byte[] sodBytes = artifacts.getSodBytes();
    createEF(ch, EF_SOD, sodBytes.length, "CREATE EF.SOD");
    selectEF(ch, EF_SOD, "SELECT EF.SOD before WRITE");
    writeBinary(ch, sodBytes, "WRITE EF.SOD");

    if (artifacts.getAaKeyPair() != null && artifacts.getAaKeyPair().getPrivate() != null) {
      seedActiveAuthenticationKey(ch, artifacts.getAaKeyPair().getPrivate());
    }

    if (artifacts.getChipAuthKeyPair() != null) {
      seedChipAuthenticationKey(ch, artifacts.getChipAuthKeyPair());
    }

    seedCvcaCertificate(ch);

    writeDefaultTrustAnchors(artifacts);
  }

  private static void writeDefaultTrustAnchors(SODArtifacts artifacts)
      throws IOException, CertificateEncodingException {
    if (artifacts == null || artifacts.getCscaCert() == null) {
      return;
    }
    Path trustDir = Paths.get("target", "trust-store");
    Files.createDirectories(trustDir);
    try (Stream<Path> stream = Files.list(trustDir)) {
      stream.filter(Files::isRegularFile).forEach(path -> {
        try {
          Files.delete(path);
        } catch (Exception ignore) {
        }
      });
    }
    Files.deleteIfExists(trustDir.resolve("dsc.cer"));
    Files.write(trustDir.resolve("csca.cer"), artifacts.getCscaCert().getEncoded());
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

  private static void seedChipAuthenticationKey(CardChannel ch, KeyPair chipAuthKeyPair) throws Exception {
    if (chipAuthKeyPair == null) {
      System.out.println("Skipping CA key seed: key pair is null.");
      return;
    }
    PublicKey publicKey = chipAuthKeyPair.getPublic();
    PrivateKey privateKey = chipAuthKeyPair.getPrivate();
    if (!(publicKey instanceof ECPublicKey)) {
      System.out.println("Skipping CA key seed: public key is not EC.");
      return;
    }
    ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
    byte[] ecPrivateKeyTlv = buildEcPrivateKeyTlv(ecPublicKey, privateKey);
    int sw = putData(ch, 0x00, 0x63, ecPrivateKeyTlv, "PUT CA EC private key TLV");
    if (sw != 0x9000) {
      throw new RuntimeException(String.format("Failed to seed CA EC private key (SW=%04X)", sw));
    }
    System.out.println("Successfully seeded Chip Authentication EC private key");
  }

  private static void seedCvcaCertificate(CardChannel ch) throws Exception {
    // Generate a minimal CVCA certificate for chip authentication/terminal authentication
    // This allows the applet to pass the hasEACCertificate() check
    // Note: Using 512-bit RSA to keep certificate size under 255-byte APDU limit
    // (PUT DATA doesn't support command chaining, unlike PSO)
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
    rsaGenerator.initialize(512);
    KeyPair cvcaKeyPair = rsaGenerator.generateKeyPair();
    RSAPublicKey rsaPublicKey = (RSAPublicKey) cvcaKeyPair.getPublic();

    String country = "UT";
    String mnemonic = "EMRTD";
    String sequence = "00001";

    CAReferenceField caReference = new CAReferenceField(country, mnemonic, sequence);
    HolderReferenceField holderReference = new HolderReferenceField(country, mnemonic, sequence);

    Date notBefore = new Date();
    Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

    CVCPublicKey cvcPublicKey = org.ejbca.cvc.KeyFactory.createInstance(rsaPublicKey, "SHA1withRSA", AuthorizationRoleEnum.CVCA);
    CVCertificateBody body = new CVCertificateBody(
        caReference,
        cvcPublicKey,
        holderReference,
        AuthorizationRoleEnum.CVCA,
        AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
        notBefore,
        notAfter);

    CVCertificate certificate = new CVCertificate(body);
    // For root certificate installation, send only the TBS (to-be-signed) body
    // The applet parseCertificate with root=true expects just the body without signature
    byte[] cvcBytes = certificate.getTBS();
    System.out.printf("Generated CVCA certificate body (TBS): %d bytes (APDU limit: 255)%n", cvcBytes.length);
    if (cvcBytes.length > 255) {
      throw new RuntimeException(String.format(
          "CVCA certificate too large (%d bytes) for standard APDU (max 255 bytes). PUT DATA doesn't support chaining.",
          cvcBytes.length));
    }
    // P1=0x01 stores this as the root CVCA certificate in slot 1
    int sw = putData(ch, 0x01, 0x64, cvcBytes, "PUT CVCA certificate");
    if (sw != 0x9000) {
      throw new RuntimeException(String.format("Failed to seed CVCA certificate (SW=%04X)", sw));
    }
    System.out.println("Successfully seeded CVCA root certificate");
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

  private static byte[] buildEcPrivateKeyTlv(ECPublicKey ecPublicKey, PrivateKey privateKey) throws Exception {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new IllegalArgumentException("Private key must be ECPrivateKey");
    }
    ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
    ECParameterSpec params = ecPublicKey.getParams();
    EllipticCurve curve = params.getCurve();
    ECPoint generator = params.getGenerator();

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // 0x81: Prime field P (using standard curve primes based on field size)
    int fieldSize = curve.getField().getFieldSize();
    byte[] prime;
    if (fieldSize == 256) {
      // P-256 (secp256r1) prime
      prime = stripLeadingZero(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16).toByteArray());
    } else if (fieldSize == 384) {
      // P-384 (secp384r1) prime
      prime = stripLeadingZero(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", 16).toByteArray());
    } else if (fieldSize == 521) {
      // P-521 (secp521r1) prime
      prime = stripLeadingZero(new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16).toByteArray());
    } else {
      throw new IllegalArgumentException("Unsupported EC curve field size: " + fieldSize);
    }
    writeTag(out, 0x81);
    writeLength(out, prime.length);
    out.write(prime, 0, prime.length);

    // 0x82: Coefficient A
    byte[] a = stripLeadingZero(curve.getA().toByteArray());
    writeTag(out, 0x82);
    writeLength(out, a.length);
    out.write(a, 0, a.length);

    // 0x83: Coefficient B
    byte[] b = stripLeadingZero(curve.getB().toByteArray());
    writeTag(out, 0x83);
    writeLength(out, b.length);
    out.write(b, 0, b.length);

    // 0x84: Generator G (uncompressed point format: 0x04 || X || Y)
    byte[] gx = stripLeadingZero(generator.getAffineX().toByteArray());
    byte[] gy = stripLeadingZero(generator.getAffineY().toByteArray());
    int coordSize = (curve.getField().getFieldSize() + 7) / 8;
    byte[] g = new byte[1 + coordSize * 2];
    g[0] = 0x04; // Uncompressed point
    System.arraycopy(gx, 0, g, 1 + coordSize - gx.length, gx.length);
    System.arraycopy(gy, 0, g, 1 + coordSize + coordSize - gy.length, gy.length);
    writeTag(out, 0x84);
    writeLength(out, g.length);
    out.write(g, 0, g.length);

    // 0x85: Order R
    byte[] r = stripLeadingZero(params.getOrder().toByteArray());
    writeTag(out, 0x85);
    writeLength(out, r.length);
    out.write(r, 0, r.length);

    // 0x86: Private key S
    byte[] s = stripLeadingZero(ecPrivateKey.getS().toByteArray());
    writeTag(out, 0x86);
    writeLength(out, s.length);
    out.write(s, 0, s.length);

    // 0x87: Cofactor (h = 1 for most curves)
    writeTag(out, 0x87);
    writeLength(out, 2);
    out.write(0x00);
    out.write(params.getCofactor());

    return out.toByteArray();
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
      int numBytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
      out.write(0x80 | numBytes);
      for (int i = numBytes - 1; i >= 0; i--) {
        out.write((length >> (8 * i)) & 0xFF);
      }
    }
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

  private static String resolveTransport(CardTerminal terminal, Card card) {
    if (card != null) {
      String protocol = card.getProtocol();
      if (protocol != null && !protocol.isBlank()) {
        return protocol;
      }
    }
    if (terminal != null) {
      String name = terminal.getName();
      if (name != null && !name.isBlank()) {
        return name;
      }
    }
    return "SIMULATOR";
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
    if (hasText(can)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createCANKey(can), "CAN", null);
      } catch (Exception e) {
        return new PaceKeySelection(null, "CAN", e);
      }
    }
    if (hasText(pin)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createPINKey(pin), "PIN", null);
      } catch (Exception e) {
        return new PaceKeySelection(null, "PIN", e);
      }
    }
    if (hasText(puk)) {
      try {
        return new PaceKeySelection(PACEKeySpec.createPUKKey(puk), "PUK", null);
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
      List<PACEInfo> paceInfos,
      String preference,
      SimEvents events) {
    PaceOutcome outcome = new PaceOutcome();
    outcome.attempted = attemptPace;
    outcome.keySelection = keySelection;
    outcome.preference = hasText(preference) ? preference : null;
    if (!attemptPace) {
      return outcome;
    }
    if (paceInfos == null || paceInfos.isEmpty()) {
      return outcome;
    }
    outcome.availableOptions = paceInfos.size();
    outcome.selectedInfo = selectPreferredPACEInfo(paceInfos, preference);
    outcome.preferenceMatched = !hasText(preference)
        || matchesPacePreference(outcome.selectedInfo, preference);
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
      if (outcome.established) {
        logSecureMessagingTransition(
            "PACE handshake",
            "PACE",
            describeCipher(result.getCipherAlg(), result.getKeyLength()));
      }
    } catch (Exception e) {
      outcome.failure = e;
    }
    return outcome;
  }

  private static void logPaceOutcome(PaceOutcome outcome) {
    securityPrintln(String.format("PACE entries advertised: %d", outcome.availableOptions));
    if (outcome.keySelection != null && outcome.keySelection.label != null) {
      securityPrintln(String.format("PACE key source: %s", outcome.keySelection.label));
    }
    if (outcome.keySelection != null && outcome.keySelection.error != null) {
      securityPrintln("PACE key preparation failed: " + outcome.keySelection.error.getMessage());
    }
    if (hasText(outcome.preference)) {
      securityPrintln(String.format("PACE preference: %s (matched=%s)",
          outcome.preference,
          outcome.preferenceMatched));
    }
    if (outcome.selectedInfo != null) {
      BigInteger parameterId = outcome.selectedInfo.getParameterId();
      String displayOid = outcome.selectedInfo.getProtocolOIDString();
      String dottedOid = outcome.selectedInfo.getObjectIdentifier();
      securityPrintln(String.format("Selected PACE OID=%s version=%d paramId=%s keyLength=%d",
          displayOid != null ? displayOid : dottedOid,
          outcome.selectedInfo.getVersion(),
          parameterId != null ? parameterId.toString(16) : "default",
          resolvePaceKeyLength(outcome.selectedInfo)));
      if (displayOid != null && dottedOid != null && !displayOid.equals(dottedOid)) {
        securityPrintln(String.format("  (OID dotted=%s)", dottedOid));
      }
    }
    if (outcome.result != null) {
      securityPrintln(String.format("PACE mapping=%s agreement=%s cipher=%s digest=%s keyLength=%d",
          outcome.result.getMappingType(),
          outcome.result.getAgreementAlg(),
          outcome.result.getCipherAlg(),
          outcome.result.getDigestAlg(),
          outcome.result.getKeyLength()));
    }
    if (outcome.availableOptions == 0) {
      securityPrintln("PACE info not present in EF.CardAccess.");
    }
    if (outcome.established) {
      securityPrintln("PACE secure messaging established.");
    } else if (outcome.failure != null) {
      securityPrintln("PACE failed: " + outcome.failure.getMessage());
    } else if (outcome.attempted) {
      securityPrintln("PACE did not establish secure messaging.");
    }
  }

  private static PACEInfo selectPreferredPACEInfo(List<PACEInfo> paceInfos, String preference) {
    if (paceInfos == null || paceInfos.isEmpty()) {
      return null;
    }
    if (hasText(preference)) {
      List<PACEInfo> matches = paceInfos.stream()
          .filter(info -> matchesPacePreference(info, preference))
          .collect(Collectors.toList());
      if (!matches.isEmpty()) {
        return matches.stream()
            .max(Comparator.comparingInt(SimRunner::resolvePaceKeyLength))
            .orElse(matches.get(0));
      }
    }
    return paceInfos.stream()
        .max(Comparator.comparingInt(SimRunner::resolvePaceKeyLength))
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

  private static boolean matchesPacePreference(PACEInfo info, String preference) {
    if (info == null || !hasText(preference)) {
      return false;
    }
    String trimmed = preference.trim();
    if (trimmed.isEmpty()) {
      return false;
    }
    String dotted = info.getObjectIdentifier();
    if (trimmed.matches("[0-9.]+")) {
      return dotted != null && dotted.equals(trimmed);
    }
    if (trimmed.regionMatches(true, 0, "oid:", 0, 4)) {
      String value = trimmed.substring(4).trim();
      return hasText(value) && dotted != null && dotted.equals(value);
    }
    String normalized = trimmed.toUpperCase(Locale.ROOT);
    String display = info.getProtocolOIDString();
    StringBuilder descriptor = new StringBuilder();
    if (display != null) {
      descriptor.append(display.toUpperCase(Locale.ROOT));
    }
    if (dotted != null) {
      if (descriptor.length() > 0) {
        descriptor.append(' ');
      }
      descriptor.append(dotted.toUpperCase(Locale.ROOT));
    }
    String combined = descriptor.toString();

    if (normalized.equals("GM")) {
      return combined.contains("GM");
    }
    if (normalized.equals("IM")) {
      return combined.contains("IM");
    }
    if (normalized.contains("3DES") || normalized.contains("DESEDE")) {
      return combined.contains("3DES") || combined.contains("DESEDE");
    }
    if (normalized.contains("AES256") || normalized.contains("AES-256")) {
      return resolvePaceKeyLength(info) == 256;
    }
    if (normalized.contains("AES192") || normalized.contains("AES-192")) {
      return resolvePaceKeyLength(info) == 192;
    }
    if (normalized.contains("AES128") || normalized.contains("AES-128") || normalized.equals("AES")) {
      return resolvePaceKeyLength(info) == 128;
    }
    if (combined.contains(normalized)) {
      return true;
    }
    return false;
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

  private static ChipAuthOutcome performChipAuthenticationIfSupported(
      PassportService svc,
      DG14File dg14) {
    ChipAuthOutcome outcome = new ChipAuthOutcome();
    if (dg14 == null) {
      securityPrintln("Chip Authentication info unavailable (DG14 missing).");
      return outcome;
    }
    List<ChipAuthenticationInfo> chipInfos = dg14.getChipAuthenticationInfos();
    List<ChipAuthenticationPublicKeyInfo> publicKeyInfos = dg14.getChipAuthenticationPublicKeyInfos();
    outcome.advertised = chipInfos != null && !chipInfos.isEmpty();
    if (!outcome.advertised) {
      securityPrintln("Chip Authentication not advertised in DG14.");
      return outcome;
    }

    securityPrintln(String.format("Chip Authentication entries advertised: %d", chipInfos.size()));
    for (ChipAuthenticationInfo info : chipInfos) {
      BigInteger keyId = info.getKeyId();
      String caDisplay = info.getProtocolOIDString();
      String caDotted = info.getObjectIdentifier();
      securityPrintln(String.format("  CA OID=%s version=%d keyId=%s keyLength=%d",
          caDisplay != null ? caDisplay : caDotted,
          info.getVersion(),
          keyId != null ? keyId.toString(16) : "n/a",
          resolveChipKeyLength(info)));
      if (caDisplay != null && caDotted != null && !caDisplay.equals(caDotted)) {
        securityPrintln(String.format("    (OID dotted=%s)", caDotted));
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
      securityPrintln("Unable to select Chip Authentication profile.");
      return outcome;
    }

    BigInteger keyId = outcome.selectedInfo.getKeyId();
    ChipAuthenticationPublicKeyInfo publicKeyInfo = keyId != null ? publicKeysById.get(keyId) : null;
    if (publicKeyInfo == null) {
      publicKeyInfo = fallbackKey;
    }

    if (publicKeyInfo == null) {
      securityPrintln("Chip Authentication public key not found; skipping CA handshake.");
      return outcome;
    }

    outcome.publicKeyInfo = publicKeyInfo;
    try {
      String caOid = outcome.selectedInfo.getObjectIdentifier();
      String publicKeyOid = publicKeyInfo.getObjectIdentifier();

      // Pass the OIDs directly to doEACCA - the library expects OID strings, not algorithm names
      EACCAResult result = svc.doEACCA(keyId, caOid, publicKeyOid, publicKeyInfo.getSubjectPublicKey());
      outcome.result = result;
      outcome.established = result != null && result.getWrapper() != null;
      if (outcome.established) {
        securityPrintln(String.format(
            "Chip Authentication established (protocol=%s keyId=%s).",
            outcome.selectedInfo.getProtocolOIDString() != null ?
                outcome.selectedInfo.getProtocolOIDString() : caOid,
            keyId != null ? keyId.toString(16) : "n/a"));
        logSecureMessagingTransition(
            "Chip Authentication",
            resolveSecureMessagingMode(null, outcome),
            describeChipCipher(outcome.selectedInfo));
      } else {
        securityPrintln("Chip Authentication handshake did not upgrade secure messaging.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      securityPrintln("Chip Authentication failed: " + e.getMessage());
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
      securityPrintln("Active Authentication skipped: DG15 not present.");
      return outcome;
    }
    outcome.available = true;
    outcome.publicKey = dg15.getPublicKey();
    if (outcome.publicKey == null) {
      securityPrintln("Active Authentication skipped: DG15 does not contain a public key.");
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
          securityPrintln(
              "Active Authentication response missing under secure messaging, retrying without protection.");
          outcome.response = tryPlainInternalAuthenticate(rawService, challenge);
        }
        try {
          outcome.verified = verifyActiveAuthenticationSignature(outcome.publicKey, challenge, outcome.response);
        } catch (GeneralSecurityException e) {
          outcome.failure = e;
          securityPrintln("Active Authentication verification error: " + e.getMessage());
        }
      }

      if (outcome.verified) {
        Integer keyBits = describeKeyBits(outcome.publicKey);
        if (keyBits != null) {
          securityPrintln(String.format("Active Authentication verified (%s %d-bit).",
              outcome.publicKey.getAlgorithm(), keyBits));
        } else {
          securityPrintln(String.format("Active Authentication verified (%s).",
              outcome.publicKey.getAlgorithm()));
        }
      } else if (requireAA) {
        securityPrintln("Active Authentication verification failed.");
      } else {
        securityPrintln("Active Authentication attempt did not verify signature.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      securityPrintln("Active Authentication failed: " + e.getMessage());
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

  private static Integer describeKeyBits(PublicKey key) {
    if (key instanceof RSAPublicKey) {
      return ((RSAPublicKey) key).getModulus().bitLength();
    }
    if (key instanceof ECPublicKey) {
      return ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
    }
    return null;
  }

  private static int expectedAaResponseLength(PublicKey key) {
    if (key instanceof RSAPublicKey) {
      int keyBits = ((RSAPublicKey) key).getModulus().bitLength();
      return keyBits / Byte.SIZE;
    }
    return -1;
  }

  private static String resolveAADigestAlgorithm(PublicKey key) {
    if (key == null) {
      return null;
    }
    if (key instanceof RSAPublicKey || "RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return "SHA-1";
    }
    if (key instanceof ECPublicKey) {
      int fieldSize = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
      if (fieldSize <= 192) {
        return "SHA-1";
      }
      if (fieldSize <= 224) {
        return "SHA-224";
      }
      if (fieldSize <= 256) {
        return "SHA-256";
      }
      if (fieldSize <= 384) {
        return "SHA-384";
      }
      return "SHA-512";
    }
    return null;
  }

  private static String resolveAASignatureAlgorithm(PublicKey key) {
    if (key == null) {
      return null;
    }
    if (key instanceof RSAPublicKey || "RSA".equalsIgnoreCase(key.getAlgorithm())) {
      return "SHA1withRSA";
    }
    if (key instanceof ECPublicKey || "EC".equalsIgnoreCase(key.getAlgorithm())) {
      String digest = resolveAADigestAlgorithm(key);
      if (digest == null) {
        return "SHA256withECDSA";
      }
      return digest.replace("-", "") + "withECDSA";
    }
    return key.getAlgorithm();
  }

  private static boolean verifyActiveAuthenticationSignature(
      PublicKey key, byte[] challenge, byte[] response) throws GeneralSecurityException {
    if (response == null || response.length == 0) {
      return false;
    }
    if (key instanceof RSAPublicKey) {
      return verifyRsaActiveAuthentication((RSAPublicKey) key, challenge, response);
    }
    if (key instanceof ECPublicKey) {
      return verifyEcdsaActiveAuthentication((ECPublicKey) key, challenge, response);
    }
    throw new GeneralSecurityException("Unsupported AA key algorithm: " + key.getAlgorithm());
  }

  private static boolean verifyRsaActiveAuthentication(RSAPublicKey key, byte[] challenge, byte[] response)
      throws GeneralSecurityException {
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

  private static boolean verifyEcdsaActiveAuthentication(
      ECPublicKey key, byte[] challenge, byte[] response)
      throws GeneralSecurityException {
    GeneralSecurityException lastError = null;
    for (String algorithm : buildEcdsaSignatureCandidates(key)) {
      try {
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(key);
        verifier.update(challenge);
        if (verifier.verify(response)) {
          return true;
        }
      } catch (GeneralSecurityException e) {
        lastError = e;
      }
    }
    if (lastError != null) {
      throw lastError;
    }
    return false;
  }

  private static List<String> buildEcdsaSignatureCandidates(ECPublicKey key) {
    List<String> algorithms = new ArrayList<>();
    String preferred = resolveAASignatureAlgorithm(key);
    if (hasText(preferred) && !algorithms.contains(preferred)) {
      algorithms.add(preferred);
    }
    int fieldSize = key.getParams().getCurve().getField().getFieldSize();
    if (fieldSize <= 192) {
      addIfMissing(algorithms, "SHA1withECDSA");
      addIfMissing(algorithms, "SHA224withECDSA");
    } else if (fieldSize <= 256) {
      addIfMissing(algorithms, "SHA256withECDSA");
      addIfMissing(algorithms, "SHA224withECDSA");
    } else if (fieldSize <= 384) {
      addIfMissing(algorithms, "SHA384withECDSA");
      addIfMissing(algorithms, "SHA256withECDSA");
    } else {
      addIfMissing(algorithms, "SHA512withECDSA");
      addIfMissing(algorithms, "SHA384withECDSA");
    }
    addIfMissing(algorithms, "SHA512withECDSA");
    return algorithms;
  }

  private static void addIfMissing(List<String> algorithms, String candidate) {
    if (!algorithms.contains(candidate)) {
      algorithms.add(candidate);
    }
  }

  private static byte[] encodeCurrentDate(LocalDate date) {
    byte[] digits = new byte[6];
    int year = date.getYear() % 100;
    int month = date.getMonthValue();
    int day = date.getDayOfMonth();
    digits[0] = (byte) ((year / 10) % 10);
    digits[1] = (byte) (year % 10);
    digits[2] = (byte) (month / 10);
    digits[3] = (byte) (month % 10);
    digits[4] = (byte) (day / 10);
    digits[5] = (byte) (day % 10);
    return digits;
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
    throw new IllegalArgumentException("Unsupported TA date format: " + override);
  }

  private static ChipAuthenticationInfo selectPreferredChipAuth(List<ChipAuthenticationInfo> chipInfos) {
    return chipInfos.stream()
        .max(Comparator.comparingInt(SimRunner::resolveChipKeyLength))
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
      String documentNumber,
      LocalDate validationDate) {
    TerminalAuthOutcome outcome = new TerminalAuthOutcome();
    outcome.suppliedCertificates = cvcBundles != null ? cvcBundles.size() : 0;

    if (cvcBundles == null || cvcBundles.isEmpty()) {
      securityPrintln("Terminal Authentication skipped: provide at least one --ta-cvc file.");
      return finalizeTerminalAuthOutcome(outcome);
    }
    if (chipOutcome == null || chipOutcome.result == null) {
      securityPrintln("Terminal Authentication skipped: Chip Authentication was not established.");
      return finalizeTerminalAuthOutcome(outcome);
    }
    if (taKeyPath == null) {
      securityPrintln("Terminal Authentication skipped: --ta-key not provided.");
      return finalizeTerminalAuthOutcome(outcome);
    }

    List<CardVerifiableCertificate> certificateChain = new ArrayList<>();
    for (CvcBundle bundle : cvcBundles) {
      if (bundle.error != null) {
        securityPrintln(String.format("  %s → cannot use certificate: %s",
            bundle.path,
            bundle.error.getMessage() != null ? bundle.error.getMessage() : "unknown error"));
        outcome.failure = bundle.error;
        return finalizeTerminalAuthOutcome(outcome);
      }
      if (bundle.cardCertificate == null) {
        securityPrintln(String.format(
            "  %s → parsed certificate but could not build CardVerifiableCertificate.",
            bundle.path));
        outcome.failure = new IllegalStateException("Unable to build CVC certificate wrapper");
        return finalizeTerminalAuthOutcome(outcome);
      }
      certificateChain.add(bundle.cardCertificate);
    }

    CvcChainValidationResult chainValidation = validateCvcChain(cvcBundles, validationDate);
    outcome.cvcValidation = chainValidation;
    if (chainValidation != null) {
      logCvcChainValidation(chainValidation);
      outcome.terminalRole = chainValidation.terminalRole;
      outcome.terminalRights = chainValidation.terminalRights;
      outcome.dg3AllowedByRights = allowsDataGroup(chainValidation.terminalRights, 3);
      outcome.dg4AllowedByRights = allowsDataGroup(chainValidation.terminalRights, 4);
      if (chainValidation.warnings != null) {
        outcome.warnings.addAll(chainValidation.warnings);
      }
    }

    PrivateKey terminalKey;
    try {
      terminalKey = loadPrivateKey(taKeyPath);
    } catch (Exception e) {
      securityPrintln("Terminal Authentication skipped: unable to load terminal private key (" + e.getMessage() + ").");
      outcome.failure = e;
      return finalizeTerminalAuthOutcome(outcome);
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
        securityPrintln("Terminal Authentication handshake completed.");
      } else {
        securityPrintln("Terminal Authentication did not return a success indicator.");
      }
    } catch (Exception e) {
      outcome.failure = e;
      securityPrintln("Terminal Authentication failed: " + e.getMessage());
    }

    outcome.dg3Readable = attemptDataGroupRead(svc, PassportService.EF_DG3, "DG3");
    outcome.dg4Readable = attemptDataGroupRead(svc, PassportService.EF_DG4, "DG4");
    if (outcome.terminalRights != null) {
      if (outcome.dg3AllowedByRights && !outcome.dg3Readable) {
        securityPrintln("DG3 read denied despite terminal rights including DG3 access.");
        outcome.warnings.add("DG3 read denied despite terminal rights including DG3 access.");
      }
      if (!outcome.dg3AllowedByRights && outcome.dg3Readable) {
        securityPrintln("DG3 read succeeded even though terminal rights do not include DG3.");
        outcome.warnings.add("DG3 read succeeded even though terminal rights do not include DG3.");
      }
      if (outcome.dg4AllowedByRights && !outcome.dg4Readable) {
        securityPrintln("DG4 read denied despite terminal rights including DG4 access.");
        outcome.warnings.add("DG4 read denied despite terminal rights including DG4 access.");
      }
      if (!outcome.dg4AllowedByRights && outcome.dg4Readable) {
        securityPrintln("DG4 read succeeded even though terminal rights do not include DG4.");
        outcome.warnings.add("DG4 read succeeded even though terminal rights do not include DG4.");
      }
    }
    return finalizeTerminalAuthOutcome(outcome);
  }

  private static TerminalAuthOutcome finalizeTerminalAuthOutcome(TerminalAuthOutcome outcome) {
    if (outcome.report == null) {
      outcome.report = SessionReport.TerminalAuth.fromOutcome(
          outcome.attempted,
          outcome.succeeded,
          outcome.dg3Readable,
          outcome.dg4Readable,
          outcome.terminalRole != null ? outcome.terminalRole.name() : null,
          outcome.terminalRights != null ? outcome.terminalRights.name() : null,
          outcome.warnings);
    }
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
      securityPrintln("Terminal Authentication info unavailable (DG14 missing).");
    } else {
      List<TerminalAuthenticationInfo> taInfos = dg14.getTerminalAuthenticationInfos();
      if (taInfos == null || taInfos.isEmpty()) {
        securityPrintln("Terminal Authentication not advertised in DG14.");
      } else {
        securityPrintln("Terminal Authentication advertised entries:");
        for (TerminalAuthenticationInfo info : taInfos) {
          int fileId = info.getFileId();
          byte sfi = info.getShortFileId();
          securityPrintln(String.format("  TA OID=%s version=%d fileId=%04X (SFI=%02X)",
              info.getProtocolOIDString(),
              info.getVersion(),
              fileId,
              sfi & 0xFF));
        }
      }
    }

    if (cvcBundles == null || cvcBundles.isEmpty()) {
      securityPrintln("No terminal authentication CVCs supplied.");
      return;
    }

    securityPrintln(String.format("Terminal Authentication CVCs processed: %d", cvcBundles.size()));
    for (CvcBundle bundle : cvcBundles) {
      if (bundle.certificate == null) {
        securityPrintln(String.format("  %s → parse failed: %s",
            bundle.path,
            bundle.error != null ? bundle.error.getMessage() : "unknown error"));
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

      securityPrintln(String.format("  %s → holder=%s issuer=%s role=%s rights=%s valid=%s..%s",
          bundle.path,
          holder != null ? holder.getConcatenated() : "-",
          authority != null ? authority.getConcatenated() : "-",
          role != null ? role.name() : "-",
          rights != null ? rights.name() : "-",
          formatDate(validFrom),
          formatDate(validTo)));
    } catch (Exception e) {
      securityPrintln(String.format("  %s → unable to summarise: %s", bundle.path, e.getMessage()));
    }
  }

  private static CvcChainValidationResult validateCvcChain(List<CvcBundle> bundles, LocalDate validationDate) {
    CvcChainValidationResult result = new CvcChainValidationResult();
    if (bundles == null || bundles.isEmpty()) {
      result.warnings.add("No CVC certificates provided for validation.");
      return result;
    }
    Date referenceDate = validationDate != null ? Date.from(validationDate.atStartOfDay(ZoneOffset.UTC).toInstant()) : null;
    CvcBundle previous = null;
    for (CvcBundle bundle : bundles) {
      if (bundle == null || bundle.certificate == null || bundle.cardCertificate == null) {
        result.errors.add(String.format("Unable to validate certificate %s: not parsed.", describePath(bundle)));
        continue;
      }
      CVCertificateBody body;
      try {
        body = bundle.certificate.getCertificateBody();
      } catch (Exception e) {
        result.errors.add(String.format("Unable to obtain certificate body for %s: %s",
            describePath(bundle),
            e.getMessage() != null ? e.getMessage() : "unknown error"));
        continue;
      }
      Date notBefore = null;
      try {
        notBefore = body.getValidFrom();
      } catch (Exception ignore) {
      }
      Date notAfter = null;
      try {
        notAfter = body.getValidTo();
      } catch (Exception ignore) {
      }
      if (referenceDate != null) {
        if (notBefore != null && referenceDate.before(notBefore)) {
          result.errors.add(String.format("Certificate %s not yet valid on %s.", describePath(bundle), formatDate(referenceDate)));
        }
        if (notAfter != null && referenceDate.after(notAfter)) {
          result.errors.add(String.format("Certificate %s expired on %s.", describePath(bundle), formatDate(notAfter)));
        }
      }

      if (previous != null && previous.certificate != null && previous.cardCertificate != null) {
        CVCertificateBody previousBody;
        try {
          previousBody = previous.certificate.getCertificateBody();
        } catch (Exception e) {
          previousBody = null;
        }
        HolderReferenceField previousHolder = null;
        if (previousBody != null) {
          try {
            previousHolder = previousBody.getHolderReference();
          } catch (Exception ignore) {
            previousHolder = null;
          }
        }
        CAReferenceField authority;
        try {
          authority = body.getAuthorityReference();
        } catch (Exception e) {
          authority = null;
        }
        if (previousHolder != null && authority != null) {
          if (!previousHolder.getConcatenated().equalsIgnoreCase(authority.getConcatenated())) {
            result.errors.add(String.format("Issuer reference mismatch: %s signed by %s but authority expects %s.",
                describePath(bundle),
                previousHolder.getConcatenated(),
                authority.getConcatenated()));
          }
        } else {
          result.warnings.add(String.format("Unable to compare issuer/holder references for %s.", describePath(bundle)));
        }
        try {
          bundle.cardCertificate.verify(previous.cardCertificate.getPublicKey());
        } catch (GeneralSecurityException e) {
          result.errors.add(String.format("Certificate %s signature failed verification with issuer public key: %s",
              describePath(bundle), e.getMessage()));
        }
      }

      CVCAuthorizationTemplate authorizationTemplate;
      try {
        authorizationTemplate = body.getAuthorizationTemplate();
      } catch (Exception e) {
        authorizationTemplate = null;
      }
      AuthorizationField authorizationField = null;
      if (authorizationTemplate != null) {
        try {
          authorizationField = authorizationTemplate.getAuthorizationField();
        } catch (Exception ignore) {
          authorizationField = null;
        }
      }
      if (authorizationField != null) {
        result.terminalRole = authorizationField.getRole();
        result.terminalRights = authorizationField.getAccessRight();
      }

      previous = bundle;
    }
    result.valid = result.errors.isEmpty();
    return result;
  }

  private static void logCvcChainValidation(CvcChainValidationResult validation) {
    if (validation == null) {
      return;
    }
    if (validation.valid) {
      System.out.println("CVC chain validation: OK");
    } else {
      System.out.println("CVC chain validation: issues detected");
    }
    for (String error : validation.errors) {
      System.out.println("  Chain error: " + error);
    }
    for (String warning : validation.warnings) {
      System.out.println("  Chain warning: " + warning);
    }
    if (validation.terminalRole != null) {
      System.out.println("  Terminal role: " + validation.terminalRole.name());
    }
    if (validation.terminalRights != null) {
      boolean dg3 = allowsDataGroup(validation.terminalRights, 3);
      boolean dg4 = allowsDataGroup(validation.terminalRights, 4);
      System.out.printf("  Terminal rights: %s (DG3=%s, DG4=%s)%n",
          validation.terminalRights.name(),
          dg3,
          dg4);
    }
  }

  private static boolean allowsDataGroup(AccessRightEnum rights, int dataGroup) {
    if (rights == null) {
      return false;
    }
    String name = rights.name();
    if (dataGroup == 3) {
      return name.contains("DG3");
    }
    if (dataGroup == 4) {
      return name.contains("DG4");
    }
    return false;
  }

  private static String describePath(CvcBundle bundle) {
    if (bundle == null || bundle.path == null) {
      return "(in-memory)";
    }
    return bundle.path.toString();
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
    String preference;
    boolean preferenceMatched;
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

  static final class ActiveAuthOutcome {
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

  private static final class CvcChainValidationResult {
    boolean valid;
    final List<String> warnings = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    AuthorizationRoleEnum terminalRole;
    AccessRightEnum terminalRights;
  }

  private static final class TerminalAuthOutcome {
    int suppliedCertificates;
    boolean attempted;
    boolean succeeded;
    boolean dg3Readable;
    boolean dg4Readable;
    Exception failure;
    CvcChainValidationResult cvcValidation;
    AuthorizationRoleEnum terminalRole;
    AccessRightEnum terminalRights;
    boolean dg3AllowedByRights;
    boolean dg4AllowedByRights;
    final List<String> warnings = new ArrayList<>();
    SessionReport.TerminalAuth report;
  }

  private static final class SimOutputRouter extends OutputStream {
    private final SimEvents events;
    private final PrintStream delegate;
    private final StringBuilder buffer = new StringBuilder();

    SimOutputRouter(SimEvents events, PrintStream delegate) {
      this.events = events;
      this.delegate = delegate;
    }

    @Override
    public void write(int b) throws IOException {
      delegate.write(b);
      appendByte(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      delegate.write(b, off, len);
      for (int i = off; i < off + len; i++) {
        appendByte(b[i]);
      }
    }

    private void appendByte(int value) {
      if (value == '\r') {
        return;
      }
      if (value == '\n') {
        flushBuffer();
        return;
      }
      buffer.append((char) value);
    }

    private void flushBuffer() {
      if (buffer.length() == 0) {
        return;
      }
      String message = buffer.toString();
      buffer.setLength(0);
      SimLogCategory category = consumeStdoutCategory();
      if (category == null) {
        category = SimLogCategory.GENERAL;
      }
      events.onLog(category, message);
    }

    void finish() {
      flushBuffer();
      delegate.flush();
    }
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

  private static SessionReport.Dg2Metadata summarizeDG2(
      PassportService svc,
      boolean largeScenario,
      SimConfig config,
      SimEvents sink,
      SODArtifacts personalizationArtifacts) {
    String issuerPreviewPath = null;
    if (config != null && config.issuerResult != null) {
      issuerPreviewPath = config.issuerResult.getFacePreviewPath()
          .map(path -> path.toAbsolutePath().toString())
          .orElse(null);
    }
    byte[] dg2Bytes = null;
    try (InputStream in = svc.getInputStream(PassportService.EF_DG2)) {
      if (in != null) {
        dg2Bytes = in.readAllBytes();
      }
    } catch (Exception e) {
      System.out.println("DG2 read error: " + e.getMessage());
    }
    if ((dg2Bytes == null || dg2Bytes.length == 0) && personalizationArtifacts != null) {
      dg2Bytes = personalizationArtifacts.getDataGroupBytes(2);
      if (dg2Bytes != null && dg2Bytes.length > 0) {
        System.out.println("Using issuer artifacts for DG2 metadata.");
      }
    }
    if (dg2Bytes == null || dg2Bytes.length == 0) {
      System.out.println("DG2 not present");
      return null;
    }

    final int warningThreshold = 120_000;
    if (dg2Bytes.length > warningThreshold) {
      System.out.printf("DG2 size %d bytes exceeds safe threshold (%d). Skipping detailed parse.%n",
          dg2Bytes.length, warningThreshold);
      return new SessionReport.Dg2Metadata(dg2Bytes.length, largeScenario, true, List.of(), null, issuerPreviewPath);
    }

    try (ByteArrayInputStream in = new ByteArrayInputStream(dg2Bytes)) {
      DG2File dg2 = new DG2File(in);
      List<FaceInfo> faceInfos = dg2.getFaceInfos();
      int faceCount = 0;
      List<SessionReport.Dg2FaceSummary> faces = new ArrayList<>();
      String previewPath = null;
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
          faces.add(new SessionReport.Dg2FaceSummary(
              i + 1,
              j + 1,
              img.getWidth(),
              img.getHeight(),
              img.getMimeType(),
              img.getImageLength(),
              img.getQuality(),
              describeImageType(img.getImageDataType())));
          if (previewPath == null && config.facePreviewDirectory != null) {
            previewPath = writeFacePreview(config.facePreviewDirectory, img, i + 1, j + 1, sink);
          }
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
      return new SessionReport.Dg2Metadata(
          dg2Bytes.length,
          largeScenario,
          false,
          faces,
          previewPath,
          issuerPreviewPath);
    } catch (IOException | RuntimeException e) {
      System.out.println("DG2 parse error: " + e.getMessage());
      return new SessionReport.Dg2Metadata(
          dg2Bytes.length,
          largeScenario,
          false,
          List.of(),
          null,
          issuerPreviewPath);
    }
  }

  private static String writeFacePreview(
      Path directory,
      FaceImageInfo imageInfo,
      int faceIndex,
      int imageIndex,
      SimEvents sink) {
    try {
      Files.createDirectories(directory);
      String extension = mimeToExtension(imageInfo.getMimeType());
      String fileName = String.format("dg2-face-%d-%d.%s", faceIndex, imageIndex, extension);
      Path target = directory.resolve(fileName);
      try (InputStream imageStream = imageInfo.getImageInputStream()) {
        Files.write(target, imageStream.readAllBytes());
      }
      String absolutePath = target.toAbsolutePath().toString();
      sink.onLog(SimLogCategory.SECURITY, "DG2 face preview exported to " + absolutePath);
      return absolutePath;
    } catch (Exception e) {
      sink.onLog(SimLogCategory.GENERAL, "Failed to export DG2 face preview: " + e.getMessage());
      return null;
    }
  }

  private static String mimeToExtension(String mime) {
    if (mime == null) {
      return "bin";
    }
    String normalized = mime.toLowerCase(Locale.ROOT);
    if (normalized.contains("jpeg")) {
      return "jpg";
    }
    if (normalized.contains("jp2")) {
      return "jp2";
    }
    if (normalized.contains("png")) {
      return "png";
    }
    return "bin";
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

  private static void securityPrintln(String message) {
    printlnWithCategory(SimLogCategory.SECURITY, message);
  }

  private static void printlnWithCategory(SimLogCategory category, String message) {
    if (message == null) {
      return;
    }
    NEXT_STDOUT_CATEGORY.set(category);
    System.out.println(message);
  }

  private static SimLogCategory consumeStdoutCategory() {
    SimLogCategory category = NEXT_STDOUT_CATEGORY.get();
    NEXT_STDOUT_CATEGORY.remove();
    return category;
  }

  private static void logSecureMessagingTransition(
      String stage,
      String mode,
      String detail) {
    if (!hasText(mode)) {
      return;
    }
    StringBuilder message = new StringBuilder("Secure messaging → ");
    message.append(mode);
    if (hasText(detail)) {
      message.append(' ').append('(').append(detail).append(')');
    }
    if (hasText(stage)) {
      message.append(" after ").append(stage);
    }
    message.append('.');
    securityPrintln(message.toString());
  }

  private static String describeCipher(String cipherAlg, int keyLength) {
    if (!hasText(cipherAlg)) {
      return null;
    }
    String normalized = cipherAlg.toUpperCase(Locale.ROOT);
    if (normalized.contains("AES")) {
      if (keyLength > 0) {
        return "AES-" + keyLength;
      }
      return "AES";
    }
    if (normalized.contains("DESEDE") || normalized.contains("3DES")) {
      return "3DES";
    }
    if (normalized.contains("DES")) {
      return "DES";
    }
    return cipherAlg;
  }

  private static String describeChipCipher(ChipAuthenticationInfo info) {
    if (info == null) {
      return null;
    }
    String oid = info.getObjectIdentifier();
    if (oid == null) {
      return null;
    }
    try {
      String cipher = ChipAuthenticationInfo.toCipherAlgorithm(oid);
      int keyLength = ChipAuthenticationInfo.toKeyLength(oid);
      return describeCipher(cipher, keyLength);
    } catch (Exception e) {
      return null;
    }
  }

  private static String resolveSecureMessagingMode(PaceOutcome paceOutcome, ChipAuthOutcome chipOutcome) {
    if (chipOutcome != null && chipOutcome.established) {
      String cipher = null;
      if (chipOutcome.selectedInfo != null) {
        String oid = chipOutcome.selectedInfo.getObjectIdentifier();
        if (oid != null) {
          try {
            cipher = ChipAuthenticationInfo.toCipherAlgorithm(oid);
          } catch (Exception ignore) {
            cipher = null;
          }
        }
      }
      if (cipher != null) {
        String normalized = cipher.toUpperCase(Locale.ROOT);
        if (normalized.contains("AES")) {
          return "CA_AES";
        }
        if (normalized.contains("DESEDE") || normalized.contains("DES")) {
          return "CA_3DES";
        }
      }
      return "CA";
    }
    if (paceOutcome != null && paceOutcome.established) {
      return "PACE";
    }
    return "BAC";
  }

  private static boolean hasText(String value) {
    return value != null && !value.isEmpty();
  }

  private static boolean containsLifecycleTarget(List<String> lifecycleTargets, String target) {
    if (lifecycleTargets == null || lifecycleTargets.isEmpty() || target == null) {
      return false;
    }
    for (String candidate : lifecycleTargets) {
      if (candidate != null && candidate.equalsIgnoreCase(target)) {
        return true;
      }
    }
    return false;
  }
}
