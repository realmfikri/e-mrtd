package emu;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.KeyFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Generates a demo CVCA→Terminal CVC chain for Terminal Authentication tests.
 */
public final class GenerateDemoTaChainMain {

  private static final String DEFAULT_COUNTRY = "UT";
  private static final String DEFAULT_MNEMONIC = "EMRTD";
  private static final String DEFAULT_CVCA_SEQUENCE = "00001";
  private static final String DEFAULT_TERMINAL_SEQUENCE = "00002";
  private static final int DEFAULT_VALIDITY_DAYS = 365;
  private static final int DEFAULT_KEY_SIZE = 2048;
  private static final Path DEFAULT_OUTPUT_DIR = Paths.get("target", "ta-demo");
  private static final String SIG_ALGORITHM = "SHA1withRSA";

  private GenerateDemoTaChainMain() {
  }

  public static void main(String[] args) throws Exception {
    ensureProvider();
    Configuration cfg = parseArgs(args);

    Files.createDirectories(cfg.outputDir);

    KeyPair cvcaKeyPair = generateKeyPair(cfg.keySize);
    KeyPair terminalKeyPair = generateKeyPair(cfg.keySize);

    CVCertificate cvcaCertificate = buildCvcaCertificate(cfg, cvcaKeyPair);
    CVCertificate terminalCertificate = buildTerminalCertificate(cfg, cvcaKeyPair.getPrivate(), terminalKeyPair.getPublic());

    Path cvcaPath = cfg.outputDir.resolve("cvca.cvc");
    Path terminalPath = cfg.outputDir.resolve("terminal.cvc");
    Path terminalKeyPath = cfg.outputDir.resolve("terminal.key");

    Files.write(cvcaPath, cvcaCertificate.getDEREncoded());
    Files.write(terminalPath, terminalCertificate.getDEREncoded());
    Files.writeString(terminalKeyPath, encodePrivateKeyPem(terminalKeyPair.getPrivate()), StandardCharsets.UTF_8);

    System.out.printf("Generated TA demo chain:%n  CVCA: %s%n  Terminal: %s%n  Terminal key: %s%n",
        cvcaPath.toAbsolutePath(),
        terminalPath.toAbsolutePath(),
        terminalKeyPath.toAbsolutePath());
  }

  private static void ensureProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static KeyPair generateKeyPair(int keySize) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keySize);
    return generator.generateKeyPair();
  }

  private static CVCertificate buildCvcaCertificate(Configuration cfg, KeyPair keyPair) throws Exception {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    CAReferenceField caReference = new CAReferenceField(cfg.country, cfg.mnemonic, cfg.cvcaSequence);
    HolderReferenceField holderReference = new HolderReferenceField(cfg.country, cfg.mnemonic, cfg.cvcaSequence);

    Date notBefore = new Date();
    Date notAfter = Date.from(Instant.now().plus(cfg.validityDays, ChronoUnit.DAYS));

    CVCPublicKey cvcPublicKey = KeyFactory.createInstance(publicKey, SIG_ALGORITHM, AuthorizationRoleEnum.CVCA);
    CVCertificateBody body = new CVCertificateBody(
        caReference,
        cvcPublicKey,
        holderReference,
        AuthorizationRoleEnum.CVCA,
        AccessRightEnum.READ_ACCESS_DG3_AND_DG4,
        notBefore,
        notAfter);

    CVCertificate certificate = new CVCertificate(body);
    signCertificate(certificate, privateKey);
    return certificate;
  }

  private static CVCertificate buildTerminalCertificate(
      Configuration cfg,
      PrivateKey signerKey,
      java.security.PublicKey terminalPublicKey) throws Exception {
    RSAPublicKey rsaPublicKey = (RSAPublicKey) terminalPublicKey;

    CAReferenceField caReference = new CAReferenceField(cfg.country, cfg.mnemonic, cfg.cvcaSequence);
    HolderReferenceField holderReference = new HolderReferenceField(cfg.country, cfg.mnemonic, cfg.terminalSequence);

    Date notBefore = new Date();
    Date notAfter = Date.from(Instant.now().plus(cfg.validityDays, ChronoUnit.DAYS));

    CVCPublicKey cvcPublicKey = KeyFactory.createInstance(rsaPublicKey, SIG_ALGORITHM, AuthorizationRoleEnum.IS);
    CVCertificateBody body = new CVCertificateBody(
        caReference,
        cvcPublicKey,
        holderReference,
        AuthorizationRoleEnum.IS,
        cfg.terminalRights,
        notBefore,
        notAfter);

    CVCertificate certificate = new CVCertificate(body);
    signCertificate(certificate, signerKey);
    return certificate;
  }

  private static void signCertificate(CVCertificate certificate, PrivateKey signerKey) throws Exception {
    Signature signature = Signature.getInstance(SIG_ALGORITHM);
    signature.initSign(signerKey);
    signature.update(certificate.getTBS());
    certificate.setSignature(signature.sign());
  }

  private static String encodePrivateKeyPem(PrivateKey privateKey) {
    byte[] pkcs8 = privateKey.getEncoded();
    String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs8);
    return "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n";
  }

  private static Configuration parseArgs(String[] args) {
    Configuration cfg = new Configuration();
    List<String> argList = new ArrayList<>(List.of(args));
    for (int i = 0; i < argList.size(); i++) {
      String arg = argList.get(i);
      if ("--out-dir".equals(arg)) {
        i = advanceWithValue(argList, i, "--out-dir");
        cfg.outputDir = Paths.get(argList.get(i));
      } else if (arg.startsWith("--out-dir=")) {
        cfg.outputDir = Paths.get(arg.substring("--out-dir=".length()));
      } else if ("--country".equals(arg)) {
        i = advanceWithValue(argList, i, "--country");
        cfg.country = argList.get(i).toUpperCase();
      } else if (arg.startsWith("--country=")) {
        cfg.country = arg.substring("--country=".length()).toUpperCase();
      } else if ("--mnemonic".equals(arg)) {
        i = advanceWithValue(argList, i, "--mnemonic");
        cfg.mnemonic = argList.get(i).toUpperCase();
      } else if (arg.startsWith("--mnemonic=")) {
        cfg.mnemonic = arg.substring("--mnemonic=".length()).toUpperCase();
      } else if ("--cvca-seq".equals(arg)) {
        i = advanceWithValue(argList, i, "--cvca-seq");
        cfg.cvcaSequence = argList.get(i).toUpperCase();
      } else if (arg.startsWith("--cvca-seq=")) {
        cfg.cvcaSequence = arg.substring("--cvca-seq=".length()).toUpperCase();
      } else if ("--terminal-seq".equals(arg)) {
        i = advanceWithValue(argList, i, "--terminal-seq");
        cfg.terminalSequence = argList.get(i).toUpperCase();
      } else if (arg.startsWith("--terminal-seq=")) {
        cfg.terminalSequence = arg.substring("--terminal-seq=".length()).toUpperCase();
      } else if ("--validity-days".equals(arg)) {
        i = advanceWithValue(argList, i, "--validity-days");
        cfg.validityDays = Integer.parseInt(argList.get(i));
      } else if (arg.startsWith("--validity-days=")) {
        cfg.validityDays = Integer.parseInt(arg.substring("--validity-days=".length()));
      } else if ("--key-size".equals(arg)) {
        i = advanceWithValue(argList, i, "--key-size");
        cfg.keySize = Integer.parseInt(argList.get(i));
      } else if (arg.startsWith("--key-size=")) {
        cfg.keySize = Integer.parseInt(arg.substring("--key-size=".length()));
      } else if ("--rights".equals(arg)) {
        i = advanceWithValue(argList, i, "--rights");
        cfg.terminalRights = parseRights(argList.get(i));
      } else if (arg.startsWith("--rights=")) {
        cfg.terminalRights = parseRights(arg.substring("--rights=".length()));
      } else if ("--help".equals(arg) || "-h".equals(arg)) {
        printUsageAndExit();
      }
    }
    return cfg;
  }

  private static AccessRightEnum parseRights(String value) {
    String upper = value.toUpperCase();
    if ("DG3".equals(upper)) {
      return AccessRightEnum.READ_ACCESS_DG3;
    }
    if ("DG4".equals(upper)) {
      return AccessRightEnum.READ_ACCESS_DG4;
    }
    if ("DG3_DG4".equals(upper) || "DG3+DG4".equals(upper) || "DG3DG4".equals(upper)) {
      return AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
    }
    return AccessRightEnum.READ_ACCESS_NONE;
  }

  private static int advanceWithValue(List<String> args, int index, String option) {
    int next = index + 1;
    if (next >= args.size()) {
      System.err.println(option + " requires a value");
      printUsageAndExit();
    }
    return next;
  }

  private static void printUsageAndExit() {
    System.out.println(
        "Usage: GenerateDemoTaChainMain [options]\n" +
            "  --out-dir <path>        Output directory (default target/ta-demo)\n" +
            "  --country <alpha-2>     Country code (default UT)\n" +
            "  --mnemonic <alpha-5>    Mnemonic (default EMRTD)\n" +
            "  --cvca-seq <digits>     CVCA sequence number (default 00001)\n" +
            "  --terminal-seq <digits> Terminal sequence number (default 00002)\n" +
            "  --validity-days <n>     Certificate validity in days (default 365)\n" +
            "  --key-size <bits>       RSA key size (default 2048)\n" +
            "  --rights <value>        Terminal access rights (DG3, DG4, DG3_DG4)\n");
    System.exit(0);
  }

  private static final class Configuration {
    Path outputDir = DEFAULT_OUTPUT_DIR;
    String country = DEFAULT_COUNTRY;
    String mnemonic = DEFAULT_MNEMONIC;
    String cvcaSequence = DEFAULT_CVCA_SEQUENCE;
    String terminalSequence = DEFAULT_TERMINAL_SEQUENCE;
    int validityDays = DEFAULT_VALIDITY_DAYS;
    int keySize = DEFAULT_KEY_SIZE;
    AccessRightEnum terminalRights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
  }
}
