package emu;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.OIDField;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.cvc.util.BCECUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Generates a synthetic terminal CVC for TA testing.
 */
public final class GenerateDemoCvcMain {

  private static final String DEFAULT_COUNTRY = "UT";
  private static final String DEFAULT_MNEMONIC = "EMRTD";
  private static final String DEFAULT_SEQUENCE = "00001";
  private static final String DEFAULT_OUTPUT = "target/demo-terminal.cvc";
  private static final String DEFAULT_KEY_OUTPUT = "target/demo-terminal.key";
  private static final String SIG_ALGORITHM = "SHA256withECDSA";

  private GenerateDemoCvcMain() {
  }

  public static void main(String[] args) throws Exception {
    ensureProvider();

    Configuration cfg = parseArgs(args);

    KeyPair keyPair = generateKeyPair(cfg);
    CVCertificate certificate = buildCertificate(cfg, keyPair);
    writeOutputs(cfg, certificate, keyPair.getPrivate());

    System.out.printf("Generated CVC at %s (private key: %s)%n",
        cfg.outputPath.toAbsolutePath(),
        cfg.keyOutputPath.toAbsolutePath());
  }

  private static void ensureProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static KeyPair generateKeyPair(Configuration cfg) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(cfg.ecCurve));
    return generator.generateKeyPair();
  }

  private static CVCertificate buildCertificate(Configuration cfg, KeyPair keyPair) throws Exception {
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    OIDField algorithmOid = AlgorithmUtil.getOIDField(SIG_ALGORITHM);
    PublicKeyEC publicKey = new PublicKeyEC(algorithmOid, ecPublicKey, AuthorizationRoleEnum.IS);

    CAReferenceField caRef = new CAReferenceField(cfg.country, cfg.mnemonic, cfg.sequence);
    HolderReferenceField holderRef = new HolderReferenceField(cfg.country, cfg.mnemonic, cfg.sequence);

    Date notBefore = new Date();
    Date notAfter = Date.from(Instant.now().plus(cfg.validityDays, ChronoUnit.DAYS));

    CVCertificateBody body = new CVCertificateBody(
        caRef,
        publicKey,
        holderRef,
        AuthorizationRoleEnum.IS,
        cfg.accessRights,
        notBefore,
        notAfter);

    CVCertificate certificate = new CVCertificate(body);
    byte[] tbs = certificate.getTBS();
    Signature signature = Signature.getInstance(SIG_ALGORITHM);
    signature.initSign(privateKey);
    signature.update(tbs);
    byte[] derSignature = signature.sign();
    byte[] cvcSignature = BCECUtil.convertX962SigToCVC(SIG_ALGORITHM, derSignature);
    certificate.setSignature(cvcSignature);
    return certificate;
  }

  private static void writeOutputs(Configuration cfg, CVCertificate certificate, PrivateKey privateKey) throws Exception {
    Files.createDirectories(cfg.outputPath.getParent());
    Files.write(cfg.outputPath, certificate.getDEREncoded());
    Files.createDirectories(cfg.keyOutputPath.getParent());
    Files.writeString(cfg.keyOutputPath, encodePrivateKeyPem(privateKey), StandardCharsets.UTF_8);
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
      if ("--out".equals(arg)) {
        i = advanceWithValue(argList, i, "--out");
        cfg.outputPath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--out=")) {
        cfg.outputPath = Paths.get(arg.substring("--out=".length()));
      } else if ("--key-out".equals(arg)) {
        i = advanceWithValue(argList, i, "--key-out");
        cfg.keyOutputPath = Paths.get(argList.get(i));
      } else if (arg.startsWith("--key-out=")) {
        cfg.keyOutputPath = Paths.get(arg.substring("--key-out=".length()));
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
      } else if ("--sequence".equals(arg)) {
        i = advanceWithValue(argList, i, "--sequence");
        cfg.sequence = argList.get(i).toUpperCase();
      } else if (arg.startsWith("--sequence=")) {
        cfg.sequence = arg.substring("--sequence=".length()).toUpperCase();
      } else if ("--curve".equals(arg)) {
        i = advanceWithValue(argList, i, "--curve");
        cfg.ecCurve = argList.get(i);
      } else if (arg.startsWith("--curve=")) {
        cfg.ecCurve = arg.substring("--curve=".length());
      } else if ("--validity-days".equals(arg)) {
        i = advanceWithValue(argList, i, "--validity-days");
        cfg.validityDays = Integer.parseInt(argList.get(i));
      } else if (arg.startsWith("--validity-days=")) {
        cfg.validityDays = Integer.parseInt(arg.substring("--validity-days=".length()));
      } else if ("--rights".equals(arg)) {
        i = advanceWithValue(argList, i, "--rights");
        cfg.accessRights = parseRights(argList.get(i));
      } else if (arg.startsWith("--rights=")) {
        cfg.accessRights = parseRights(arg.substring("--rights=".length()));
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
        "Usage: GenerateDemoCvcMain [options]\n" +
        "  --out <path>            Output CVC file (default target/demo-terminal.cvc)\n" +
        "  --key-out <path>        Output PKCS#8 private key PEM (default target/demo-terminal.key)\n" +
        "  --country <alpha-3>     Country code (default UTO)\n" +
        "  --mnemonic <string>     Terminal mnemonic (default EMRTD)\n" +
        "  --sequence <string>     Sequence identifier (default 00001)\n" +
        "  --curve <name>          EC curve (default secp256r1)\n" +
        "  --rights <mode>         Access rights: none|dg3|dg4|dg3_dg4 (default none)\n" +
        "  --validity-days <n>     Validity window (default 365)\n" +
        "  -h, --help              Show this help\n");
    System.exit(0);
  }

  private static final class Configuration {
    Path outputPath = Paths.get(DEFAULT_OUTPUT);
    Path keyOutputPath = Paths.get(DEFAULT_KEY_OUTPUT);
    String country = DEFAULT_COUNTRY;
    String mnemonic = DEFAULT_MNEMONIC;
    String sequence = DEFAULT_SEQUENCE;
    String ecCurve = "secp256r1";
    int validityDays = 365;
    AccessRightEnum accessRights = AccessRightEnum.READ_ACCESS_NONE;
  }
}
