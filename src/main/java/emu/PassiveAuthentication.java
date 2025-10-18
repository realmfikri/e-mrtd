package emu;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.jmrtd.PassportService;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.COMFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import net.sf.scuba.smartcards.CardServiceException;

/**
 * Host-side Passive Authentication verifier for the emulator.
 */
public final class PassiveAuthentication {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private PassiveAuthentication() {
  }

  public static Result verify(PassportService service, Path trustStorePath, char[] trustStorePassword) throws Exception {
    List<Path> paths = trustStorePath != null ? List.of(trustStorePath) : Collections.emptyList();
    return verify(service, paths, trustStorePassword);
  }

  public static Result verify(PassportService service, List<Path> trustStorePaths, char[] trustStorePassword) throws Exception {
    FileReadResult sodResult = readFile(service, PassportService.EF_SOD);
    if (sodResult.status != FileStatus.OK || sodResult.data == null) {
      String issue = sodResult.status == FileStatus.LOCKED ? "EF.SOD locked" : "EF.SOD missing";
      return Result.failed(issue, Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
    }
    byte[] sodBytes = sodResult.data;

    SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
    String digestAlgorithm = normalizeDigestAlgorithm(sod.getDigestAlgorithm());
    Map<Integer, byte[]> expectedHashes = new TreeMap<>(sod.getDataGroupHashes());

    Set<Integer> comTags = readComTagList(service);

    List<Integer> okDataGroups = new ArrayList<>();
    List<Integer> badDataGroups = new ArrayList<>();
    List<Integer> missingDataGroups = new ArrayList<>();
    List<Integer> lockedDataGroups = new ArrayList<>();

    for (Map.Entry<Integer, byte[]> entry : expectedHashes.entrySet()) {
      int dg = entry.getKey();
      FileReadResult dataGroup = readDataGroup(service, dg);
      if (dataGroup.status == FileStatus.LOCKED) {
        lockedDataGroups.add(dg);
        continue;
      }
      if (dataGroup.status != FileStatus.OK || dataGroup.data == null) {
        missingDataGroups.add(dg);
        continue;
      }
      try {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        byte[] digest = md.digest(dataGroup.data);
        if (Arrays.equals(digest, entry.getValue())) {
          okDataGroups.add(dg);
        } else {
          badDataGroups.add(dg);
        }
      } catch (GeneralSecurityException e) {
        badDataGroups.add(dg);
      }
    }

    SignatureCheck signatureCheck = verifySodSignature(sodBytes, sod);

    TrustStore trustStore = loadTrustStores(trustStorePaths, trustStorePassword);

    ChainValidation chainValidation = validateChain(signatureCheck.signerCertificate, sod.getDocSigningCertificates(), trustStore);

    boolean pass = signatureCheck.valid
        && badDataGroups.isEmpty()
        && missingDataGroups.isEmpty()
        && chainValidation.chainOk;

    return new Result(digestAlgorithm,
        Collections.unmodifiableList(okDataGroups),
        Collections.unmodifiableList(badDataGroups),
        Collections.unmodifiableList(missingDataGroups),
        Collections.unmodifiableList(lockedDataGroups),
        signatureCheck,
        chainValidation,
        comTags,
        trustStore.issues,
        pass);
  }

  private static FileReadResult readFile(PassportService service, short fid) throws IOException {
    try {
      InputStream raw = service.getInputStream(fid);
      if (raw == null) {
        return FileReadResult.missing();
      }
      try (InputStream in = raw; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        byte[] buf = new byte[256];
        int r;
        while (true) {
          try {
            r = in.read(buf);
          } catch (IOException io) {
            CardServiceException cardError = findCardServiceException(io);
            if (cardError != null) {
              if (isSecurityStatusError(cardError)) {
                return FileReadResult.locked();
              }
              return FileReadResult.missing();
            }
            throw io;
          }
          if (r == -1) {
            break;
          }
          out.write(buf, 0, r);
        }
        return FileReadResult.ok(out.toByteArray());
      }
    } catch (CardServiceException e) {
      if (isSecurityStatusError(e)) {
        return FileReadResult.locked();
      }
      return FileReadResult.missing();
    }
  }

  private static Set<Integer> readComTagList(PassportService service) {
    try {
      FileReadResult comResult = readFile(service, PassportService.EF_COM);
      if (comResult.status != FileStatus.OK || comResult.data == null) {
        return Collections.emptySet();
      }
      COMFile com = new COMFile(new ByteArrayInputStream(comResult.data));
      int[] tags = com.getTagList();
      Set<Integer> tagSet = new TreeSet<>();
      if (tags != null) {
        for (int tag : tags) {
          tagSet.add(tag);
        }
      }
      return tagSet;
    } catch (Exception e) {
      return Collections.emptySet();
    }
  }

  private static FileReadResult readDataGroup(PassportService service, int dataGroup) {
    short fid = (short) (0x0100 | (dataGroup & 0xFF));
    try {
      return readFile(service, fid);
    } catch (Exception e) {
      return FileReadResult.missing();
    }
  }

  private static boolean isSecurityStatusError(CardServiceException e) {
    int sw = e.getSW();
    if (sw == 0x6982 || sw == 0x6985 || sw == 0x6988) {
      return true;
    }
    if (sw == CardServiceException.SW_NONE) {
      String message = e.getMessage();
      if (message != null) {
        String lower = message.toLowerCase(Locale.ROOT);
        return lower.contains("access to file denied")
            || lower.contains("security status")
            || lower.contains("no response apdu");
      }
    }
    return false;
  }

  private static CardServiceException findCardServiceException(Throwable throwable) {
    Throwable current = throwable;
    while (current != null) {
      if (current instanceof CardServiceException) {
        return (CardServiceException) current;
      }
      current = current.getCause();
    }
    return null;
  }

  private enum FileStatus {
    OK,
    MISSING,
    LOCKED
  }

  private static final class FileReadResult {
    final FileStatus status;
    final byte[] data;

    private FileReadResult(FileStatus status, byte[] data) {
      this.status = status;
      this.data = data;
    }

    static FileReadResult ok(byte[] data) {
      return new FileReadResult(FileStatus.OK, data);
    }

    static FileReadResult missing() {
      return new FileReadResult(FileStatus.MISSING, null);
    }

    static FileReadResult locked() {
      return new FileReadResult(FileStatus.LOCKED, null);
    }
  }

  private static String normalizeDigestAlgorithm(String algorithm) {
    if (algorithm == null) {
      return null;
    }
    String trimmed = algorithm.trim();
    String upper = trimmed.toUpperCase(Locale.ROOT);
    switch (upper) {
    case "2.16.840.1.101.3.4.2.1":
    case "SHA256":
      return "SHA-256";
    case "2.16.840.1.101.3.4.2.2":
    case "SHA384":
      return "SHA-384";
    case "2.16.840.1.101.3.4.2.3":
    case "SHA512":
      return "SHA-512";
    case "2.16.840.1.101.3.4.2.4":
    case "SHA224":
      return "SHA-224";
    case "1.3.14.3.2.26":
    case "SHA1":
      return "SHA-1";
    default:
      return trimmed;
    }
  }

  private static SignatureCheck verifySodSignature(byte[] sodBytes, SODFile sodFile) {
    try {
      CMSSignedData cms = new CMSSignedData(extractCmsSignedData(sodBytes));
      SignerInformationStore signers = cms.getSignerInfos();
      if (signers == null || signers.getSigners().isEmpty()) {
        return SignatureCheck.invalid("No signer info");
      }
      SignerInformation signerInformation = signers.getSigners().iterator().next();
      Store<X509CertificateHolder> certStore = cms.getCertificates();
      X509Certificate signerCert = extractSignerCertificate(signerInformation, certStore, sodFile);
      if (signerCert == null) {
        return SignatureCheck.invalid("Signer certificate missing");
      }
      boolean signatureValid = signerInformation.verify(
          new JcaSimpleSignerInfoVerifierBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(signerCert));
      String signerSubject = signerCert.getSubjectX500Principal().getName();
      String signerIssuer = signerCert.getIssuerX500Principal().getName();
      String digestEncryptionAlg = sodFile.getDigestEncryptionAlgorithm();
      String signerInfoDigestAlg = sodFile.getSignerInfoDigestAlgorithm();
      List<String> warnings = new ArrayList<>();
      try {
        signerCert.checkValidity();
      } catch (CertificateException e) {
        warnings.add("Signer certificate not valid at current date: " + e.getMessage());
      }
      return new SignatureCheck(signatureValid, signerSubject, signerIssuer,
          signerCert.getSerialNumber().toString(16), digestEncryptionAlg, signerInfoDigestAlg,
          signerCert, null, warnings);
    } catch (CMSException | GeneralSecurityException | OperatorCreationException e) {
      return SignatureCheck.invalid(e.getMessage());
    }
  }

  private static byte[] extractCmsSignedData(byte[] sodBytes) {
    if (sodBytes == null || sodBytes.length < 2) {
      return sodBytes;
    }
    int tag = sodBytes[0] & 0xFF;
    if (tag != 0x77) {
      return sodBytes;
    }
    int lengthByte = sodBytes[1] & 0xFF;
    int offset;
    int length;
    if ((lengthByte & 0x80) == 0) {
      length = lengthByte;
      offset = 2;
    } else {
      int numBytes = lengthByte & 0x7F;
      offset = 2;
      length = 0;
      for (int i = 0; i < numBytes && offset < sodBytes.length; i++) {
        length = (length << 8) | (sodBytes[offset] & 0xFF);
        offset++;
      }
    }
    if (offset + length > sodBytes.length) {
      return sodBytes;
    }
    return Arrays.copyOfRange(sodBytes, offset, offset + length);
  }

  private static X509Certificate extractSignerCertificate(SignerInformation signerInformation,
                                                         Store<X509CertificateHolder> certStore,
                                                         SODFile sodFile) throws CertificateException {
    Collection<X509CertificateHolder> holders = certStore == null ? Collections.emptyList() : certStore.getMatches(signerInformation.getSID());
    JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
    if (!holders.isEmpty()) {
      return converter.getCertificate(holders.iterator().next());
    }
    X509Certificate fallback = sodFile.getDocSigningCertificate();
    if (fallback != null) {
      return fallback;
    }
    List<X509Certificate> all = sodFile.getDocSigningCertificates();
    if (all != null && !all.isEmpty()) {
      return all.get(0);
    }
    return null;
  }

  private static TrustStore loadTrustStore(Path path, char[] password) {
    if (path == null) {
      return new TrustStore(Collections.emptyList(), Collections.singletonList("Trust store not provided"));
    }
    return loadTrustStores(List.of(path), password);
  }

  private static TrustStore loadTrustStores(List<Path> paths, char[] password) {
    if (paths == null || paths.isEmpty()) {
      return new TrustStore(Collections.emptyList(), Collections.singletonList("Trust store not provided"));
    }
    List<X509Certificate> certificates = new ArrayList<>();
    List<String> issues = new ArrayList<>();
    for (Path path : paths) {
      if (path == null) {
        continue;
      }
      try {
        if (!Files.exists(path)) {
          issues.add("Trust store path not found: " + path);
          continue;
        }
        if (Files.isDirectory(path)) {
          loadDirectoryTrustStore(path, certificates, issues);
        } else {
          String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
          if (fileName.endsWith(".jks") || fileName.endsWith(".keystore")) {
            loadKeyStore(path, "JKS", password, certificates, issues);
          } else if (fileName.endsWith(".p12") || fileName.endsWith(".pfx")) {
            loadKeyStore(path, "PKCS12", password, certificates, issues);
          } else {
            loadCertificateFile(path, certificates, issues);
          }
        }
      } catch (Exception e) {
        issues.add("Failed to load trust store " + path.getFileName() + ": " + e.getMessage());
      }
    }

    validateTrustAnchors(certificates, issues);

    return new TrustStore(Collections.unmodifiableList(certificates), Collections.unmodifiableList(issues));
  }

  private static void loadDirectoryTrustStore(Path dir, List<X509Certificate> certificates, List<String> issues) throws IOException {
    try (var stream = Files.list(dir)) {
      stream.filter(Files::isRegularFile).forEach(path -> {
        try {
          loadCertificateFile(path, certificates, issues);
        } catch (Exception e) {
          issues.add("Failed to load certificate " + path.getFileName() + ": " + e.getMessage());
        }
      });
    }
  }

  private static void loadKeyStore(Path path, String type, char[] password, List<X509Certificate> certificates, List<String> issues)
      throws Exception {
    KeyStore ks = KeyStore.getInstance(type);
    try (InputStream in = Files.newInputStream(path)) {
      ks.load(in, password);
    }
    for (String alias : Collections.list(ks.aliases())) {
      Certificate cert = ks.getCertificate(alias);
      if (cert instanceof X509Certificate) {
        certificates.add((X509Certificate) cert);
      } else {
        issues.add("Skipping non X509 certificate alias " + alias);
      }
    }
  }

  private static void loadCertificateFile(Path path, List<X509Certificate> certificates, List<String> issues)
      throws IOException, CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try (InputStream in = Files.newInputStream(path)) {
      Collection<? extends Certificate> certs = cf.generateCertificates(in);
      for (Certificate cert : certs) {
        if (cert instanceof X509Certificate) {
          certificates.add((X509Certificate) cert);
        } else {
          issues.add("Unsupported certificate type in " + path.getFileName());
        }
      }
    }
  }

  private static void validateTrustAnchors(List<X509Certificate> certificates, List<String> issues) {
    for (X509Certificate cert : certificates) {
      try {
        cert.checkValidity();
      } catch (CertificateException e) {
        issues.add("Trust anchor invalid date: " + cert.getSubjectX500Principal().getName() + " -> " + e.getMessage());
      }
      if (cert.getBasicConstraints() < 0) {
        issues.add("Trust anchor not a CA: " + cert.getSubjectX500Principal().getName());
      }
      boolean[] keyUsage = cert.getKeyUsage();
      if (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5])) {
        issues.add("Trust anchor missing keyCertSign usage: " + cert.getSubjectX500Principal().getName());
      }
    }
  }

  private static ChainValidation validateChain(X509Certificate signerCert,
                                               List<X509Certificate> intermediateCerts,
                                               TrustStore trustStore) {
    if (signerCert == null) {
      return new ChainValidation(false, "Signer certificate missing", Collections.emptyList());
    }
    List<String> issues = new ArrayList<>();
    if (trustStore.certificates.isEmpty()) {
      issues.add("No trust anchors available");
      return new ChainValidation(false, "Missing trust anchors", issues);
    }
    boolean anchorVerified = verifySignerAgainstAnchors(signerCert, trustStore.certificates, issues);
    try {
      Set<TrustAnchor> anchors = new HashSet<>();
      for (X509Certificate cert : trustStore.certificates) {
        anchors.add(new TrustAnchor(cert, null));
      }

      List<X509Certificate> allCerts = new ArrayList<>();
      allCerts.add(signerCert);
      if (intermediateCerts != null) {
        allCerts.addAll(intermediateCerts);
      }

      CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(allCerts));

      X509CertSelector selector = new X509CertSelector();
      selector.setCertificate(signerCert);
      PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, selector);
      params.addCertStore(certStore);
      params.setRevocationEnabled(false);

      CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
      builder.build(params);
      if (!anchorVerified) {
        issues.add("Signer certificate not verified by provided trust anchors");
        return new ChainValidation(false, "Signer not linked to trust anchor", issues);
      }
      return new ChainValidation(true, "Validated", issues);
    } catch (CertPathBuilderException e) {
      issues.add("Cert path builder error: " + e.getMessage());
      return new ChainValidation(false, e.getMessage(), issues);
    } catch (GeneralSecurityException e) {
      issues.add("Cert path validation failure: " + e.getMessage());
      return new ChainValidation(false, e.getMessage(), issues);
    }
  }

  private static boolean verifySignerAgainstAnchors(X509Certificate signerCert,
                                                    List<X509Certificate> anchors,
                                                    List<String> issues) {
    if (anchors == null || anchors.isEmpty()) {
      return false;
    }
    for (X509Certificate anchor : anchors) {
      try {
        signerCert.verify(anchor.getPublicKey());
        issues.add("Signer verified by trust anchor: " + anchor.getSubjectX500Principal().getName());
        return true;
      } catch (GeneralSecurityException e) {
        // continue
      }
    }
    return false;
  }

  public static final class Result {
    private final String digestAlgorithm;
    private final List<Integer> okDataGroups;
    private final List<Integer> badDataGroups;
    private final List<Integer> missingDataGroups;
    private final List<Integer> lockedDataGroups;
    private final SignatureCheck signatureCheck;
    private final ChainValidation chainValidation;
    private final Set<Integer> comTagList;
    private final List<String> trustStoreIssues;
    private final boolean pass;

    Result(String digestAlgorithm,
           List<Integer> okDataGroups,
           List<Integer> badDataGroups,
           List<Integer> missingDataGroups,
           List<Integer> lockedDataGroups,
           SignatureCheck signatureCheck,
           ChainValidation chainValidation,
           Set<Integer> comTagList,
           List<String> trustStoreIssues,
           boolean pass) {
      this.digestAlgorithm = digestAlgorithm;
      this.okDataGroups = okDataGroups;
      this.badDataGroups = badDataGroups;
      this.missingDataGroups = missingDataGroups;
      this.lockedDataGroups = lockedDataGroups;
      this.signatureCheck = signatureCheck;
      this.chainValidation = chainValidation;
      this.comTagList = comTagList;
      this.trustStoreIssues = trustStoreIssues;
      this.pass = pass;
    }

    public String getDigestAlgorithm() {
      return digestAlgorithm;
    }

    public List<Integer> getOkDataGroups() {
      return okDataGroups;
    }

    public List<Integer> getBadDataGroups() {
      return badDataGroups;
    }

    public List<Integer> getMissingDataGroups() {
      return missingDataGroups;
    }

    public List<Integer> getLockedDataGroups() {
      return lockedDataGroups;
    }

    public SignatureCheck getSignatureCheck() {
      return signatureCheck;
    }

    public ChainValidation getChainValidation() {
      return chainValidation;
    }

    public Set<Integer> getComTagList() {
      return comTagList;
    }

    public List<String> getTrustStoreIssues() {
      return trustStoreIssues;
    }

    public boolean isPass() {
      return pass;
    }

    public String verdict() {
      return pass ? "PASS" : "FAIL";
    }

    public void printReport() {
      System.out.println("---- Passive Authentication ----");
      System.out.println("Digest: " + digestAlgorithm);
      System.out.println("DG OK : " + okDataGroups);
      System.out.println("DG BAD: " + badDataGroups);
      System.out.println("DG MISS: " + missingDataGroups);
      System.out.println("DG LOCK: " + lockedDataGroups);
      if (!comTagList.isEmpty()) {
        System.out.println("COM tags: " + comTagList);
      }
      System.out.println("Signature: " + (signatureCheck.valid ? "OK" : "FAIL") +
          " alg=" + signatureCheck.digestEncryptionAlgorithm +
          " digest=" + signatureCheck.signerInfoDigestAlgorithm);
      if (signatureCheck.issue != null) {
        System.out.println("  Info: " + signatureCheck.issue);
      }
      if (!signatureCheck.warnings.isEmpty()) {
        for (String warning : signatureCheck.warnings) {
          System.out.println("  Warning: " + warning);
        }
      }
      System.out.println("Signer: " + signatureCheck.signerSubject);
      System.out.println("Chain : " + (chainValidation.chainOk ? "OK" : "FAIL") + " - " + chainValidation.message);
      for (String issue : chainValidation.issues) {
        if (issue != null && !issue.isEmpty()) {
          System.out.println("  Chain note: " + issue);
        }
      }
      for (String issue : trustStoreIssues) {
        System.out.println("  Trust store: " + issue);
      }
      System.out.println("Verdict: " + verdict());
      System.out.println("--------------------------------");
    }

    static Result failed(String message,
                         List<Integer> ok,
                         List<Integer> bad,
                         List<Integer> missing,
                         List<Integer> locked) {
      SignatureCheck sig = SignatureCheck.invalid(message);
      return new Result("-", ok, bad, missing, locked, sig,
          new ChainValidation(false, message, Collections.emptyList()),
          Collections.emptySet(), Collections.emptyList(), false);
    }
  }

  public static final class SignatureCheck {
    final boolean valid;
    final String signerSubject;
    final String signerIssuer;
    final String signerSerial;
    final String digestEncryptionAlgorithm;
    final String signerInfoDigestAlgorithm;
    final X509Certificate signerCertificate;
    final String issue;
    final List<String> warnings;

    SignatureCheck(boolean valid,
                   String signerSubject,
                   String signerIssuer,
                   String signerSerial,
                   String digestEncryptionAlgorithm,
                   String signerInfoDigestAlgorithm,
                   X509Certificate signerCertificate,
                   String issue,
                   List<String> warnings) {
      this.valid = valid;
      this.signerSubject = signerSubject;
      this.signerIssuer = signerIssuer;
      this.signerSerial = signerSerial;
      this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
      this.signerInfoDigestAlgorithm = signerInfoDigestAlgorithm;
      this.signerCertificate = signerCertificate;
      this.issue = issue;
      this.warnings = warnings;
    }

    static SignatureCheck invalid(String message) {
      return new SignatureCheck(false, "-", "-", "-", "-", "-", null, message, Collections.emptyList());
    }
  }

  public static final class ChainValidation {
    final boolean chainOk;
    final String message;
    final List<String> issues;

    ChainValidation(boolean chainOk, String message, List<String> issues) {
      this.chainOk = chainOk;
      this.message = message;
      this.issues = issues;
    }
  }

  private static final class TrustStore {
    final List<X509Certificate> certificates;
    final List<String> issues;

    TrustStore(List<X509Certificate> certificates, List<String> issues) {
      this.certificates = certificates;
      this.issues = issues;
    }
  }
}
