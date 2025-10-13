package emu;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG15File;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

final class PersonalizationSupport {

  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private PersonalizationSupport() {
  }

  static SODArtifacts buildSOD(byte[] dg1Bytes) throws GeneralSecurityException, OperatorCreationException, CertIOException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    SecureRandom random = new SecureRandom();

    KeyPair cscaPair = kpg.generateKeyPair();
    KeyPair docSignerPair = kpg.generateKeyPair();

    Date notBefore = new Date(System.currentTimeMillis() - 24L * 60 * 60 * 1000);
    Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

    X509Certificate cscaCert = createCertificate(
        "CN=CSCA Emulator,OU=Emu,O=JMRTD,L=Sample,C=UT",
        "CN=CSCA Emulator,OU=Emu,O=JMRTD,L=Sample,C=UT",
        cscaPair.getPublic(),
        cscaPair.getPrivate(),
        true,
        notBefore,
        notAfter,
        random);

    X509Certificate docSignerCert = createCertificate(
        "CN=DSC Emulator,OU=Emu,O=JMRTD,L=Sample,C=UT",
        "CN=CSCA Emulator,OU=Emu,O=JMRTD,L=Sample,C=UT",
        docSignerPair.getPublic(),
        cscaPair.getPrivate(),
        false,
        notBefore,
        new Date(System.currentTimeMillis() + 180L * 24 * 60 * 60 * 1000),
        random);

    DG15File dg15File = new DG15File(docSignerPair.getPublic());
    byte[] dg15Bytes = dg15File.getEncoded();

    Map<Integer, byte[]> hashes = new HashMap<>();
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    hashes.put(Integer.valueOf(1), md.digest(dg1Bytes));
    hashes.put(Integer.valueOf(15), md.digest(dg15Bytes));

    SODFile sodFile = new SODFile("SHA-256", SIGNATURE_ALGORITHM, hashes, docSignerPair.getPrivate(), docSignerCert);
    if (sodFile.getDocSigningCertificate() == null) {
      throw new IllegalStateException("Generated SOD without signer certificate");
    }
    byte[] sodBytes = sodFile.getEncoded();

    return new SODArtifacts(sodBytes, dg15Bytes, cscaCert, docSignerCert);
  }

  private static X509Certificate createCertificate(String subject,
                                                    String issuer,
                                                    java.security.PublicKey subjectPublicKey,
                                                    PrivateKey signingKey,
                                                    boolean isCA,
                                                    Date notBefore,
                                                    Date notAfter,
                                                    SecureRandom random) throws GeneralSecurityException, OperatorCreationException, CertIOException {
    X500Name subjectName = new X500Name(subject);
    X500Name issuerName = new X500Name(issuer);

    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        issuerName,
        new java.math.BigInteger(160, random),
        notBefore,
        notAfter,
        subjectName,
        subjectPublicKey);

    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
    if (isCA) {
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    } else {
      builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    }

    JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
        .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    X509CertificateHolder holder = builder.build(signerBuilder.build(signingKey));

    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(holder);
  }

  static final class SODArtifacts {
    final byte[] sodBytes;
    final byte[] dg15Bytes;
    final X509Certificate cscaCert;
    final X509Certificate docSignerCert;

    SODArtifacts(byte[] sodBytes, byte[] dg15Bytes, X509Certificate cscaCert, X509Certificate docSignerCert) {
      this.sodBytes = sodBytes;
      this.dg15Bytes = dg15Bytes;
      this.cscaCert = cscaCert;
      this.docSignerCert = docSignerCert;
    }
  }
}
