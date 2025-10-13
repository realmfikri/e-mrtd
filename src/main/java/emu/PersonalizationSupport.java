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
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;

import javax.imageio.ImageIO;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
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

  static SODArtifacts buildArtifacts(byte[] dg1Bytes,
                                     int imageWidth,
                                     int imageHeight,
                                     boolean corruptDG2)
      throws GeneralSecurityException, OperatorCreationException, CertIOException, IOException {
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

    byte[] jpegBytes = createSampleFaceImage(imageWidth, imageHeight);

    FaceImageInfo faceImageInfo = new FaceImageInfo(
        net.sf.scuba.data.Gender.UNSPECIFIED,
        null,
        0,
        FaceImageInfo.HAIR_COLOR_UNSPECIFIED,
        FaceImageInfo.EXPRESSION_NEUTRAL,
        new int[]{0, 0, 0},
        new int[]{0, 0, 0},
        FaceImageInfo.FACE_IMAGE_TYPE_FULL_FRONTAL,
        FaceImageInfo.IMAGE_COLOR_SPACE_RGB24,
        FaceImageInfo.SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM,
        0,
        85,
        null,
        imageWidth,
        imageHeight,
        new ByteArrayInputStream(jpegBytes),
        jpegBytes.length,
        FaceImageInfo.IMAGE_DATA_TYPE_JPEG);

    FaceInfo faceInfo = new FaceInfo(Collections.singletonList(faceImageInfo));
    DG2File dg2File = DG2File.createISO19794DG2File(Collections.singletonList(faceInfo));
    byte[] dg2Bytes = dg2File.getEncoded();

    DG15File dg15File = new DG15File(docSignerPair.getPublic());
    byte[] dg15Bytes = dg15File.getEncoded();

    if (corruptDG2) {
      dg2Bytes = corrupt(dg2Bytes);
    }

    Map<Integer, byte[]> hashes = new HashMap<>();
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    hashes.put(Integer.valueOf(1), md.digest(dg1Bytes));
    hashes.put(Integer.valueOf(2), md.digest(dg2Bytes));
    hashes.put(Integer.valueOf(15), md.digest(dg15Bytes));

    SODFile sodFile = new SODFile("SHA-256", SIGNATURE_ALGORITHM, hashes, docSignerPair.getPrivate(), docSignerCert);
    byte[] sodBytes = sodFile.getEncoded();

    return new SODArtifacts(sodBytes, dg2Bytes, dg15Bytes, cscaCert, docSignerCert);
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

  private static byte[] createSampleFaceImage(int width, int height) throws IOException {
    BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
    Graphics2D g2d = image.createGraphics();
    try {
      g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
      g2d.setColor(new Color(208, 224, 245));
      g2d.fillRect(0, 0, width, height);

      int faceSize = Math.min(width, height) * 3 / 4;
      int faceX = (width - faceSize) / 2;
      int faceY = (height - faceSize) / 2;

      g2d.setColor(new Color(255, 221, 188));
      g2d.fill(new Ellipse2D.Double(faceX, faceY, faceSize, faceSize));

      g2d.setColor(new Color(160, 110, 70));
      g2d.fillOval(faceX - faceSize / 10, faceY - faceSize / 6, faceSize + faceSize / 5, faceSize / 3);

      int eyeWidth = faceSize / 6;
      int eyeHeight = faceSize / 8;
      int eyeY = faceY + faceSize / 3;
      int eyeSpacing = faceSize / 5;
      int eyeXLeft = faceX + faceSize / 2 - eyeSpacing - eyeWidth;
      int eyeXRight = faceX + faceSize / 2 + eyeSpacing;

      g2d.setColor(Color.WHITE);
      g2d.fillOval(eyeXLeft, eyeY, eyeWidth, eyeHeight);
      g2d.fillOval(eyeXRight, eyeY, eyeWidth, eyeHeight);

      g2d.setColor(Color.DARK_GRAY);
      g2d.fillOval(eyeXLeft + eyeWidth / 3, eyeY + eyeHeight / 4, eyeHeight / 2, eyeHeight / 2);
      g2d.fillOval(eyeXRight + eyeWidth / 3, eyeY + eyeHeight / 4, eyeHeight / 2, eyeHeight / 2);

      g2d.setColor(new Color(180, 120, 80));
      g2d.setStroke(new BasicStroke(Math.max(2f, faceSize / 40f)));
      int mouthWidth = faceSize / 2;
      int mouthX = faceX + (faceSize - mouthWidth) / 2;
      int mouthY = faceY + (int) (faceSize * 0.7);
      g2d.drawArc(mouthX, mouthY, mouthWidth, faceSize / 5, 0, -160);
    } finally {
      g2d.dispose();
    }

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ImageIO.write(image, "jpg", out);
    return out.toByteArray();
  }

  private static byte[] corrupt(byte[] data) {
    byte[] mutated = data.clone();
    int start = Math.min(mutated.length / 4, 64);
    int end = Math.min(mutated.length, start + 128);
    for (int i = start; i < end; i++) {
      mutated[i] = (byte) 0xFF;
    }
    mutated[0] = 0x00;
    mutated[1] = 0x00;
    return mutated;
  }

  static final class SODArtifacts {
    final byte[] sodBytes;
    final byte[] dg2Bytes;
    final byte[] dg15Bytes;
    final X509Certificate cscaCert;
    final X509Certificate docSignerCert;

    SODArtifacts(byte[] sodBytes,
                 byte[] dg2Bytes,
                 byte[] dg15Bytes,
                 X509Certificate cscaCert,
                 X509Certificate docSignerCert) {
      this.sodBytes = sodBytes;
      this.dg2Bytes = dg2Bytes;
      this.dg15Bytes = dg15Bytes;
      this.cscaCert = cscaCert;
      this.docSignerCert = docSignerCert;
    }
  }
}
