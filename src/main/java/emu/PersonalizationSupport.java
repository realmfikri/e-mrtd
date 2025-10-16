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
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.TerminalAuthenticationInfo;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.DG3File;
import org.jmrtd.lds.icao.DG4File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso19794.FingerImageInfo;
import org.jmrtd.lds.iso19794.FingerInfo;
import org.jmrtd.lds.iso19794.IrisBiometricSubtypeInfo;
import org.jmrtd.lds.iso19794.IrisImageInfo;
import org.jmrtd.lds.iso19794.IrisInfo;

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
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.math.BigInteger;

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
    SecureRandom random = new SecureRandom();

    KeyPairGenerator cscaGenerator = KeyPairGenerator.getInstance("RSA");
    cscaGenerator.initialize(2048, random);
    KeyPair cscaPair = cscaGenerator.generateKeyPair();

    KeyPairGenerator docSignerGenerator = KeyPairGenerator.getInstance("RSA");
    docSignerGenerator.initialize(2048, random);
    KeyPair docSignerPair = docSignerGenerator.generateKeyPair();

    KeyPairGenerator aaGenerator = KeyPairGenerator.getInstance("RSA");
    aaGenerator.initialize(1024, random);
    KeyPair aaKeyPair = aaGenerator.generateKeyPair();
    if (Arrays.equals(docSignerPair.getPublic().getEncoded(), aaKeyPair.getPublic().getEncoded())) {
      throw new IllegalStateException("AA key pair must differ from document signer key pair");
    }
    KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
    ecGenerator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair chipAuthKeyPair = ecGenerator.generateKeyPair();

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

    DG15File dg15File = new DG15File(aaKeyPair.getPublic());
    byte[] dg15Bytes = dg15File.getEncoded();

    List<SecurityInfo> paceInfos = new ArrayList<>();
    paceInfos.add(new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1));
    paceInfos.add(new PACEInfo(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1));
    paceInfos.add(new PACEInfo(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1));
    paceInfos.add(new PACEInfo(SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC, 2, PACEInfo.PARAM_ID_ECP_NIST_P256_R1));
    CardAccessFile cardAccessFile = new CardAccessFile(paceInfos);
    byte[] cardAccessBytes = cardAccessFile.getEncoded();

    List<SecurityInfo> dg14Infos = new ArrayList<>();
    BigInteger chipKeyId = BigInteger.ONE;
    dg14Infos.add(new ChipAuthenticationPublicKeyInfo(chipAuthKeyPair.getPublic(), chipKeyId));
    dg14Infos.add(new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128, 2, chipKeyId));
    dg14Infos.add(new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192, 2, chipKeyId));
    dg14Infos.add(new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256, 2, chipKeyId));
    dg14Infos.add(new ChipAuthenticationInfo(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC, 2, chipKeyId));
    dg14Infos.add(new TerminalAuthenticationInfo((short) 0x011C, (byte) 0x1C));
    DG14File dg14File = new DG14File(dg14Infos);
    byte[] dg14Bytes = dg14File.getEncoded();

    byte[] dg3Bytes = buildDemoDG3();
    byte[] dg4Bytes = buildDemoDG4();

    if (corruptDG2) {
      dg2Bytes = corrupt(dg2Bytes);
    }

    Map<Integer, byte[]> hashes = new HashMap<>();
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    hashes.put(Integer.valueOf(1), md.digest(dg1Bytes));
    hashes.put(Integer.valueOf(2), md.digest(dg2Bytes));
    hashes.put(Integer.valueOf(3), md.digest(dg3Bytes));
    hashes.put(Integer.valueOf(4), md.digest(dg4Bytes));
    hashes.put(Integer.valueOf(14), md.digest(dg14Bytes));
    hashes.put(Integer.valueOf(15), md.digest(dg15Bytes));

    SODFile sodFile = new SODFile("SHA-256", SIGNATURE_ALGORITHM, hashes, docSignerPair.getPrivate(), docSignerCert);
    byte[] sodBytes = sodFile.getEncoded();

    return new SODArtifacts(
        sodBytes,
        dg2Bytes,
        dg3Bytes,
        dg4Bytes,
        dg15Bytes,
        dg14Bytes,
        cardAccessBytes,
        chipAuthKeyPair,
        aaKeyPair,
        docSignerPair,
        cscaCert,
        docSignerCert);
  }

  private static byte[] buildDemoDG3() throws IOException {
    int width = 160;
    int height = 160;
    byte[] fingerprintPixels = createFingerprintPixels(width, height);

    FingerImageInfo fingerImage = new FingerImageInfo(
        FingerImageInfo.POSITION_RIGHT_INDEX_FINGER,
        1,
        1,
        80,
        FingerImageInfo.IMPRESSION_TYPE_LIVE_SCAN_PLAIN,
        width,
        height,
        new ByteArrayInputStream(fingerprintPixels),
        fingerprintPixels.length,
        FingerInfo.COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING);

    FingerInfo fingerInfo = new FingerInfo(
        1,
        31,
        FingerInfo.SCALE_UNITS_PPI,
        500,
        500,
        500,
        500,
        8,
        FingerInfo.COMPRESSION_UNCOMPRESSED_NO_BIT_PACKING,
        Collections.singletonList(fingerImage));

    DG3File dg3File = new DG3File(Collections.singletonList(fingerInfo));
    return dg3File.getEncoded();
  }

  private static byte[] buildDemoDG4() throws IOException {
    int width = 160;
    int height = 160;
    byte[] irisPixels = createIrisPixels(width, height);

    IrisImageInfo irisImage = new IrisImageInfo(
        1,
        IrisImageInfo.IMAGE_QUAL_MED_HI,
        0,
        0,
        width,
        height,
        new ByteArrayInputStream(irisPixels),
        irisPixels.length,
        IrisInfo.IMAGEFORMAT_MONO_RAW);

    IrisBiometricSubtypeInfo subtype = new IrisBiometricSubtypeInfo(
        IrisBiometricSubtypeInfo.EYE_RIGHT,
        IrisInfo.IMAGEFORMAT_MONO_RAW,
        Collections.singletonList(irisImage));

    byte[] deviceId = new byte[16];
    for (int i = 0; i < deviceId.length; i++) {
      deviceId[i] = (byte) (0xA0 + i);
    }

    IrisInfo irisInfo = new IrisInfo(
        1,
        IrisInfo.ORIENTATION_BASE,
        IrisInfo.ORIENTATION_BASE,
        IrisInfo.SCAN_TYPE_PROGRESSIVE,
        IrisInfo.IROCC_PROCESSED,
        IrisInfo.IROC_UNITFILL,
        IrisInfo.IRBNDY_PROCESSED,
        220,
        IrisInfo.IMAGEFORMAT_MONO_RAW,
        width,
        height,
        8,
        IrisInfo.TRANS_STD,
        deviceId,
        Collections.singletonList(subtype));

    DG4File dg4File = new DG4File(Collections.singletonList(irisInfo));
    return dg4File.getEncoded();
  }

  private static byte[] createFingerprintPixels(int width, int height) {
    byte[] pixels = new byte[width * height];
    for (int y = 0; y < height; y++) {
      for (int x = 0; x < width; x++) {
        int index = y * width + x;
        int ridge = (int) ((Math.sin((x + y) / 12.0) + 1.0) * 120.0);
        int swirl = (int) ((Math.cos((x - y) / 18.0) + 1.0) * 60.0);
        int value = Math.min(255, ridge + swirl);
        pixels[index] = (byte) value;
      }
    }
    return pixels;
  }

  private static byte[] createIrisPixels(int width, int height) {
    byte[] pixels = new byte[width * height];
    double centerX = width / 2.0;
    double centerY = height / 2.0;
    double maxRadius = Math.min(width, height) / 2.0;
    for (int y = 0; y < height; y++) {
      for (int x = 0; x < width; x++) {
        double dx = x - centerX;
        double dy = y - centerY;
        double distance = Math.sqrt(dx * dx + dy * dy);
        double normalized = Math.min(1.0, distance / maxRadius);
        int value = (int) (200 - 140 * normalized + 30 * Math.sin(distance / 4.0));
        pixels[y * width + x] = (byte) Math.max(0, Math.min(255, value));
      }
    }
    return pixels;
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
    final byte[] dg3Bytes;
    final byte[] dg4Bytes;
    final byte[] dg15Bytes;
    final byte[] dg14Bytes;
    final byte[] cardAccessBytes;
    final KeyPair chipAuthKeyPair;
    final KeyPair aaKeyPair;
    final KeyPair docSignerKeyPair;
    final X509Certificate cscaCert;
    final X509Certificate docSignerCert;

    SODArtifacts(byte[] sodBytes,
                 byte[] dg2Bytes,
                 byte[] dg3Bytes,
                 byte[] dg4Bytes,
                 byte[] dg15Bytes,
                 byte[] dg14Bytes,
                 byte[] cardAccessBytes,
                 KeyPair chipAuthKeyPair,
                 KeyPair aaKeyPair,
                 KeyPair docSignerKeyPair,
                 X509Certificate cscaCert,
                 X509Certificate docSignerCert) {
      this.sodBytes = sodBytes;
      this.dg2Bytes = dg2Bytes;
      this.dg3Bytes = dg3Bytes;
      this.dg4Bytes = dg4Bytes;
      this.dg15Bytes = dg15Bytes;
      this.dg14Bytes = dg14Bytes;
      this.cardAccessBytes = cardAccessBytes;
      this.chipAuthKeyPair = chipAuthKeyPair;
      this.aaKeyPair = aaKeyPair;
      this.docSignerKeyPair = docSignerKeyPair;
      this.cscaCert = cscaCert;
      this.docSignerCert = docSignerCert;
    }
  }
}
