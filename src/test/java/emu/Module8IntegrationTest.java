package emu;

import net.sf.scuba.smartcards.CommandAPDU;
import net.sf.scuba.smartcards.ResponseAPDU;
import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.PassportService;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG15File;
import org.jmrtd.protocol.AAResult;
import org.jmrtd.protocol.BACResult;
import org.jmrtd.protocol.PACEResult;
import org.jmrtd.protocol.SecureMessagingWrapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.List;

import emu.PassiveAuthentication.Result;
import emu.PassiveAuthentication.ChainValidation;

import static org.junit.jupiter.api.Assertions.*;

class Module8IntegrationTest {

  private static final byte[] MRTD_AID = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

  private TestCardManager.TestCard card;

  @BeforeEach
  void setUp() throws Exception {
    card = TestCardManager.provisionCard();
  }

  @AfterEach
  void tearDown() {
    if (card != null) {
      card.close();
    }
  }

  @Test
  void bacFlowAllowsReadingDg1() throws Exception {
    PassportService service = card.passportService;
    BACResult bac = service.doBAC(card.bacKey);
    assertNotNull(bac.getWrapper(), "BAC should produce secure messaging wrapper");

    byte[] dg1 = readFile(service, PassportService.EF_DG1);
    assertArrayEquals(card.dg1Bytes, dg1, "DG1 contents should match personalization");
  }

  @Test
  void paceFlowEstablishesSecureMessaging() throws Exception {
    PassportService service = card.passportService;
    PACEInfo paceInfo = new PACEInfo(
        SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        2,
        PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    AlgorithmParameterSpec paramSpec = PACEInfo.toParameterSpec(paceInfo.getParameterId());

    PACEResult paceResult = service.doPACE(
        org.jmrtd.PACEKeySpec.createMRZKey(card.bacKey),
        paceInfo.getObjectIdentifier(),
        paramSpec,
        paceInfo.getParameterId());

    assertNotNull(paceResult, "PACE result should not be null");
    assertNotNull(paceResult.getWrapper(), "PACE should establish secure messaging");

    byte[] dg1 = readFile(service, PassportService.EF_DG1);
    assertNotNull(dg1);
    assertTrue(dg1.length > 0, "DG1 must be readable after PACE");
  }

  @Test
  void passiveAuthenticationDetectsHashMismatch() throws Exception {
    card.close();
    card = TestCardManager.provisionCard(true);
    PassportService service = card.passportService;

    service.doBAC(card.bacKey);

    Path trustDir = Files.createTempDirectory("trust-store");
    Files.write(trustDir.resolve("csca.cer"), card.artifacts.getCscaCert().getEncoded());

    Result result = PassiveAuthentication.verify(service, trustDir, null);
    assertFalse(result.isPass(), "Passive authentication must fail after tampering");
    assertTrue(result.getBadDataGroups().contains(1), "DG1 should be flagged as bad");
  }

  @Test
  void passiveAuthenticationFailsWithoutTrustAnchors() throws Exception {
    PassportService service = card.passportService;
    service.doBAC(card.bacKey);

    Result result = PassiveAuthentication.verify(service, (Path) null, null);
    ChainValidation chain = result.getChainValidation();
    assertNotNull(chain);
    assertFalse(chain.chainOk, "Chain validation must fail without trust anchors");
    assertFalse(result.isPass(), "Overall verdict must be failure");
  }

  @Test
  void passiveAuthenticationAcceptsMasterListDirectory() throws Exception {
    PassportService service = card.passportService;
    service.doBAC(card.bacKey);

    Path masterListDir = Files.createTempDirectory("master-list");
    Files.write(masterListDir.resolve("csca.cer"), card.artifacts.getCscaCert().getEncoded());
    Files.write(masterListDir.resolve("docsigner.cer"), card.artifacts.getDocSignerCert().getEncoded());

    List<Path> masterList = List.of(masterListDir);
    Result result = PassiveAuthentication.verify(service, masterList, null);
    assertTrue(result.getChainValidation().chainOk, "Chain validation should succeed with master list directory");
    assertTrue(result.getSignatureCheck().valid, "SOD signature should validate with trust anchor");
    assertTrue(result.getOkDataGroups().containsAll(List.of(1, 2)),
        "DG1/DG2 should be hashed successfully");
    assertTrue(result.getLockedDataGroups().containsAll(List.of(3, 4, 14, 15)),
        "DG3/DG4/DG14/DG15 should be reported as locked without TA");
    assertTrue(result.getMissingDataGroups().isEmpty(),
        "Locked DGs must not be treated as missing");
    assertTrue(result.isPass(), "Locked DGs should not cause PA to fail");
  }

  @Test
  void activeAuthenticationVerifiesSignature() throws Exception {
    PassportService service = card.passportService;
    service.doBAC(card.bacKey);

    byte[] dg15Bytes = readFile(service, PassportService.EF_DG15);
    DG15File dg15 = new DG15File(new java.io.ByteArrayInputStream(dg15Bytes));
    PublicKey publicKey = dg15.getPublicKey();
    assertNotNull(publicKey);

    byte[] challenge = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    AAResult result = service.doAA(publicKey, "SHA-1", "SHA1withRSA", challenge);
    assertNotNull(result);
    byte[] response = result.getResponse();
    assertNotNull(response);
    assertTrue(response.length > 0);

    assertTrue(verifyActiveAuthenticationSignature(publicKey, challenge, response),
        "AA signature must validate with original challenge");

    byte[] wrongChallenge = challenge.clone();
    wrongChallenge[0] ^= 0x10;
    assertFalse(verifyActiveAuthenticationSignature(publicKey, wrongChallenge, response),
        "AA verification must fail for a mismatched challenge");
  }

  @Test
  void dg15PublishesActiveAuthenticationKey() throws Exception {
    PassportService service = card.passportService;
    service.doBAC(card.bacKey);

    byte[] dg15Bytes = readFile(service, PassportService.EF_DG15);
    DG15File dg15 = new DG15File(new java.io.ByteArrayInputStream(dg15Bytes));
    PublicKey dg15Key = dg15.getPublicKey();
    assertNotNull(dg15Key, "DG15 must expose a public key");

    byte[] expectedAA = card.artifacts.getAaKeyPair().getPublic().getEncoded();
    assertArrayEquals(expectedAA, dg15Key.getEncoded(), "DG15 should publish the AA key");

    byte[] docSignerKey = card.artifacts.getDocSignerKeyPair().getPublic().getEncoded();
    assertFalse(Arrays.equals(docSignerKey, dg15Key.getEncoded()),
        "DG15 must not reuse the document signer key");
  }

  @Test
  void secureMessagingRejectsReplay() throws Exception {
    PassportService service = card.passportService;
    TerminalCardService raw = card.terminalService;

    PACEInfo paceInfo = new PACEInfo(
        SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        2,
        PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
    PACEResult pace = service.doPACE(
        org.jmrtd.PACEKeySpec.createMRZKey(card.bacKey),
        paceInfo.getObjectIdentifier(),
        PACEInfo.toParameterSpec(paceInfo.getParameterId()),
        paceInfo.getParameterId());
    SecureMessagingWrapper wrapper = pace.getWrapper();
    assertNotNull(wrapper);

    CommandAPDU readPlain = new CommandAPDU(0x0C, 0xB0, 0x00, 0x00, 16);
    CommandAPDU wrapped = wrapper.wrap(readPlain);

    ResponseAPDU first = raw.transmit(wrapped);
    assertEquals(0x9000, first.getSW());
    wrapper.unwrap(first);

    ResponseAPDU replay = raw.transmit(wrapped);
    assertNotEquals(0x9000, replay.getSW(), "Replayed command must be rejected");
  }

  private static byte[] readFile(PassportService service, short fid) throws Exception {
    try (InputStream in = service.getInputStream(fid); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      if (in == null) {
        return new byte[0];
      }
      byte[] buffer = new byte[256];
      int read;
      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
      }
      return out.toByteArray();
    }
  }

  private static boolean verifyActiveAuthenticationSignature(PublicKey key, byte[] challenge, byte[] response)
      throws GeneralSecurityException {
    if (!(key instanceof RSAPublicKey)) {
      throw new GeneralSecurityException("Unsupported AA key algorithm: " + key.getAlgorithm());
    }
    if (response == null || response.length == 0) {
      return false;
    }

    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding");
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
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

    int m1Length = digestOffset - 1; // exclude header byte
    if (m1Length < 0) {
      return false;
    }

    byte[] digest = new byte[digestLength];
    System.arraycopy(plain, digestOffset, digest, 0, digestLength);

    byte[] m1m2 = new byte[m1Length + challenge.length];
    // m1 is zero-filled by the applet implementation
    System.arraycopy(challenge, 0, m1m2, m1Length, challenge.length);

    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
    byte[] expected = md.digest(m1m2);
    return java.util.Arrays.equals(digest, expected);
  }
}
