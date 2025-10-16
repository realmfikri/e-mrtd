package emu;

import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.ChipAuthenticationInfo;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.TerminalAuthenticationInfo;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG14File;
import org.jmrtd.lds.icao.MRZInfo;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

import emu.PersonalizationSupport.SODArtifacts;

import net.sf.scuba.data.Gender;

import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationField;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

import sos.passportapplet.PassportCrypto;
import sos.passportapplet.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

class Module11SecurityProfilesTest {

  @Test
  void cardAccessPublishesExpectedPaceProfiles() throws Exception {
    SODArtifacts artifacts = buildArtifacts();

    CardAccessFile cardAccess = new CardAccessFile(new ByteArrayInputStream(artifacts.cardAccessBytes));
    Collection<SecurityInfo> infos = cardAccess.getSecurityInfos();
    Set<String> paceOids = infos.stream()
        .filter(info -> info instanceof PACEInfo)
        .map(SecurityInfo::getObjectIdentifier)
        .collect(Collectors.toSet());

    assertTrue(paceOids.contains(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128),
        "GM AES PACE profile must be advertised");
    assertTrue(paceOids.contains(SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128),
        "IM AES PACE profile must be advertised");
    assertTrue(paceOids.contains(SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC),
        "GM 3DES PACE profile must be advertised");
    assertTrue(paceOids.contains(SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC),
        "IM 3DES PACE profile must be advertised");
  }

  @Test
  void dg14AdvertisesChipAuthenticationVariantsAndTerminalReference() throws Exception {
    SODArtifacts artifacts = buildArtifacts();

    DG14File dg14 = new DG14File(new ByteArrayInputStream(artifacts.dg14Bytes));
    Set<String> chipOids = dg14.getChipAuthenticationInfos().stream()
        .map(SecurityInfo::getObjectIdentifier)
        .collect(Collectors.toSet());

    assertTrue(chipOids.contains(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128),
        "DG14 must include CA AES-128 info");
    assertTrue(chipOids.contains(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192),
        "DG14 must include CA AES-192 info");
    assertTrue(chipOids.contains(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256),
        "DG14 must include CA AES-256 info");
    assertTrue(chipOids.contains(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC),
        "DG14 must include CA 3DES info");

    assertEquals(1, dg14.getTerminalAuthenticationInfos().size(),
        "DG14 should contain a single TerminalAuthenticationInfo entry");
    TerminalAuthenticationInfo taInfo = dg14.getTerminalAuthenticationInfos().get(0);
    assertEquals(0x011C, taInfo.getFileId(), "TA info must reference EF.CVCA");
    assertEquals((byte) 0x1C, taInfo.getShortFileId(), "TA info must reference EF.CVCA SFI");
  }

  @Test
  void configureChipAuthenticationSupportsAesAndDesede() throws Exception {
    PassportCrypto crypto = new PassportCrypto(createKeyStore());

    String aes256 = ChipAuthenticationInfo.toCipherAlgorithm(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256);
    int aes256Length = ChipAuthenticationInfo.toKeyLength(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256);
    crypto.configureChipAuthentication(aes256, aes256Length);
    assertEquals(aes256, crypto.getChipAuthCipherAlgorithm(), "AES cipher must be retained");
    assertEquals(aes256Length, crypto.getChipAuthKeyLength(), "AES key length must be preserved");

    String aes192 = ChipAuthenticationInfo.toCipherAlgorithm(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192);
    int aes192Length = ChipAuthenticationInfo.toKeyLength(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192);
    crypto.configureChipAuthentication(aes192, aes192Length);
    assertEquals(aes192, crypto.getChipAuthCipherAlgorithm(), "AES cipher must be retained");
    assertEquals(aes192Length, crypto.getChipAuthKeyLength(), "AES key length must be preserved");

    String desCipher = ChipAuthenticationInfo.toCipherAlgorithm(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC);
    int desLength = ChipAuthenticationInfo.toKeyLength(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC);
    crypto.configureChipAuthentication(desCipher, desLength);
    assertEquals("DESede", crypto.getChipAuthCipherAlgorithm(), "3DES cipher must downgrade to DESede helper");
    assertEquals(128, crypto.getChipAuthKeyLength(), "3DES sessions must use 128-bit keys");
  }

  @Test
  void generateDemoTaChainRespectsRequestedRightsAndValidity() throws Exception {
    Path outputDir = Files.createTempDirectory("ta-demo-");
    int validityDays = 5;
    AccessRightEnum requestedRights = AccessRightEnum.READ_ACCESS_DG4;

    GenerateDemoTaChainMain.main(new String[]{
        "--out-dir", outputDir.toString(),
        "--validity-days", Integer.toString(validityDays),
        "--rights", "DG4"
    });

    CVCertificate terminalCert = CertificateParser.parseCertificate(Files.readAllBytes(outputDir.resolve("terminal.cvc")));
    CVCAuthorizationTemplate terminalTemplate = terminalCert.getCertificateBody().getAuthorizationTemplate();
    AuthorizationField terminalAuth = terminalTemplate.getAuthorizationField();
    assertEquals(AuthorizationRoleEnum.IS, terminalAuth.getRole(), "Terminal certificate must declare IS role");
    assertEquals(requestedRights, terminalAuth.getAccessRight(), "Terminal certificate must reflect requested rights");

    Date validFrom = terminalCert.getCertificateBody().getValidFrom();
    Date validTo = terminalCert.getCertificateBody().getValidTo();
    long deltaDays = ChronoUnit.DAYS.between(validFrom.toInstant(), validTo.toInstant());
    assertTrue(deltaDays >= validityDays - 1 && deltaDays <= validityDays,
        "Terminal validity period must match requested duration");

    CVCertificate cvcaCert = CertificateParser.parseCertificate(Files.readAllBytes(outputDir.resolve("cvca.cvc")));
    CVCAuthorizationTemplate cvcaTemplate = cvcaCert.getCertificateBody().getAuthorizationTemplate();
    AuthorizationField cvcaAuth = cvcaTemplate.getAuthorizationField();
    assertEquals(AuthorizationRoleEnum.CVCA, cvcaAuth.getRole(), "CVCA certificate must declare CVCA role");
    assertEquals(AccessRightEnum.READ_ACCESS_DG3_AND_DG4, cvcaAuth.getAccessRight(),
        "CVCA certificate must retain DG3/DG4 rights");
  }

  private static SODArtifacts buildArtifacts() throws Exception {
    MRZInfo mrz = new MRZInfo(
        "P<",
        "UTO",
        "BEAN",
        "HAPPY",
        TestCardManager.DEFAULT_DOC,
        "UTO",
        TestCardManager.DEFAULT_DOB,
        Gender.MALE,
        TestCardManager.DEFAULT_DOE,
        "");
    DG1File dg1 = new DG1File(mrz);
    return PersonalizationSupport.buildArtifacts(dg1.getEncoded(), 480, 600, false);
  }

  private static KeyStore createKeyStore() throws Exception {
    java.lang.reflect.Constructor<KeyStore> ctor = KeyStore.class.getDeclaredConstructor(byte.class);
    ctor.setAccessible(true);
    return ctor.newInstance(PassportCrypto.PERFECTWORLD_MODE);
  }
}
