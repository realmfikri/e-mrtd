package emu;

import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.SODFile;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import emu.PersonalizationSupport.SODArtifacts;

import net.sf.scuba.data.Gender;

import static org.junit.jupiter.api.Assertions.*;

class PersonalizationSupportTest {

  @Test
  void excludingDataGroupRemovesItFromComAndSodMap() throws Exception {
    PersonalizationJob job = baseJobBuilder()
        .enableDataGroup(3, false)
        .build();

    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(job);

    List<Integer> comTags = job.getComTagList();
    assertFalse(comTags.contains(LDSFile.EF_DG3_TAG), "COM tag list must omit disabled DG3");
    assertFalse(artifacts.getPresentDataGroupNumbers().contains(3), "Artifacts should not expose DG3 bytes");
    assertFalse(artifacts.getDataGroupHashes().containsKey(3), "SOD hash map must omit DG3");
    assertNull(artifacts.getDg3Bytes(), "DG3 payload should be absent");
  }

  @Test
  void digestSelectionReflectedInArtifacts() throws Exception {
    assertDigestRoundTrip("SHA-384", "SHA384withRSA");
    assertDigestRoundTrip("SHA-512", "SHA512withRSA");
  }

  @Test
  void deterministicSeedProducesRepeatableOutput() throws Exception {
    PersonalizationJob jobA = baseJobBuilder()
        .deterministicSeed(42L)
        .build();
    PersonalizationJob jobB = baseJobBuilder()
        .deterministicSeed(42L)
        .build();

    SODArtifacts artifactsA = PersonalizationSupport.buildArtifacts(jobA);
    SODArtifacts artifactsB = PersonalizationSupport.buildArtifacts(jobB);

    assertArrayEquals(artifactsA.getSodBytes(), artifactsB.getSodBytes(), "SOD bytes must repeat for fixed seed");
    assertArrayEquals(artifactsA.getDg2Bytes(), artifactsB.getDg2Bytes(), "DG2 must be reproducible");
    compareHashMaps(artifactsA.getDataGroupHashes(), artifactsB.getDataGroupHashes());
  }

  private static void assertDigestRoundTrip(String digestAlgorithm, String signatureAlgorithm) throws Exception {
    PersonalizationJob job = baseJobBuilder()
        .digestAlgorithm(digestAlgorithm)
        .signatureAlgorithm(signatureAlgorithm)
        .build();

    SODArtifacts artifacts = PersonalizationSupport.buildArtifacts(job);
    assertEquals(digestAlgorithm, artifacts.getDigestAlgorithm(), "Artifact metadata must record digest selection");
    assertEquals(signatureAlgorithm, artifacts.getSignatureAlgorithm(), "Artifact metadata must record signature selection");

    SODFile sod = new SODFile(new ByteArrayInputStream(artifacts.getSodBytes()));
    assertEquals(digestAlgorithm, sod.getDigestAlgorithm(), "SOD must encode requested digest algorithm");
    assertEquals(signatureAlgorithm, sod.getDigestEncryptionAlgorithm(), "SOD must encode requested signature algorithm");
  }

  private static PersonalizationJob.Builder baseJobBuilder() {
    MRZInfo mrz = new MRZInfo(
        "P<",
        "UTO",
        "TEST",
        "SUBJECT",
        TestCardManager.DEFAULT_DOC,
        "UTO",
        TestCardManager.DEFAULT_DOB,
        Gender.FEMALE,
        TestCardManager.DEFAULT_DOE,
        "");
    return PersonalizationJob.builder().withMrzInfo(mrz);
  }

  private static void compareHashMaps(Map<Integer, byte[]> expected, Map<Integer, byte[]> actual) {
    assertEquals(expected.keySet(), actual.keySet(), "Hash map keys must match");
    for (Integer key : expected.keySet()) {
      byte[] left = expected.get(key);
      byte[] right = actual.get(key);
      assertNotNull(left, "Hash value should be present for DG" + key);
      assertNotNull(right, "Hash value should be present for DG" + key);
      assertTrue(Arrays.equals(left, right), "Hash values must match for DG" + key);
    }
  }
}

