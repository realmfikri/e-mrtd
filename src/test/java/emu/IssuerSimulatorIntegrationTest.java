package emu;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.sf.scuba.data.Gender;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.smartcards.TerminalCardService;

import org.jmrtd.BACKey;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.PACEInfo;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class IssuerSimulatorIntegrationTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Test
  void fullLdsLockedOpenReadsPassesPassiveAuthentication() throws Exception {
    MRZInfo mrz = createMrz("123456789");
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .lifecycleTargets(List.of("PERSONALIZED", "LOCKED"))
        .build();

    Path outputDir = Files.createTempDirectory("issuer-full-lds");

    IssuerSimulator.Options options = new IssuerSimulator.Options()
        .outputDirectory(outputDir)
        .openComSodReads(Boolean.TRUE);

    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(job, options);

    try (CardSession session = openSession(result)) {
      PassportService service = session.passportService;
      service.doBAC(toBacKey(mrz));

      Path csca = result.getOutputDirectory().resolve("CSCA.cer");
      PassiveAuthentication.Result pa = PassiveAuthentication.verify(service, List.of(csca), null);
      assertTrue(pa.isPass(), "Passive authentication should pass for full LDS");
      assertTrue(pa.getChainValidation().chainOk, "Signer chain should validate against exported CSCA");
      assertEquals(Set.of(1, 2), Set.copyOf(pa.getOkDataGroups()),
          "DG1 and DG2 should be readable without TA");
      assertEquals(Set.of(3, 4, 14, 15), Set.copyOf(pa.getLockedDataGroups()),
          "Extended access control groups remain locked until TA");
    }

    Map<String, Object> manifest = readManifest(result.getManifestPath());
    assertEquals(List.of("PERSONALIZED", "LOCKED"), manifest.get("lifecycleTargets"));
    assertDataGroups(manifest, 1, 2, 3, 4, 14, 15);
    assertTrue(Files.exists(outputDir.resolve("EF.SOD.bin")), "EF.SOD must be exported");
    assertTrue(Files.exists(outputDir.resolve("CSCA.cer")), "CSCA certificate must be exported");
    assertTrue(Files.exists(outputDir.resolve("DSC.cer")), "DSC certificate must be exported");
  }

  @Test
  void minimalDg1AndDg2StillPassesPassiveAuthentication() throws Exception {
    MRZInfo mrz = createMrz("987654321");
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .enableDataGroup(3, false)
        .enableDataGroup(4, false)
        .enableDataGroup(14, false)
        .enableDataGroup(15, false)
        .lifecycleTargets(List.of("PERSONALIZED"))
        .build();

    Path outputDir = Files.createTempDirectory("issuer-minimal");

    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(job, new IssuerSimulator.Options().outputDirectory(outputDir));

    try (CardSession session = openSession(result)) {
      PassportService service = session.passportService;
      service.doBAC(toBacKey(mrz));

      Path csca = result.getOutputDirectory().resolve("CSCA.cer");
      PassiveAuthentication.Result pa = PassiveAuthentication.verify(service, List.of(csca), null);
      assertTrue(pa.isPass(), "Passive authentication should pass for minimal LDS");
      assertEquals(Set.of(1, 2), Set.copyOf(pa.getOkDataGroups()), "Only DG1 and DG2 should be present");
      assertTrue(pa.getBadDataGroups().isEmpty(), "No data group should fail hashing");
    }

    Map<String, Object> manifest = readManifest(result.getManifestPath());
    assertDataGroups(manifest, 1, 2);
  }

  @Test
  void corruptedDg2TriggersPassiveAuthenticationFailure() throws Exception {
    MRZInfo mrz = createMrz("321654987");
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .corruptDg2(true)
        .lifecycleTargets(List.of("PERSONALIZED", "LOCKED"))
        .build();

    Path outputDir = Files.createTempDirectory("issuer-corrupt-dg2");

    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(job, new IssuerSimulator.Options().outputDirectory(outputDir));

    try (CardSession session = openSession(result)) {
      PassportService service = session.passportService;
      service.doBAC(toBacKey(mrz));

      Path csca = result.getOutputDirectory().resolve("CSCA.cer");
      PassiveAuthentication.Result pa = PassiveAuthentication.verify(service, List.of(csca), null);
      assertFalse(pa.isPass(), "Passive authentication should fail for corrupted DG2");
      assertTrue(pa.getBadDataGroups().contains(2), "DG2 must be flagged as bad");
    }
  }

  @Test
  void missingPaceSecretPreventsPaceButKeepsPaPassing() throws Exception {
    MRZInfo mrz = createMrz("555555555");
    PersonalizationJob job = PersonalizationJob.builder()
        .withMrzInfo(mrz)
        .lifecycleTargets(List.of("PERSONALIZED"))
        .build();

    Path outputDir = Files.createTempDirectory("issuer-missing-pace");

    IssuerSimulator.Options options = new IssuerSimulator.Options()
        .outputDirectory(outputDir)
        .includePaceSecrets(false);

    IssuerSimulator simulator = new IssuerSimulator();
    IssuerSimulator.Result result = simulator.run(job, options);

    try (CardSession session = openSession(result)) {
      PassportService service = session.passportService;
      PACEInfo paceInfo = new PACEInfo(
          SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
          2,
          PACEInfo.PARAM_ID_ECP_NIST_P256_R1);
      AlgorithmParameterSpec params = PACEInfo.toParameterSpec(paceInfo.getParameterId());

      assertThrows(CardServiceException.class, () -> service.doPACE(
          PACEKeySpec.createCANKey("123456"),
          paceInfo.getObjectIdentifier(),
          params,
          paceInfo.getParameterId()),
          "PACE must fail when no CAN secret was installed");

      service.doBAC(toBacKey(mrz));
      Path csca = result.getOutputDirectory().resolve("CSCA.cer");
      PassiveAuthentication.Result pa = PassiveAuthentication.verify(service, List.of(csca), null);
      assertTrue(pa.isPass(), "Passive authentication should still succeed without PACE secrets");
    }

    Map<String, Object> manifest = readManifest(result.getManifestPath());
    assertTrue(manifest.containsKey("efCardAccess"), "EF.CardAccess path must be recorded in the manifest");
  }

  private CardSession openSession(IssuerSimulator.Result result) throws Exception {
    TerminalCardService terminalService = new TerminalCardService(result.getTerminal());
    terminalService.open();
    LoggingCardService loggingService = new LoggingCardService(terminalService, null);
    loggingService.open();
    PassportService service = new PassportService(
        loggingService,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        false,
        false);
    service.open();
    service.sendSelectApplet(false);
    return new CardSession(terminalService, loggingService, service);
  }

  private static MRZInfo createMrz(String documentNumber) {
    return new MRZInfo(
        "P<",
        "UTO",
        "SIMTEST",
        "EMULATOR",
        documentNumber,
        "UTO",
        "750101",
        Gender.MALE,
        "250101",
        "");
  }

  private static BACKey toBacKey(MRZInfo mrz) {
    return new BACKey(mrz.getDocumentNumber(), mrz.getDateOfBirth(), mrz.getDateOfExpiry());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> readManifest(Path manifestPath) throws Exception {
    return MAPPER.readValue(manifestPath.toFile(), Map.class);
  }

  @SuppressWarnings("unchecked")
  private void assertDataGroups(Map<String, Object> manifest, int... expected) {
    Object groupsRaw = manifest.get("dataGroups");
    assertNotNull(groupsRaw, "Manifest must include dataGroups section");
    List<Map<String, Object>> entries = (List<Map<String, Object>>) groupsRaw;
    Set<Integer> numbers = entries.stream()
        .map(entry -> ((Number) entry.get("dg")).intValue())
        .collect(Collectors.toSet());
    assertEquals(expected.length, numbers.size(), "Mismatch in data group count");
    for (int value : expected) {
      assertTrue(numbers.contains(value), "Expected DG" + value + " in manifest");
    }
  }

  private static final class CardSession implements AutoCloseable {
    private final TerminalCardService terminalService;
    private final LoggingCardService loggingService;
    private final PassportService passportService;

    private CardSession(TerminalCardService terminalService,
                        LoggingCardService loggingService,
                        PassportService passportService) {
      this.terminalService = terminalService;
      this.loggingService = loggingService;
      this.passportService = passportService;
    }

    @Override
    public void close() throws Exception {
      passportService.close();
      loggingService.close();
      terminalService.close();
    }
  }
}

