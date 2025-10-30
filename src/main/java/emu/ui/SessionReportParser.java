package emu.ui;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import emu.SessionReport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

final class SessionReportParser {

  private static final ObjectMapper MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private SessionReportParser() {
  }

  static SessionReportViewData parse(Path reportPath) throws IOException {
    if (!Files.exists(reportPath)) {
      return null;
    }
    RawSessionReport raw = MAPPER.readValue(reportPath.toFile(), RawSessionReport.class);
    if (raw == null || raw.session == null) {
      return null;
    }
    RawDataGroups dg = raw.dg != null ? raw.dg : new RawDataGroups();
    RawTerminalAuth ta = raw.ta != null ? raw.ta : new RawTerminalAuth();
    List<Integer> present = dg.present != null ? dg.present : Collections.emptyList();
    SessionReportViewData.MrzSummary mrzSummary = toViewMrz(dg.dg1);
    List<Integer> paOk = raw.pa != null ? safeList(raw.pa.okDGs) : Collections.emptyList();
    List<Integer> paBad = raw.pa != null ? safeList(raw.pa.badDGs) : Collections.emptyList();
    List<Integer> paMissing = raw.pa != null ? safeList(raw.pa.missingDGs) : Collections.emptyList();
    List<Integer> paLocked = raw.pa != null ? safeList(raw.pa.lockedDGs) : Collections.emptyList();
    String dg2PreviewPath = dg.dg2 != null ? dg.dg2.previewPath : null;
    String issuerPreviewPath = dg.dg2 != null ? dg.dg2.issuerPreviewPath : null;
    List<String> taWarnings = safeStringList(ta.validationWarnings);
    return new SessionReportViewData(
        raw.session.transport,
        raw.session.smMode,
        raw.session.paceAttempted,
        raw.session.paceEstablished,
        raw.session.caEstablished,
        raw.aa != null && raw.aa.enabled,
        raw.aa != null && raw.aa.supported,
        raw.aa != null && raw.aa.verified,
        raw.aa != null ? raw.aa.algorithm : null,
        raw.pa != null ? raw.pa.verdict : null,
        raw.pa != null ? raw.pa.algorithm : null,
        paOk,
        paBad,
        paMissing,
        paLocked,
        raw.pa != null ? raw.pa.signer : null,
        raw.pa != null ? raw.pa.chainStatus : null,
        mrzSummary,
        present,
        dg.dg3Readable,
        dg.dg4Readable,
        dg2PreviewPath,
        issuerPreviewPath,
        ta.attempted,
        ta.succeeded,
        ta.dg3Readable,
        ta.dg4Readable,
        ta.terminalRole,
        ta.terminalRights,
        taWarnings);
  }

  static SessionReportViewData fromReport(SessionReport report) {
    if (report == null || report.session == null) {
      return null;
    }
    SessionReport.DataGroups dg = report.dataGroups != null ? report.dataGroups : new SessionReport.DataGroups();
    List<Integer> present = dg.getPresent();
    SessionReport.MrzSummary dg1 = dg.getDg1Mrz();
    SessionReport.Dg2Metadata dg2Metadata = dg.getDg2Metadata();
    String dg2PreviewPath = dg2Metadata != null ? dg2Metadata.previewPath : null;
    String issuerPreviewPath = dg2Metadata != null ? dg2Metadata.issuerPreviewPath : null;
    SessionReport.TerminalAuth ta = report.terminalAuth != null
        ? report.terminalAuth
        : SessionReport.TerminalAuth.fromOutcome(false, false, false, false, null, null, List.of());
    return new SessionReportViewData(
        report.session.transport,
        report.session.smMode,
        report.session.paceAttempted,
        report.session.paceEstablished,
        report.session.caEstablished,
        report.activeAuth != null && report.activeAuth.enabled,
        report.activeAuth != null && report.activeAuth.supported,
        report.activeAuth != null && report.activeAuth.verified,
        report.activeAuth != null ? report.activeAuth.algorithm : null,
        report.passiveAuth != null ? report.passiveAuth.verdict : null,
        report.passiveAuth != null ? report.passiveAuth.algorithm : null,
        report.passiveAuth != null ? report.passiveAuth.ok : Collections.emptyList(),
        report.passiveAuth != null ? report.passiveAuth.bad : Collections.emptyList(),
        report.passiveAuth != null ? report.passiveAuth.missing : Collections.emptyList(),
        report.passiveAuth != null ? report.passiveAuth.locked : Collections.emptyList(),
        report.passiveAuth != null ? report.passiveAuth.signer : null,
        report.passiveAuth != null ? report.passiveAuth.chainStatus : null,
        toViewMrz(dg1),
        present,
        dg.isDg3Readable(),
        dg.isDg4Readable(),
        dg2PreviewPath,
        issuerPreviewPath,
        ta.attempted,
        ta.succeeded,
        ta.dg3Readable,
        ta.dg4Readable,
        ta.terminalRole,
        ta.terminalRights,
        ta.validationWarnings);
  }

  private static List<Integer> safeList(List<Integer> values) {
    return values != null ? values : Collections.emptyList();
  }

  private static List<String> safeStringList(List<String> values) {
    return values != null ? values : Collections.emptyList();
  }

  private static SessionReportViewData.MrzSummary toViewMrz(RawMrz rawMrz) {
    if (rawMrz == null) {
      return null;
    }
    return new SessionReportViewData.MrzSummary(
        rawMrz.documentNumber,
        rawMrz.dateOfBirth,
        rawMrz.dateOfExpiry,
        rawMrz.primaryIdentifier,
        rawMrz.secondaryIdentifier,
        rawMrz.issuingState,
        rawMrz.nationality);
  }

  private static SessionReportViewData.MrzSummary toViewMrz(SessionReport.MrzSummary summary) {
    if (summary == null) {
      return null;
    }
    return new SessionReportViewData.MrzSummary(
        summary.documentNumber,
        summary.dateOfBirth,
        summary.dateOfExpiry,
        summary.primaryIdentifier,
        summary.secondaryIdentifier,
        summary.issuingState,
        summary.nationality);
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawSessionReport {
    RawSession session;
    RawPassiveAuth pa;
    RawActiveAuth aa;
    RawDataGroups dg;
    RawTerminalAuth ta;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawSession {
    String transport;
    String smMode;
    boolean paceAttempted;
    boolean paceEstablished;
    boolean caEstablished;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawActiveAuth {
    boolean enabled;
    boolean supported;
    boolean verified;
    String algorithm;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawPassiveAuth {
    boolean executed;
    String algorithm;
    String verdict;
    List<Integer> okDGs;
    List<Integer> badDGs;
    List<Integer> missingDGs;
    List<Integer> lockedDGs;
    String signer;
    String chainStatus;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawDataGroups {
    List<Integer> present = List.of();
    boolean dg3Readable;
    boolean dg4Readable;
    RawMrz dg1;
    RawDg2 dg2;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawTerminalAuth {
    boolean attempted;
    boolean succeeded;
    boolean dg3Readable;
    boolean dg4Readable;
    String terminalRole;
    String terminalRights;
    List<String> validationWarnings = List.of();
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawMrz {
    String documentNumber;
    String dateOfBirth;
    String dateOfExpiry;
    String primaryIdentifier;
    String secondaryIdentifier;
    String issuingState;
    String nationality;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawDg2 {
    String previewPath;
    String issuerPreviewPath;
  }
}

