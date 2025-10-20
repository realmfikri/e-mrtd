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
    List<Integer> present = dg.present != null ? dg.present : Collections.emptyList();
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
        present,
        dg.dg3Readable,
        dg.dg4Readable);
  }

  static SessionReportViewData fromReport(SessionReport report) {
    if (report == null || report.session == null) {
      return null;
    }
    SessionReport.DataGroups dg = report.dataGroups != null ? report.dataGroups : new SessionReport.DataGroups();
    List<Integer> present = dg.getPresent();
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
        present,
        dg.isDg3Readable(),
        dg.isDg4Readable());
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawSessionReport {
    RawSession session;
    RawPassiveAuth pa;
    RawActiveAuth aa;
    RawDataGroups dg;
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
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static final class RawDataGroups {
    List<Integer> present = List.of();
    boolean dg3Readable;
    boolean dg4Readable;
  }
}

