package emu.ui;

import java.util.List;

final class SessionReportViewData {

  private final String transport;
  private final String secureMessagingMode;
  private final boolean paceAttempted;
  private final boolean paceEstablished;
  private final boolean caEstablished;
  private final boolean activeAuthEnabled;
  private final boolean activeAuthSupported;
  private final boolean activeAuthVerified;
  private final String activeAuthAlgorithm;
  private final String passiveAuthVerdict;
  private final String passiveAuthAlgorithm;
  private final List<Integer> presentDataGroups;
  private final boolean dg3Readable;
  private final boolean dg4Readable;

  SessionReportViewData(
      String transport,
      String secureMessagingMode,
      boolean paceAttempted,
      boolean paceEstablished,
      boolean caEstablished,
      boolean activeAuthEnabled,
      boolean activeAuthSupported,
      boolean activeAuthVerified,
      String activeAuthAlgorithm,
      String passiveAuthVerdict,
      String passiveAuthAlgorithm,
      List<Integer> presentDataGroups,
      boolean dg3Readable,
      boolean dg4Readable) {
    this.transport = transport;
    this.secureMessagingMode = secureMessagingMode;
    this.paceAttempted = paceAttempted;
    this.paceEstablished = paceEstablished;
    this.caEstablished = caEstablished;
    this.activeAuthEnabled = activeAuthEnabled;
    this.activeAuthSupported = activeAuthSupported;
    this.activeAuthVerified = activeAuthVerified;
    this.activeAuthAlgorithm = activeAuthAlgorithm;
    this.passiveAuthVerdict = passiveAuthVerdict;
    this.passiveAuthAlgorithm = passiveAuthAlgorithm;
    this.presentDataGroups = List.copyOf(presentDataGroups);
    this.dg3Readable = dg3Readable;
    this.dg4Readable = dg4Readable;
  }

  String getTransport() {
    return transport;
  }

  String getSecureMessagingMode() {
    return secureMessagingMode;
  }

  boolean isPaceAttempted() {
    return paceAttempted;
  }

  boolean isPaceEstablished() {
    return paceEstablished;
  }

  boolean isCaEstablished() {
    return caEstablished;
  }

  boolean isActiveAuthEnabled() {
    return activeAuthEnabled;
  }

  boolean isActiveAuthSupported() {
    return activeAuthSupported;
  }

  boolean isActiveAuthVerified() {
    return activeAuthVerified;
  }

  String getActiveAuthAlgorithm() {
    return activeAuthAlgorithm;
  }

  String getPassiveAuthVerdict() {
    return passiveAuthVerdict;
  }

  String getPassiveAuthAlgorithm() {
    return passiveAuthAlgorithm;
  }

  List<Integer> getPresentDataGroups() {
    return presentDataGroups;
  }

  boolean isDg3Readable() {
    return dg3Readable;
  }

  boolean isDg4Readable() {
    return dg4Readable;
  }
}

