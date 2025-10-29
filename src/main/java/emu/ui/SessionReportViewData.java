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
  private final List<Integer> passiveAuthOkDataGroups;
  private final List<Integer> passiveAuthBadDataGroups;
  private final List<Integer> passiveAuthMissingDataGroups;
  private final List<Integer> passiveAuthLockedDataGroups;
  private final String passiveAuthSigner;
  private final String passiveAuthChainStatus;
  private final MrzSummary mrzSummary;
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
      List<Integer> passiveAuthOkDataGroups,
      List<Integer> passiveAuthBadDataGroups,
      List<Integer> passiveAuthMissingDataGroups,
      List<Integer> passiveAuthLockedDataGroups,
      String passiveAuthSigner,
      String passiveAuthChainStatus,
      MrzSummary mrzSummary,
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
    this.passiveAuthOkDataGroups = List.copyOf(passiveAuthOkDataGroups);
    this.passiveAuthBadDataGroups = List.copyOf(passiveAuthBadDataGroups);
    this.passiveAuthMissingDataGroups = List.copyOf(passiveAuthMissingDataGroups);
    this.passiveAuthLockedDataGroups = List.copyOf(passiveAuthLockedDataGroups);
    this.passiveAuthSigner = passiveAuthSigner;
    this.passiveAuthChainStatus = passiveAuthChainStatus;
    this.mrzSummary = mrzSummary;
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

  List<Integer> getPassiveAuthOkDataGroups() {
    return passiveAuthOkDataGroups;
  }

  List<Integer> getPassiveAuthBadDataGroups() {
    return passiveAuthBadDataGroups;
  }

  List<Integer> getPassiveAuthMissingDataGroups() {
    return passiveAuthMissingDataGroups;
  }

  List<Integer> getPassiveAuthLockedDataGroups() {
    return passiveAuthLockedDataGroups;
  }

  String getPassiveAuthSigner() {
    return passiveAuthSigner;
  }

  String getPassiveAuthChainStatus() {
    return passiveAuthChainStatus;
  }

  MrzSummary getMrzSummary() {
    return mrzSummary;
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

  static final class MrzSummary {
    private final String documentNumber;
    private final String dateOfBirth;
    private final String dateOfExpiry;
    private final String primaryIdentifier;
    private final String secondaryIdentifier;
    private final String issuingState;
    private final String nationality;

    MrzSummary(String documentNumber,
               String dateOfBirth,
               String dateOfExpiry,
               String primaryIdentifier,
               String secondaryIdentifier,
               String issuingState,
               String nationality) {
      this.documentNumber = documentNumber;
      this.dateOfBirth = dateOfBirth;
      this.dateOfExpiry = dateOfExpiry;
      this.primaryIdentifier = primaryIdentifier;
      this.secondaryIdentifier = secondaryIdentifier;
      this.issuingState = issuingState;
      this.nationality = nationality;
    }

    String getDocumentNumber() {
      return documentNumber;
    }

    String getDateOfBirth() {
      return dateOfBirth;
    }

    String getDateOfExpiry() {
      return dateOfExpiry;
    }

    String getPrimaryIdentifier() {
      return primaryIdentifier;
    }

    String getSecondaryIdentifier() {
      return secondaryIdentifier;
    }

    String getIssuingState() {
      return issuingState;
    }

    String getNationality() {
      return nationality;
    }
  }
}

