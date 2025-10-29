package emu.ui;

import emu.SimConfig;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

final class AdvancedOptionsSnapshot {

  private final String documentType;
  private final String documentNumber;
  private final String issuingState;
  private final String nationality;
  private final String primaryIdentifier;
  private final String secondaryIdentifier;
  private final String dateOfBirth;
  private final String dateOfExpiry;
  private final String gender;
  private final String can;
  private final String pin;
  private final String puk;
  private final String pacePreference;
  private final List<String> taCvcPaths;
  private final String taKeyPath;
  private final String taDate;
  private final String trustStorePath;
  private final boolean openComSod;
  private final boolean secureComSod;
  private final List<Integer> issuerEnableDataGroups;
  private final List<Integer> issuerDisableDataGroups;
  private final String issuerDigestAlgorithm;
  private final String issuerSignatureAlgorithm;
  private final List<String> issuerLifecycleTargets;
  private final Boolean issuerOpenRead;
  private final String issuerFacePath;
  private final Integer issuerFaceWidth;
  private final Integer issuerFaceHeight;

  AdvancedOptionsSnapshot(
      String documentType,
      String documentNumber,
      String issuingState,
      String nationality,
      String primaryIdentifier,
      String secondaryIdentifier,
      String dateOfBirth,
      String dateOfExpiry,
      String gender,
      String can,
      String pin,
      String puk,
      String pacePreference,
      List<String> taCvcPaths,
      String taKeyPath,
      String taDate,
      String trustStorePath,
      boolean openComSod,
      boolean secureComSod,
      List<Integer> issuerEnableDataGroups,
      List<Integer> issuerDisableDataGroups,
      String issuerDigestAlgorithm,
      String issuerSignatureAlgorithm,
      List<String> issuerLifecycleTargets,
      Boolean issuerOpenRead,
      String issuerFacePath,
      Integer issuerFaceWidth,
      Integer issuerFaceHeight) {
    this.documentType = documentType;
    this.documentNumber = documentNumber;
    this.issuingState = issuingState;
    this.nationality = nationality;
    this.primaryIdentifier = primaryIdentifier;
    this.secondaryIdentifier = secondaryIdentifier;
    this.dateOfBirth = dateOfBirth;
    this.dateOfExpiry = dateOfExpiry;
    this.gender = gender;
    this.can = can;
    this.pin = pin;
    this.puk = puk;
    this.pacePreference = pacePreference;
    this.taCvcPaths = List.copyOf(taCvcPaths);
    this.taKeyPath = taKeyPath;
    this.taDate = taDate;
    this.trustStorePath = trustStorePath;
    this.openComSod = openComSod;
    this.secureComSod = secureComSod;
    this.issuerEnableDataGroups = List.copyOf(issuerEnableDataGroups);
    this.issuerDisableDataGroups = List.copyOf(issuerDisableDataGroups);
    this.issuerDigestAlgorithm = issuerDigestAlgorithm;
    this.issuerSignatureAlgorithm = issuerSignatureAlgorithm;
    this.issuerLifecycleTargets = List.copyOf(issuerLifecycleTargets);
    this.issuerOpenRead = issuerOpenRead;
    this.issuerFacePath = issuerFacePath;
    this.issuerFaceWidth = issuerFaceWidth;
    this.issuerFaceHeight = issuerFaceHeight;
  }

  List<String> toArgs() {
    List<String> args = new ArrayList<>();
    if (hasText(documentNumber)) {
      args.add("--doc=" + documentNumber);
    }
    if (hasText(dateOfBirth)) {
      args.add("--dob=" + dateOfBirth);
    }
    if (hasText(dateOfExpiry)) {
      args.add("--doe=" + dateOfExpiry);
    }
    if (hasText(can)) {
      args.add("--can=" + can);
    }
    if (hasText(pin)) {
      args.add("--pin=" + pin);
    }
    if (hasText(puk)) {
      args.add("--puk=" + puk);
    }
    if (hasText(pacePreference)) {
      args.add("--pace-prefer=" + pacePreference);
    }
    for (String cvc : taCvcPaths) {
      if (hasText(cvc)) {
        args.add("--ta-cvc=" + cvc);
      }
    }
    if (hasText(taKeyPath)) {
      args.add("--ta-key=" + taKeyPath);
    }
    if (hasText(taDate)) {
      args.add("--ta-date=" + taDate);
    }
    if (hasText(trustStorePath)) {
      args.add("--trust-store=" + trustStorePath);
    }
    if (openComSod) {
      args.add("--open-com-sod");
    }
    if (secureComSod) {
      args.add("--secure-com-sod");
    }
    if (hasText(issuerFacePath)) {
      args.add("--face-path=" + issuerFacePath);
    }
    if (issuerFaceWidth != null && issuerFaceHeight != null) {
      args.add("--face-size=" + issuerFaceWidth + "x" + issuerFaceHeight);
    }
    return args;
  }

  void applyToBuilder(SimConfig.Builder builder) {
    if (hasText(documentNumber)) {
      builder.docNumber(documentNumber);
    }
    if (hasText(dateOfBirth)) {
      builder.dateOfBirth(dateOfBirth);
    }
    if (hasText(dateOfExpiry)) {
      builder.dateOfExpiry(dateOfExpiry);
    }
    if (hasText(can)) {
      builder.can(can);
    }
    if (hasText(pin)) {
      builder.pin(pin);
    }
    if (hasText(puk)) {
      builder.puk(puk);
    }
    if (hasText(pacePreference)) {
      builder.pacePreference(pacePreference);
    }
    for (String cvc : taCvcPaths) {
      if (hasText(cvc)) {
        builder.addTaCvc(Paths.get(cvc));
      }
    }
    if (hasText(taKeyPath)) {
      builder.taKey(Paths.get(taKeyPath));
    }
    if (hasText(taDate)) {
      builder.terminalAuthDate(parseDate(taDate));
    }
    if (hasText(trustStorePath)) {
      builder.trustStorePath(Paths.get(trustStorePath));
    }
    if (openComSod) {
      builder.openComSodReads(true);
    }
    if (secureComSod) {
      builder.openComSodReads(false);
    }
  }

  String getTrustStorePath() {
    return trustStorePath;
  }

  String getDocumentType() {
    return documentType;
  }

  String getDocumentNumber() {
    return documentNumber;
  }

  String getIssuingState() {
    return issuingState;
  }

  String getNationality() {
    return nationality;
  }

  String getPrimaryIdentifier() {
    return primaryIdentifier;
  }

  String getSecondaryIdentifier() {
    return secondaryIdentifier;
  }

  String getDateOfBirth() {
    return dateOfBirth;
  }

  String getDateOfExpiry() {
    return dateOfExpiry;
  }

  String getGender() {
    return gender;
  }

  String getCan() {
    return can;
  }

  String getPin() {
    return pin;
  }

  String getPuk() {
    return puk;
  }

  boolean isOpenComSod() {
    return openComSod;
  }

  boolean isSecureComSod() {
    return secureComSod;
  }

  List<Integer> getIssuerEnableDataGroups() {
    return issuerEnableDataGroups;
  }

  List<Integer> getIssuerDisableDataGroups() {
    return issuerDisableDataGroups;
  }

  String getIssuerDigestAlgorithm() {
    return issuerDigestAlgorithm;
  }

  String getIssuerSignatureAlgorithm() {
    return issuerSignatureAlgorithm;
  }

  List<String> getIssuerLifecycleTargets() {
    return issuerLifecycleTargets;
  }

  Boolean getIssuerOpenRead() {
    return issuerOpenRead;
  }

  String getIssuerFacePath() {
    return issuerFacePath;
  }

  Integer getIssuerFaceWidth() {
    return issuerFaceWidth;
  }

  Integer getIssuerFaceHeight() {
    return issuerFaceHeight;
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  private static LocalDate parseDate(String value) {
    try {
      return LocalDate.parse(value, DateTimeFormatter.ISO_LOCAL_DATE);
    } catch (Exception e) {
      return LocalDate.now();
    }
  }
}

