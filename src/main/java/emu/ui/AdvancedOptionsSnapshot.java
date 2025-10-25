package emu.ui;

import emu.SimConfig;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

final class AdvancedOptionsSnapshot {

  private final String documentNumber;
  private final String dateOfBirth;
  private final String dateOfExpiry;
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

  AdvancedOptionsSnapshot(
      String documentNumber,
      String dateOfBirth,
      String dateOfExpiry,
      String can,
      String pin,
      String puk,
      String pacePreference,
      List<String> taCvcPaths,
      String taKeyPath,
      String taDate,
      String trustStorePath,
      boolean openComSod,
      boolean secureComSod) {
    this.documentNumber = documentNumber;
    this.dateOfBirth = dateOfBirth;
    this.dateOfExpiry = dateOfExpiry;
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

  String getDocumentNumber() {
    return documentNumber;
  }

  String getDateOfBirth() {
    return dateOfBirth;
  }

  String getDateOfExpiry() {
    return dateOfExpiry;
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

