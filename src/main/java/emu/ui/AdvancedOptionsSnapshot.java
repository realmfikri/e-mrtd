package emu.ui;

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

  String getTrustStorePath() {
    return trustStorePath;
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }
}

