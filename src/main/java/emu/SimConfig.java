package emu;

import com.licel.jcardsim.smartcardio.CardSimulator;

import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/** Immutable configuration used by {@link SimRunner}. */
public final class SimConfig {

  public final boolean seed;
  public final boolean corruptDg2;
  public final boolean largeDg2;
  public final boolean attemptPace;
  public final String pacePreference;
  public final Path trustStorePath;
  public final List<Path> trustMasterListPaths;
  public final String trustStorePassword;
  public final boolean requirePa;
  public final boolean requireAa;
  public final List<Path> taCvcPaths;
  public final Path taKeyPath;
  public final String docNumber;
  public final String dateOfBirth;
  public final String dateOfExpiry;
  public final String can;
  public final String pin;
  public final String puk;
  public final LocalDate terminalAuthDate;
  public final Boolean openComSodReads;
  public final Path reportOutput;
  public final Path eventsOutput;
  public final Path facePreviewDirectory;
  public final IssuerSimulator.Result issuerResult;
  public final CardSimulator cardSimulator;
  public final RealPassportProfile realPassportProfile;

  private SimConfig(Builder builder) {
    this.seed = builder.seed;
    this.corruptDg2 = builder.corruptDg2;
    this.largeDg2 = builder.largeDg2;
    this.attemptPace = builder.attemptPace;
    this.pacePreference = builder.pacePreference;
    this.trustStorePath = builder.trustStorePath;
    this.trustMasterListPaths = List.copyOf(builder.trustMasterListPaths);
    this.trustStorePassword = builder.trustStorePassword;
    this.requirePa = builder.requirePa;
    this.requireAa = builder.requireAa;
    this.taCvcPaths = List.copyOf(builder.taCvcPaths);
    this.taKeyPath = builder.taKeyPath;
    this.docNumber = builder.docNumber;
    this.dateOfBirth = builder.dateOfBirth;
    this.dateOfExpiry = builder.dateOfExpiry;
    this.can = builder.can;
    this.pin = builder.pin;
    this.puk = builder.puk;
    this.terminalAuthDate = builder.terminalAuthDate;
    this.openComSodReads = builder.openComSodReads;
    this.reportOutput = builder.reportOutput;
    this.eventsOutput = builder.eventsOutput;
    this.facePreviewDirectory = builder.facePreviewDirectory;
    this.issuerResult = builder.issuerResult;
    this.cardSimulator = builder.cardSimulator;
    this.realPassportProfile = builder.realPassportProfile;
  }

  public Builder toBuilder() {
    Builder builder = new Builder();
    builder.seed = seed;
    builder.corruptDg2 = corruptDg2;
    builder.largeDg2 = largeDg2;
    builder.attemptPace = attemptPace;
    builder.pacePreference = pacePreference;
    builder.trustStorePath = trustStorePath;
    builder.trustMasterListPaths = new ArrayList<>(trustMasterListPaths);
    builder.trustStorePassword = trustStorePassword;
    builder.requirePa = requirePa;
    builder.requireAa = requireAa;
    builder.taCvcPaths = new ArrayList<>(taCvcPaths);
    builder.taKeyPath = taKeyPath;
    builder.docNumber = docNumber;
    builder.dateOfBirth = dateOfBirth;
    builder.dateOfExpiry = dateOfExpiry;
    builder.can = can;
    builder.pin = pin;
    builder.puk = puk;
    builder.terminalAuthDate = terminalAuthDate;
    builder.openComSodReads = openComSodReads;
    builder.reportOutput = reportOutput;
    builder.eventsOutput = eventsOutput;
    builder.facePreviewDirectory = facePreviewDirectory;
    builder.issuerResult = issuerResult;
    builder.cardSimulator = cardSimulator;
    builder.realPassportProfile = realPassportProfile;
    return builder;
  }

  public static final class Builder {
    boolean seed;
    boolean corruptDg2;
    boolean largeDg2;
    boolean attemptPace;
    String pacePreference;
    Path trustStorePath;
    List<Path> trustMasterListPaths = new ArrayList<>();
    String trustStorePassword;
    boolean requirePa;
    boolean requireAa;
    List<Path> taCvcPaths = new ArrayList<>();
    Path taKeyPath;
    String docNumber;
    String dateOfBirth;
    String dateOfExpiry;
    String can;
    String pin;
    String puk;
    LocalDate terminalAuthDate;
    Boolean openComSodReads;
    Path reportOutput;
    Path eventsOutput;
    Path facePreviewDirectory;
    IssuerSimulator.Result issuerResult;
    CardSimulator cardSimulator;
    RealPassportProfile realPassportProfile;

    public Builder seed(boolean value) {
      this.seed = value;
      return this;
    }

    public Builder corruptDg2(boolean value) {
      this.corruptDg2 = value;
      return this;
    }

    public Builder largeDg2(boolean value) {
      this.largeDg2 = value;
      return this;
    }

    public Builder attemptPace(boolean value) {
      this.attemptPace = value;
      return this;
    }

    public Builder pacePreference(String value) {
      this.pacePreference = value;
      return this;
    }

    public Builder trustStorePath(Path value) {
      this.trustStorePath = value;
      return this;
    }

    public Builder trustMasterList(Path value) {
      if (value != null) {
        this.trustMasterListPaths.add(value);
      }
      return this;
    }

    public Builder trustMasterLists(List<Path> values) {
      this.trustMasterListPaths.addAll(values);
      return this;
    }

    public Builder trustStorePassword(String value) {
      this.trustStorePassword = value;
      return this;
    }

    public Builder requirePa(boolean value) {
      this.requirePa = value;
      return this;
    }

    public Builder requireAa(boolean value) {
      this.requireAa = value;
      return this;
    }

    public Builder addTaCvc(Path value) {
      if (value != null) {
        this.taCvcPaths.add(value);
      }
      return this;
    }

    public Builder taKey(Path value) {
      this.taKeyPath = value;
      return this;
    }

    public Builder docNumber(String value) {
      this.docNumber = value;
      return this;
    }

    public Builder dateOfBirth(String value) {
      this.dateOfBirth = value;
      return this;
    }

    public Builder dateOfExpiry(String value) {
      this.dateOfExpiry = value;
      return this;
    }

    public Builder can(String value) {
      this.can = value;
      return this;
    }

    public Builder pin(String value) {
      this.pin = value;
      return this;
    }

    public Builder puk(String value) {
      this.puk = value;
      return this;
    }

    public Builder terminalAuthDate(LocalDate value) {
      this.terminalAuthDate = value;
      return this;
    }

    public Builder openComSodReads(Boolean value) {
      this.openComSodReads = value;
      return this;
    }

    public Builder reportOutput(Path value) {
      this.reportOutput = value;
      return this;
    }

    public Builder eventsOutput(Path value) {
      this.eventsOutput = value;
      return this;
    }

    public Builder facePreviewDirectory(Path value) {
      this.facePreviewDirectory = value;
      return this;
    }

    public Builder issuerResult(IssuerSimulator.Result value) {
      this.issuerResult = value;
      return this;
    }

    public Builder cardSimulator(CardSimulator value) {
      this.cardSimulator = value;
      return this;
    }

    public Builder realPassportProfile(RealPassportProfile value) {
      this.realPassportProfile = value;
      return this;
    }

    public SimConfig build() {
      return new SimConfig(this);
    }
  }
}

