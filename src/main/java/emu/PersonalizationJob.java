package emu;

import org.jmrtd.lds.LDSFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration object describing how a simulated passport should be personalised.
 */
public final class PersonalizationJob {

  private final MRZInfo mrzInfo;
  private final Set<Integer> enabledDataGroups;
  private final boolean corruptDg2;
  private final BiometricSource faceSource;
  private final BiometricSource fingerprintSource;
  private final BiometricSource irisSource;
  private final String digestAlgorithm;
  private final String signatureAlgorithm;
  private final List<String> paceOids;
  private final boolean includeCardAccess;
  private final boolean includeTerminalAuthentication;
  private final String chipAuthenticationCurve;
  private final int aaKeySize;
  private final int docSignerKeySize;
  private final int cscaKeySize;
  private final BigInteger chipAuthenticationKeyId;
  private final Long deterministicSeed;
  private final List<String> lifecycleTargets;

  private volatile byte[] dg1Bytes;

  private PersonalizationJob(Builder builder) {
    this.mrzInfo = builder.mrzInfo;
    this.enabledDataGroups = Collections.unmodifiableSet(new HashSet<>(builder.enabledDataGroups));
    this.corruptDg2 = builder.corruptDg2;
    this.faceSource = builder.faceSource;
    this.fingerprintSource = builder.fingerprintSource;
    this.irisSource = builder.irisSource;
    this.digestAlgorithm = builder.digestAlgorithm;
    this.signatureAlgorithm = builder.signatureAlgorithm;
    this.paceOids = List.copyOf(builder.paceOids);
    this.includeCardAccess = builder.includeCardAccess;
    this.includeTerminalAuthentication = builder.includeTerminalAuthentication;
    this.chipAuthenticationCurve = builder.chipAuthenticationCurve;
    this.aaKeySize = builder.aaKeySize;
    this.docSignerKeySize = builder.docSignerKeySize;
    this.cscaKeySize = builder.cscaKeySize;
    this.chipAuthenticationKeyId = builder.chipAuthenticationKeyId;
    this.deterministicSeed = builder.deterministicSeed;
    this.lifecycleTargets = List.copyOf(builder.lifecycleTargets);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static Set<Integer> defaultEnabledDataGroups() {
    return Builder.defaultDataGroups();
  }

  public static String defaultDigestAlgorithm() {
    return Builder.DEFAULT_DIGEST_ALGORITHM;
  }

  public static String defaultSignatureAlgorithm() {
    return Builder.DEFAULT_SIGNATURE_ALGORITHM;
  }

  public static List<String> defaultLifecycleTargets() {
    return Builder.DEFAULT_LIFECYCLE_TARGETS;
  }

  public MRZInfo getMrzInfo() {
    return mrzInfo;
  }

  public boolean isDataGroupEnabled(int dataGroupNumber) {
    return enabledDataGroups.contains(dataGroupNumber);
  }

  public Set<Integer> getEnabledDataGroups() {
    return enabledDataGroups;
  }

  public boolean isCorruptDg2() {
    return corruptDg2;
  }

  public BiometricSource getFaceSource() {
    return faceSource;
  }

  public BiometricSource getFingerprintSource() {
    return fingerprintSource;
  }

  public BiometricSource getIrisSource() {
    return irisSource;
  }

  public String getDigestAlgorithm() {
    return digestAlgorithm;
  }

  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  public List<String> getPaceOids() {
    return paceOids;
  }

  public boolean includeCardAccess() {
    return includeCardAccess;
  }

  public boolean includeTerminalAuthentication() {
    return includeTerminalAuthentication;
  }

  public String getChipAuthenticationCurve() {
    return chipAuthenticationCurve;
  }

  public int getAaKeySize() {
    return aaKeySize;
  }

  public int getDocSignerKeySize() {
    return docSignerKeySize;
  }

  public int getCscaKeySize() {
    return cscaKeySize;
  }

  public BigInteger getChipAuthenticationKeyId() {
    return chipAuthenticationKeyId;
  }

  public Long getDeterministicSeed() {
    return deterministicSeed;
  }

  public List<String> getLifecycleTargets() {
    return lifecycleTargets;
  }

  public List<Integer> getComTagList() {
    List<Integer> tags = new ArrayList<>();
    tags.add(LDSFile.EF_DG1_TAG);
    for (Integer dg : enabledDataGroups) {
      tags.add(0x0100 | dg.intValue());
    }
    Collections.sort(tags);
    return Collections.unmodifiableList(tags);
  }

  public byte[] getDg1Bytes() {
    byte[] local = dg1Bytes;
    if (local == null) {
      synchronized (this) {
        local = dg1Bytes;
        if (local == null) {
          dg1Bytes = local = new DG1File(mrzInfo).getEncoded();
        }
      }
    }
    return local.clone();
  }

  public static final class Builder {
    private static final Set<Integer> DEFAULT_DATA_GROUPS = Set.of(2, 3, 4, 14, 15);
    private static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final List<String> DEFAULT_LIFECYCLE_TARGETS = List.of("SIMULATOR");

    private MRZInfo mrzInfo;
    private final Set<Integer> enabledDataGroups = new HashSet<>();
    private boolean corruptDg2;
    private BiometricSource faceSource = BiometricSource.synthetic(BiometricType.FACE, 480, 600);
    private BiometricSource fingerprintSource = BiometricSource.synthetic(BiometricType.FINGERPRINT, 160, 160);
    private BiometricSource irisSource = BiometricSource.synthetic(BiometricType.IRIS, 160, 160);
    private String digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private String signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
    private List<String> paceOids = defaultPaceOids();
    private boolean includeCardAccess = true;
    private boolean includeTerminalAuthentication = true;
    private String chipAuthenticationCurve = "secp256r1";
    private int aaKeySize = 1024;
    private int docSignerKeySize = 2048;
    private int cscaKeySize = 2048;
    private BigInteger chipAuthenticationKeyId = BigInteger.ONE;
    private Long deterministicSeed;
    private List<String> lifecycleTargets = new ArrayList<>(DEFAULT_LIFECYCLE_TARGETS);

    private static List<String> defaultPaceOids() {
      List<String> defaults = new ArrayList<>();
      defaults.add(org.jmrtd.lds.SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128);
      defaults.add(org.jmrtd.lds.SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128);
      defaults.add(org.jmrtd.lds.SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC);
      defaults.add(org.jmrtd.lds.SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC);
      return defaults;
    }

    private Builder() {
      enabledDataGroups.addAll(DEFAULT_DATA_GROUPS);
    }

    private static Set<Integer> defaultDataGroups() {
      return DEFAULT_DATA_GROUPS;
    }

    public Builder withMrzInfo(MRZInfo mrzInfo) {
      this.mrzInfo = Objects.requireNonNull(mrzInfo, "mrzInfo");
      return this;
    }

    public Builder enableDataGroup(int number, boolean enabled) {
      if (number <= 1) {
        throw new IllegalArgumentException("DG1 is mandatory and cannot be toggled");
      }
      if (enabled) {
        enabledDataGroups.add(number);
      } else {
        enabledDataGroups.remove(number);
      }
      return this;
    }

    public Builder corruptDg2(boolean value) {
      this.corruptDg2 = value;
      return this;
    }

    public Builder withFaceSyntheticSize(int width, int height) {
      this.faceSource = BiometricSource.synthetic(BiometricType.FACE, width, height);
      return this;
    }

    public Builder withFaceImagePath(Path path) {
      this.faceSource = BiometricSource.fromPath(BiometricType.FACE, path);
      return this;
    }

    public Builder withFingerprintSyntheticSize(int width, int height) {
      this.fingerprintSource = BiometricSource.synthetic(BiometricType.FINGERPRINT, width, height);
      return this;
    }

    public Builder withFingerprintImagePath(Path path) {
      this.fingerprintSource = BiometricSource.fromPath(BiometricType.FINGERPRINT, path);
      return this;
    }

    public Builder withIrisSyntheticSize(int width, int height) {
      this.irisSource = BiometricSource.synthetic(BiometricType.IRIS, width, height);
      return this;
    }

    public Builder withIrisImagePath(Path path) {
      this.irisSource = BiometricSource.fromPath(BiometricType.IRIS, path);
      return this;
    }

    public Builder digestAlgorithm(String algorithm) {
      this.digestAlgorithm = Objects.requireNonNull(algorithm, "algorithm");
      return this;
    }

    public Builder signatureAlgorithm(String algorithm) {
      this.signatureAlgorithm = Objects.requireNonNull(algorithm, "algorithm");
      return this;
    }

    public Builder paceOids(List<String> paceOids) {
      this.paceOids = new ArrayList<>(Objects.requireNonNull(paceOids, "paceOids"));
      return this;
    }

    public Builder includeCardAccess(boolean includeCardAccess) {
      this.includeCardAccess = includeCardAccess;
      return this;
    }

    public Builder includeTerminalAuthentication(boolean includeTerminalAuthentication) {
      this.includeTerminalAuthentication = includeTerminalAuthentication;
      return this;
    }

    public Builder chipAuthenticationCurve(String curve) {
      this.chipAuthenticationCurve = Objects.requireNonNull(curve, "curve");
      return this;
    }

    public Builder aaKeySize(int bits) {
      this.aaKeySize = bits;
      return this;
    }

    public Builder docSignerKeySize(int bits) {
      this.docSignerKeySize = bits;
      return this;
    }

    public Builder cscaKeySize(int bits) {
      this.cscaKeySize = bits;
      return this;
    }

    public Builder chipAuthenticationKeyId(BigInteger keyId) {
      this.chipAuthenticationKeyId = Objects.requireNonNull(keyId, "keyId");
      return this;
    }

    public Builder deterministicSeed(Long seed) {
      this.deterministicSeed = seed;
      return this;
    }

    public Builder lifecycleTargets(List<String> lifecycleTargets) {
      this.lifecycleTargets = new ArrayList<>(Objects.requireNonNull(lifecycleTargets, "lifecycleTargets"));
      return this;
    }

    public PersonalizationJob build() {
      if (mrzInfo == null) {
        throw new IllegalStateException("MRZ information is required");
      }
      return new PersonalizationJob(this);
    }
  }

  public enum BiometricType {
    FACE,
    FINGERPRINT,
    IRIS
  }

  public static final class BiometricSource {
    private final BiometricType type;
    private final Path path;
    private final Integer width;
    private final Integer height;

    private BiometricSource(BiometricType type, Path path, Integer width, Integer height) {
      this.type = Objects.requireNonNull(type, "type");
      this.path = path;
      this.width = width;
      this.height = height;
    }

    public static BiometricSource synthetic(BiometricType type, int width, int height) {
      if (width <= 0 || height <= 0) {
        throw new IllegalArgumentException("Invalid biometric dimensions");
      }
      return new BiometricSource(type, null, width, height);
    }

    public static BiometricSource fromPath(BiometricType type, Path path) {
      return new BiometricSource(type, Objects.requireNonNull(path, "path"), null, null);
    }

    public BiometricType getType() {
      return type;
    }

    public Path getPath() {
      return path;
    }

    public Integer getWidth() {
      return width;
    }

    public Integer getHeight() {
      return height;
    }

    public boolean isSynthetic() {
      return path == null;
    }
  }
}

