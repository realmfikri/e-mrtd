package emu;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import emu.PassiveAuthentication;
import emu.PassiveAuthentication.Result;
import emu.SimRunner;

/**
 * Shared session report model used by both the CLI and JavaFX UI.
 */
public final class SessionReport {

  public final Session session = new Session();
  public PassiveAuth passiveAuth = PassiveAuth.notRun();
  public ActiveAuth activeAuth = ActiveAuth.fromOutcome(null, false);
  public final DataGroups dataGroups = new DataGroups();

  public void setPassiveAuthentication(Result result) {
    this.passiveAuth = PassiveAuth.fromResult(result);
  }

  public void setActiveAuthentication(SimRunner.ActiveAuthOutcome outcome, boolean requireAa) {
    this.activeAuth = ActiveAuth.fromOutcome(outcome, requireAa);
  }

  public void write(Path output) throws IOException {
    Path parent = output.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(output, toJson());
  }

  public String toJson() {
    StringBuilder sb = new StringBuilder();
    sb.append("{\n");
    sb.append("  \"session\": ").append(session.toJson("  ")).append(",\n");
    sb.append("  \"pa\": ").append(passiveAuth.toJson("  ")).append(",\n");
    sb.append("  \"aa\": ").append(activeAuth.toJson("  ")).append(",\n");
    sb.append("  \"dg\": ").append(dataGroups.toJson("  ")).append('\n');
    sb.append("}\n");
    return sb.toString();
  }

  public static final class Session {
    public String transport;
    public String smMode;
    public boolean paceAttempted;
    public boolean paceEstablished;
    public boolean caEstablished;
    public Instant completedAt;

    String toJson(String indent) {
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append("\"transport\":").append(toJsonString(transport)).append(',');
      sb.append("\"smMode\":").append(toJsonString(smMode)).append(',');
      sb.append("\"paceAttempted\":").append(paceAttempted);
      sb.append(',');
      sb.append("\"paceEstablished\":").append(paceEstablished);
      sb.append(',');
      sb.append("\"caEstablished\":").append(caEstablished);
      if (completedAt != null) {
        sb.append(',');
        sb.append("\"completedAt\":").append(toJsonString(completedAt.toString()));
      }
      sb.append('}');
      return sb.toString();
    }
  }

  public static final class PassiveAuth {
    public final boolean executed;
    public final String algorithm;
    public final List<Integer> ok;
    public final List<Integer> bad;
    public final List<Integer> missing;
    public final String signer;
    public final String chainStatus;
    public final String verdict;

    PassiveAuth(boolean executed,
                String algorithm,
                List<Integer> ok,
                List<Integer> bad,
                List<Integer> missing,
                String signer,
                String chainStatus,
                String verdict) {
      this.executed = executed;
      this.algorithm = algorithm;
      this.ok = ok;
      this.bad = bad;
      this.missing = missing;
      this.signer = signer;
      this.chainStatus = chainStatus;
      this.verdict = verdict;
    }

    static PassiveAuth fromResult(Result result) {
      if (result == null) {
        return notRun();
      }
      PassiveAuthentication.SignatureCheck sig = result.getSignatureCheck();
      PassiveAuthentication.ChainValidation chain = result.getChainValidation();
      String signer = sig != null ? sig.signerSubject : null;
      String chainStatus = null;
      if (chain != null) {
        chainStatus = (chain.chainOk ? "OK" : "FAIL") +
            (chain.message != null && !chain.message.isBlank() ? (" - " + chain.message) : "");
      }
      return new PassiveAuth(
          true,
          result.getDigestAlgorithm(),
          result.getOkDataGroups(),
          result.getBadDataGroups(),
          result.getMissingDataGroups(),
          signer,
          chainStatus,
          result.verdict());
    }

    static PassiveAuth notRun() {
      return new PassiveAuth(false, null, List.of(), List.of(), List.of(), null, null, "SKIPPED");
    }

    String toJson(String indent) {
      StringBuilder sb = new StringBuilder();
      sb.append('{');
      sb.append("\"executed\":").append(executed).append(',');
      sb.append("\"algorithm\":").append(toJsonString(algorithm)).append(',');
      sb.append("\"okDGs\":").append(intList(ok)).append(',');
      sb.append("\"badDGs\":").append(intList(bad)).append(',');
      sb.append("\"missingDGs\":").append(intList(missing)).append(',');
      sb.append("\"signer\":").append(toJsonString(signer)).append(',');
      sb.append("\"chainStatus\":").append(toJsonString(chainStatus)).append(',');
      sb.append("\"verdict\":").append(toJsonString(verdict));
      sb.append('}');
      return sb.toString();
    }
  }

  public static final class ActiveAuth {
    public final boolean enabled;
    public final boolean supported;
    public final String algorithm;
    public final boolean verified;

    ActiveAuth(boolean enabled, boolean supported, String algorithm, boolean verified) {
      this.enabled = enabled;
      this.supported = supported;
      this.algorithm = algorithm;
      this.verified = verified;
    }

    static ActiveAuth fromOutcome(SimRunner.ActiveAuthOutcome outcome, boolean requireAa) {
      if (outcome == null) {
        return new ActiveAuth(requireAa, false, null, false);
      }
      String algorithm = outcome.publicKey != null ? outcome.publicKey.getAlgorithm() : null;
      boolean enabled = requireAa || outcome.attempted;
      return new ActiveAuth(enabled, outcome.available, algorithm, outcome.verified);
    }

    String toJson(String indent) {
      StringBuilder sb = new StringBuilder();
      sb.append('{');
      sb.append("\"enabled\":").append(enabled).append(',');
      sb.append("\"supported\":").append(supported).append(',');
      sb.append("\"algorithm\":").append(toJsonString(algorithm)).append(',');
      sb.append("\"verified\":").append(verified);
      sb.append('}');
      return sb.toString();
    }
  }

  public static final class DataGroups {
    private final List<Integer> present = new ArrayList<>();
    private boolean dg3Readable;
    private boolean dg4Readable;
    private Dg2Metadata dg2Metadata;

    public void addPresent(int dg) {
      if (!present.contains(dg)) {
        present.add(dg);
      }
    }

    public void setDg3Readable(boolean readable) {
      this.dg3Readable = readable;
      if (readable) {
        addPresent(3);
      }
    }

    public void setDg4Readable(boolean readable) {
      this.dg4Readable = readable;
      if (readable) {
        addPresent(4);
      }
    }

    public void setDg2Metadata(Dg2Metadata metadata) {
      this.dg2Metadata = metadata;
    }

    public List<Integer> getPresent() {
      present.sort(Comparator.naturalOrder());
      return List.copyOf(present);
    }

    public boolean isDg3Readable() {
      return dg3Readable;
    }

    public boolean isDg4Readable() {
      return dg4Readable;
    }

    public Dg2Metadata getDg2Metadata() {
      return dg2Metadata;
    }

    String toJson(String indent) {
      present.sort(Comparator.naturalOrder());
      StringBuilder sb = new StringBuilder();
      sb.append('{');
      sb.append("\"present\":").append(intList(present)).append(',');
      sb.append("\"dg3Readable\":").append(dg3Readable).append(',');
      sb.append("\"dg4Readable\":").append(dg4Readable).append(',');
      sb.append("\"dg2\":").append(dg2ToJson(dg2Metadata));
      sb.append('}');
      return sb.toString();
    }

    private String dg2ToJson(Dg2Metadata metadata) {
      if (metadata == null) {
        return "null";
      }
      StringBuilder sb = new StringBuilder();
      sb.append('{');
      sb.append("\"length\":").append(metadata.length).append(',');
      sb.append("\"largeScenario\":").append(metadata.largeScenario).append(',');
      sb.append("\"truncated\":").append(metadata.truncated).append(',');
      sb.append("\"previewPath\":").append(toJsonString(metadata.previewPath));
      sb.append(',');
      sb.append("\"faces\":").append(faceList(metadata.faces));
      sb.append('}');
      return sb.toString();
    }

    private String faceList(List<Dg2FaceSummary> faces) {
      if (faces == null || faces.isEmpty()) {
        return "[]";
      }
      StringBuilder sb = new StringBuilder();
      sb.append('[');
      for (int i = 0; i < faces.size(); i++) {
        Dg2FaceSummary face = faces.get(i);
        if (i > 0) {
          sb.append(',');
        }
        sb.append('{');
        sb.append("\"faceIndex\":").append(face.faceIndex).append(',');
        sb.append("\"imageIndex\":").append(face.imageIndex).append(',');
        sb.append("\"width\":").append(face.width).append(',');
        sb.append("\"height\":").append(face.height).append(',');
        sb.append("\"mimeType\":").append(toJsonString(face.mimeType)).append(',');
        sb.append("\"length\":").append(face.length).append(',');
        sb.append("\"quality\":").append(face.quality).append(',');
        sb.append("\"imageType\":").append(toJsonString(face.imageType));
        sb.append('}');
      }
      sb.append(']');
      return sb.toString();
    }
  }

  public static final class Dg2Metadata {
    public final int length;
    public final boolean largeScenario;
    public final boolean truncated;
    public final List<Dg2FaceSummary> faces;
    public final String previewPath;

    public Dg2Metadata(int length, boolean largeScenario, boolean truncated, List<Dg2FaceSummary> faces,
                       String previewPath) {
      this.length = length;
      this.largeScenario = largeScenario;
      this.truncated = truncated;
      this.faces = faces;
      this.previewPath = previewPath;
    }
  }

  public static final class Dg2FaceSummary {
    public final int faceIndex;
    public final int imageIndex;
    public final int width;
    public final int height;
    public final String mimeType;
    public final int length;
    public final int quality;
    public final String imageType;

    public Dg2FaceSummary(int faceIndex, int imageIndex, int width, int height, String mimeType,
                          int length, int quality, String imageType) {
      this.faceIndex = faceIndex;
      this.imageIndex = imageIndex;
      this.width = width;
      this.height = height;
      this.mimeType = mimeType;
      this.length = length;
      this.quality = quality;
      this.imageType = imageType;
    }
  }

  private static String toJsonString(String value) {
    if (value == null) {
      return "null";
    }
    String escaped = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r");
    return '"' + escaped + '"';
  }

  private static String intList(List<Integer> values) {
    if (values == null || values.isEmpty()) {
      return "[]";
    }
    StringBuilder sb = new StringBuilder();
    sb.append('[');
    for (int i = 0; i < values.size(); i++) {
      if (i > 0) {
        sb.append(',');
      }
      sb.append(values.get(i));
    }
    sb.append(']');
    return sb.toString();
  }
}

