package emu;

/** Event callbacks surfaced by {@link SimRunner} during execution. */
public interface SimEvents {

  default void onPhase(SimPhase phase, String detail) {
  }

  default void onLog(SimLogCategory category, String message) {
  }
}

