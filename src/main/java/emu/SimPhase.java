package emu;

/** High level lifecycle phases surfaced to the UI stepper. */
public enum SimPhase {
  CONNECTING,
  AUTHENTICATING,
  READING,
  VERIFYING,
  COMPLETE,
  FAILED
}

