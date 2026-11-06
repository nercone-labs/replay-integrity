# Using Replay Integrity

Replay Integrity keeps Play Integrity at `STRONG` on a rooted device, and keeps it there, by
driving two modules: TEESimulator-RS (key attestation) and PlayIntegrityFork (build spoof).

## Requirements

- A rooted device with **Magisk**, **KernelSU** or **APatch**.
- A **Zygisk** implementation for the build spoof: Magisk's built-in Zygisk, or a standalone
  Zygisk Next / ReZygisk / NeoZygisk (recommended, and required on KernelSU/APatch). The Home
  screen warns when none is present.
- Either a **root manager** that grants `su`, or **Shizuku**/**Sui** started with root. The engine
  must run as root, so a Shizuku started through ADB (shell) is not enough; the app says so.
- Android 13 (API 33) or later.

## First run

1. Open the app. The Home screen shows what is present and what is missing.
2. Grant the privilege when asked (Shizuku's dialog, or `su` from your root manager).
3. If a module is missing, install it from your root manager. (A future version installs them for
   you from the app.)
4. Tap **Refresh now**. The app downloads a working keybox and a fresh Pixel fingerprint, installs
   them, writes the attestation target list and the security patch, applies the STRONG spoof flags,
   and restarts the keystore. Check the verdict with a Play Integrity checker; no reboot is needed.

## Keeping it

Replay Integrity refreshes the keybox and the fingerprint on a schedule, and **repairs** the
keystore at every boot — including removing the stale per-application keys that otherwise keep an
app on an old, revoked keybox (the usual reason a working setup quietly stops passing after a few
days). The two automatic refreshes and the boot repair can each be turned off in Settings.

- **Refresh now** downloads fresh inputs, installs them, and restarts the keystore.
- **Repair** re-applies everything and removes stale keys **without** downloading — useful when the
  network is down, or to fix a drift at once.

## Settings

- **Privilege** — Automatic (prefer Shizuku/Sui, fall back to `su`), Shizuku/Sui only, or Root
  only.
- **Refresh the keybox automatically** — turn off if you manage `keybox.xml` yourself.
- **Refresh the fingerprint automatically** — turn off if you keep your own fingerprint.
- **Repair at every boot** — installs a boot script in your root manager so the keystore is
  repaired before the framework starts.

## Where the files are

Replay Integrity writes the configuration the modules read, under `/data/adb/tricky_store/`
(`keybox.xml`, `target.txt`, `security_patch.txt`) and the module's `custom.pif.prop`. Its own data
lives in `/data/adb/replay-integrity/`.
