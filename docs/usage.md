# Using Replay Integrity

Replay Integrity keeps Play Integrity at `STRONG` on a rooted device, and keeps it there, by
driving two modules: TEESimulator-RS (key attestation) and PlayIntegrityFork (build spoof).

## Requirements

- A rooted device with **Magisk**, **KernelSU** or **APatch**.
- A **Zygisk** implementation for the build spoof: Magisk's built-in Zygisk, or a standalone
  Zygisk Next / ReZygisk / NeoZygisk (required on KernelSU/APatch). The checklist says when none
  is present.
- A way to run the engine as root: `su` of the root manager, **Sui**, or **Shizuku started with
  root**. A Shizuku started through wireless debugging or ADB runs as the shell user, which cannot
  write `/data/adb`; the app says so.
- The root must be **unrestricted**. Magisk's "Restrict" policy (and similar profiles of other
  root managers) runs the app as root without the capabilities of root; the app detects this and
  explains how to grant full access.
- Android 13 (API 33) or later.

## First run

1. Open the app. It waits briefly for Shizuku, then **asks for the permission it needs**: the
   Shizuku dialog, or the root manager's `su` prompt. On KernelSU and APatch, allow the app in the
   manager first, then tap **Check again**. If nothing can run as root, the Home screen lists each
   way and what it lacks.
2. Install the modules if they are missing: on the **Attestation** tab, open **Releases** of each
   module, download the zip, and use **Install zip**. Reboot afterwards.
3. Tap **Set up** on the Home screen. The app downloads a keybox and a Pixel fingerprint, checks
   and installs them, writes the attestation target list, the security patch and the spoof flags,
   restarts the keystore, and installs the boot hook. No reboot is needed.

## The Home screen

- The **verdict** at the top: ready for STRONG, needs attention, not set up, or why the app cannot
  act (no root, restricted root).
- **Refresh** downloads fresh inputs and applies them. **Repair** re-applies everything and removes
  stale keys without downloading.
- The **checklist**: both modules, Zygisk, the keybox (usable EC and RSA keys, revocation,
  expiry), the fingerprint (model, patch, expiry), the spoof flags (and whether another script
  rewrote them), the per-app keys (how many were made with an old keybox), the keystore daemon,
  conflicting modules, and what runs at boot. Tap an item to see its details.
- **Details**: the privilege in use, the root manager, the last refresh and its problems, the last
  apply, and the engine log of the last operation.
- **This device**: the real model, Android version, security patch, first API level and build
  fingerprint.

## Attestation

- **Keybox**: every key with its algorithm, serial number, root, validity and problems; where the
  keybox came from, when it was installed and its hash. **Import keybox** checks a file of your
  own and shows the result before installing it.
- **Fingerprint**: the spoofed build, device, security patch and estimated expiry. **Import
  fingerprint** takes a `custom.pif.prop`, or a `custom.pif.json` (the earlier format of
  PlayIntegrityFork, which other tools still write), which is converted to the prop format; an
  entry commented out with `//` stays commented out.
- Importing a file turns off the automatic refresh of that file, so that it is kept.
- **Spoof flags**: each flag can be left at its recommended value, or forced on or off. The value
  applied and the value the module reads now are shown; a red value was changed by another script.
- **Modules**: name, version, author and state of both modules, with their releases and a zip
  installer.
- **Conflicts**: modules that change the same things (other keystore simulators, other Play
  Integrity fixes, tools that rewrite `target.txt`) are listed with a **Disable** button. It
  marks them disabled in the root manager from the next boot; their files stay, and they can be
  enabled again there. Reboot afterwards.

## Targets

The applications whose keys TEESimulator-RS attests (`target.txt`). Google Play services, its
framework and the Play Store are always targets; installed third-party applications and wallet
applications are added automatically; Xposed managers are always left out.

- **Key handling**: Automatic, Generate or Patch, for every target.
- **Added packages**: system applications (or any package) to attest too.
- **Excluded packages**: applications that keep the device's own attestation. A target can also
  be excluded from the list with its button.

Changes to targets and spoof flags take effect when they are applied; the app shows a notice with
**Apply now** until then.

With **Add new apps at once** (Settings, Boot), an application installed while the system runs is
added to `target.txt` within seconds, with the settings applied last; one removed is taken out.
Without it, the list follows the installed applications at the next refresh or repair.

## Settings

- **Privilege**: Automatic (Sui or Shizuku as root first, then `su`), Shizuku/Sui only, or `su` only.
- **Refresh**: whether the keybox and the fingerprint are refreshed, the interval of the scheduled
  refresh (off, 3, 6, 12 or 24 hours), and whether it waits for an unmetered network.
- **Sources**: the HTTPS URLs of the keybox and the fingerprint. The keybox may be served as XML or
  base64 of it. Everything downloaded is checked by the engine before it is installed.
- **Applying**: whether a change restarts the keystore and ends the Play processes at once, and a
  button that restarts them now.
- **Boot**: the boot hook (the root manager runs the engine before the keystore daemon starts),
  **Add new apps at once** (the boot hook also runs the package watcher, which updates the target
  list when an application is installed or removed; it needs the boot hook), and the repair the
  app runs once the system has started.
- **Notifications**: whether failures of the boot repair and of scheduled refreshes are notified.

## Where the files are

Replay Integrity writes the configuration the modules read: `keybox.xml`, `target.txt` and
`security_patch.txt` under `/data/adb/tricky_store/`, and the module's `custom.pif.prop`. Its own
data lives in `/data/adb/replay-integrity/`: its state, the settings applied last (which the boot
hook applies), the installed fingerprint, the keybox replaced last, its log, the copy of the
engine that the boot hook runs, and the lock of the package watcher (`watch.lock`, which holds its
process ID). The boot hook is `replay-integrity.sh` in `post-fs-data.d` (Magisk) or `post-mount.d`
(KernelSU, APatch), and, for the package watcher, in `service.d`.

When the app is uninstalled, the boot hook removes itself (and the engine copy): the package
watcher does so as soon as the package list changes, and the early script at the next boot.
The module files stay, so the modules keep working with the last configuration.
