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
  the outdated keys that the settings allow (see "Outdated keys" below) without downloading. A key
  is deleted through the keystore, as the app that owns it, together with a key of the device's own
  keystore under the same name: an app could otherwise pick up that older key, which reports the
  device's real (unlocked or self-signed) boot state, until it happens to make a new one. This is
  done only while TEESimulator-RS is active; without it, that older key is the app's own and is
  left alone. When the keystore cannot delete the key, it is kept, still shown as stale, and the
  next repair tries again.
- The **checklist**: both modules, Zygisk, the keybox (a usable EC key, revocation, expiry, and
  whether the keystore can read the file), the fingerprint (model, patch, expiry), the spoof flags (and whether another script
  rewrote them), the per-app keys (how many were made with an old keybox or security patch), the keystore daemon,
  conflicting modules, and what runs at boot. Tap an item to see its details.
- **Details**: the privilege in use, the root manager, the last refresh and its problems, the last
  apply, and the engine log of the last operation.
- **This device**: the real model, Android version, security patch, first API level (unknown
  when the device does not report it) and build fingerprint.

## Protection

Some settings trade the safety of your data and of the device against how surely and how quickly
STRONG is reached. **Settings → Protection** sets all of them at once; each one can then be
adjusted on its own, and the protection reads **Custom** until one is chosen again.

| Setting | Maximum safety | Balanced (default) | Integrity first |
| --- | --- | --- | --- |
| Replace the keybox | When needed | When needed | Whenever not worse |
| Targets | Google Play + wallets | All applications | All applications |
| Key handling of Google Play | Automatic | Generate | Generate |
| Key handling (other targets) | Automatic | Automatic | Automatic |
| Outdated Play Integrity key | When replaced | When replaced | When replaced |
| Outdated other Google Play keys | Never | Never | When replaced |
| Outdated keys of other applications | Never | Never | When replaced |
| Renew the Play Integrity key on a new patch | On | On | On |
| Restart the keystore on changes | Off | On | On |
| Also end background applications | Off | Off | On |

- **Balanced** reaches STRONG almost surely while keeping what you set up: the keybox is replaced
  only when it must be, and the only key removed when it is outdated is the Play Integrity key,
  which holds nothing of yours. Cards in Google Wallet, passkeys and applications' enrolments
  survive a new keybox and a new security patch.
- **Maximum safety** changes as little as possible: fewer applications are targets, Google Play
  keeps the device's own keys while its keystore works, and changes wait for the next reboot.
  STRONG may be lost on a device whose own keystore fails attestation, and after a change until
  the reboot.
- **Integrity first** takes a mirror's newer keybox at once and removes every outdated key as
  soon as its keybox is replaced. Cards, passkeys and enrolments are lost at every change of the
  keybox and must be set up again.

The Play Integrity key is removed when outdated in every protection: the Play Store makes it
again, and it holds nothing of yours, so keeping it would cost STRONG for nothing.

### Outdated keys

TEESimulator-RS keeps the keys it made for each application with the certificate chain of the
keybox in use at the time. When the keybox changes, those keys keep the old chain: they are
**outdated**. Each kind of key has its own setting (**Settings → Outdated keys**):

- **Never**: the key is kept. It keeps working as long as its old keybox is valid.
- **When unusable**: the key is removed once its old chain is known to fail: revoked (seen with
  Google's certificate status list), expired or untrusted.
- **When replaced**: the key is removed as soon as the keybox changes.

The kinds are the **Play Integrity key** (the Play Store's key for the Play Integrity API),
**other Google Play keys** (Google Wallet's tap-and-pay cards and passkeys live in Play services)
and **keys of other applications**. A key whose application cannot be told is treated as another
application's, the most careful kind. The Play Integrity key is also outdated when it was made
with another security patch than the current fingerprint's, unless **Renew the Play Integrity key
on a new security patch** is off; other keys keep the patch they were made with, as on a genuine
device.

Outdated keys that the settings keep are listed under **Attestation → Outdated keys**, each with
what it is for and why it is outdated, and a **Remove** button that asks before it removes the
key. An application that checks its key attestation itself may fail once the old keybox of its
key is revoked; removing that key there fixes it, at the cost of setting the application up
again.

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
- **Outdated keys**: the keys made with a keybox or security patch that is no longer configured,
  whether the next repair removes them, and a **Remove** button for those the settings keep (see
  "Outdated keys" above).
- **Modules**: name, version, author and state of both modules, with their releases and a zip
  installer.
- **Conflicts**: modules that change the same things (other keystore simulators, other Play
  Integrity fixes, tools that rewrite `target.txt`) are listed with a **Disable** button. It
  marks them disabled in the root manager from the next boot; their files stay, and they can be
  enabled again there. Reboot afterwards.

## Targets

The applications whose keys TEESimulator-RS attests (`target.txt`). Google Play services, its
framework and the Play Store are always targets; Xposed managers are always left out.

- **Targets**: which installed applications are added automatically: Google Play only, Google
  Play and wallet applications, or all applications (every third-party application and the
  wallet applications; the default). Within the chosen choice, applications installed only in
  another user or profile (a work profile, Secure Folder, Second Space) count too. An application
  that checks key attestation itself passes
  only as a target; one that is not a target keeps the device's own keystore.
- **Key handling**: Automatic, Generate or Patch, for every target but Google Play.
- **Key handling of Google Play**: the same choice for Play services, its framework and the Play
  Store. Generate is the default and is recommended (TEESimulator-RS documents
  `com.google.android.gms!`): Play Integrity then always gets a key attested with the keybox.
  If you had chosen Generate or Patch for every target before this setting existed, Google Play
  keeps that choice.
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
- **Protection** and **Outdated keys**: see "Protection" above.
- **Refresh**: whether the keybox and the fingerprint are refreshed, when a downloaded keybox
  replaces the installed one (below), the interval of the scheduled refresh (off, 3, 6, 12 or 24
  hours), and whether it waits for an unmetered network.
- **Sources**: the HTTPS URLs of the keybox and the fingerprint, and further keybox URLs tried in
  order when the first cannot be downloaded or serves a worse keybox. The keybox may be served as
  XML or base64 of it. Everything downloaded is checked by the engine before it is installed.
- **Applying**: whether a change restarts the keystore and ends the Play processes at once,
  whether a restart also ends every background application (so that other targets ask for their
  keys again at once), and a button that restarts them now.
- **Boot**: the boot hook (the root manager runs the engine before the keystore daemon starts),
  **Add new apps at once** (the boot hook also runs the package watcher, which updates the target
  list when an application is installed or removed; it needs the boot hook), and the repair the
  app runs once the system has started.
- **Notifications**: whether failures of the boot repair and of scheduled refreshes are notified.

## How a keybox is installed

**Replace the keybox** (Settings → Refresh) decides when a downloaded keybox replaces the
installed one:

- **When needed** (the default): only when the installed keybox has no usable EC key, or will not
  have one at the end of the expiry margin (48 hours by default; 72 or 168 can be chosen, all longer than the longest scheduled refresh):
  it is missing, revoked, untrusted, or about to expire. A working keybox is kept, so the keys made
  with it stay current, and the other sources are not asked. Revocation is seen only with Google's
  certificate status list; while it cannot be downloaded (for up to a week a copy is used), a
  revoked keybox is replaced only once it expires. The list is downloaded past Google's edge caches,
  which otherwise hand out a copy up to a day old and so hide a revocation for that long.
- **Whenever not worse**: whenever the downloaded keybox is not worse than the installed one, before
  the installed one can leak and be revoked. Every change outdates the keys made with the old one.

In both, a downloaded keybox is installed only when it is at least as good as the installed one:
it must have a usable EC key if the installed one has one, and, when both or neither have one,
at least as many usable keys. A keybox
that a mirror serves revoked, expired or untrusted is therefore kept out, and the next source is
tried; the installed keybox stays, and this is not reported as a failure. Broken XML alone does
not keep a keybox out, because its keys are written again (below). A keybox you import is
installed even when it is weak, as long as one of its keys matches its certificate.

What is written to `keybox.xml` is not the downloaded file itself but its keys, checked and
written again as a well-formed keybox: mirrors often serve files with broken XML (a missing
quote, a watermark element), from which the keystore would read no key at all. When a keybox
has usable keys, the others (revoked, untrusted, expired) are left out, so that the keystore
never uses them. A `keybox.xml` that another tool put there with broken XML is written again,
with the keys that can be recovered from it, at the next repair or boot; the original is kept in
`/data/adb/replay-integrity/` as the previous keybox. Recovering keys keeps one keybox without its
device ID, which the keystore does not read.

An RSA key is not needed for STRONG: Play Integrity attests with EC, and TEESimulator-RS signs
RSA requests with the EC key when there is no RSA key.

## Where the files are

Replay Integrity writes the configuration the modules read: `keybox.xml`, `target.txt` and
`security_patch.txt` under `/data/adb/tricky_store/`, and the module's `custom.pif.prop`. Its own
data lives in `/data/adb/replay-integrity/`: its state, the settings applied last (which the boot
hook applies), the certificate status list applied last (with which the boot hook judges
outdated keys), the installed fingerprint, the keybox replaced last, its log, the copy of the
engine that the boot hook runs, and the lock of the package watcher (`watch.lock`, which holds its
process ID). The boot hook is `replay-integrity.sh` in `post-fs-data.d` (Magisk) or `post-mount.d`
(KernelSU, APatch), and, for the package watcher, in `service.d`.

When the app is uninstalled, the boot hook removes itself (and the engine copy): the package
watcher does so as soon as the package list changes, and the early script at the next boot.
The module files stay, so the modules keep working with the last configuration.
