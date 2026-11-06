# Replay Integrity — developer notes

These notes record what the engine does, why the pieces are shaped the way they are, and the
options that were considered and set aside. Read them with the crate documentation; every crate's
`lib.rs` states its own contract.

## The problem: a STRONG verdict that decays

A rooted device reaches the Play Integrity STRONG verdict with two modules working together:

- a keystore simulator (TEESimulator-RS, module `tricky_store`) that builds hardware key
  attestation certificate chains from an attestation **keybox**, so an app that verifies hardware
  key attestation sees a legitimate TEE; and
- a build spoof (PlayIntegrityFork, module `playintegrityfix`) that makes Google Play services
  report a Pixel build.

Both are known and maintained. What is not solved, and what Replay Integrity exists for, is that
the verdict reached this way decays over days. The AlwaysStrong module (which bundles the same two
halves) exhibits exactly this: STRONG for about two days, then DEVICE, then BASIC, and the only
reliable cure its users have is to **remove and reinstall the module**. That last fact is the clue
to the real cause.

## The four causes, separated

1. **The keybox is revoked or expires.** Google publishes a certificate revocation status list
   (`https://android.googleapis.com/attestation/status`) and adds leaked keyboxes to it, usually
   within days of discovery. A keybox also has a validity period. Either one ends a keybox's
   usefulness while nothing on the device changes.

2. **The spoofed Pixel build stops being accepted.** Canary fingerprints are short-lived; Google
   cross-checks the claimed first-API level against the device's real launch OS, so only a device
   that genuinely launched on Android 12 (the Pixel 6 series) still earns STRONG with a spoofed
   Pixel identity.

3. **The modules' own refresh scripts reset the spoof flags.** PlayIntegrityFork's `autopif`
   rewrites `custom.pif.prop` with a weak default set of flags (`spoofProvider=1`,
   `spoofVendingFinger=0`) that does not reach STRONG. Anything that keeps STRONG must re-apply the
   correct flags after every such run.

4. **Stale per-application keys — the reinstall clue.** TEESimulator-RS persists the keys it
   generates per application, each with the certificate chain it attested the key with, under
   `/data/adb/tricky_store/persistent_keys/`. When the keybox changes, those chains are **not**
   regenerated: an app that reuses its key keeps receiving a chain built from the old keybox. Once
   that old keybox is revoked or expires (cause 1), the app's attestation fails even though a valid
   keybox is installed. Removing and reinstalling the module "fixes" it only because uninstalling
   wipes `persistent_keys/`. This is why AlwaysStrong's Action re-run does nothing but a reinstall
   works.

Causes 1–3 are refresh problems, solved by fetching fresh inputs and re-applying settings. Cause 4
is a **repair** problem that no amount of refreshing fixes, and it is the one AlwaysStrong never
addressed. Replay Integrity reads each persisted key, finds the ones whose chain was signed by a
key that is not in the current keybox, and deletes them; the daemon regenerates them against the
current keybox the next time each app asks. This runs at every boot (through the root manager's
boot scripts) and on a schedule, so the verdict does not drift.

## Why an app, and why this split

AlwaysStrong is a Magisk module with a WebUI and a pile of shell scripts. Replay Integrity is an
app, like TypeFace Droplet, with a small Kotlin GUI (Material 3 Expressive) and a Rust engine. The
split puts every trust decision — parsing DER, checking certificate chains against the Google trust
anchors and the status list, judging a keybox — in the engine, where it is covered by tests and
cannot be fooled by malformed input. The app's job is the network and the screen.

### The engine performs no network access

Downloading the keybox, the fingerprint and the status list is left to the app, which has the
platform's ordinary TLS. Reimplementing TLS in the engine (as AlwaysStrong's `asfetch` does, with
rustls) was considered and rejected: it is a large dependency to audit, the app already has working
TLS, and keeping the network out of the engine means the engine's whole input surface is "bytes
from a file", which is simple to reason about and to test. The engine never makes a trust decision
from unchecked input: a downloaded keybox is parsed and checked before it replaces the installed
one, and a keybox with no usable key is reported but a keybox that is merely weak is still
installable, because the decision of what to run is the user's.

### The modules are driven, not replaced

Replay Integrity installs TEESimulator-RS and PlayIntegrityFork through the root manager's own
module installer (`magisk --install-module`, `ksud module install`, `apd module install`) and
writes their configuration files, but it does not fork or bundle them. This keeps their upstreams
authoritative and means a module update is an ordinary module update.

## The generic crates

Each crate is a complete, reusable library, not an internal helper:

- `der` is a general ASN.1 DER reader (X.690), usable for any DER structure, not only
  certificates. It accepts only the definite-length form and the shortest encodings DER requires.
- `x509` is X.509 (RFC 5280), PEM (RFC 7468) and the key types, parsed but not verified — it
  exposes fields to compare, which is what a device needs to judge the chains it hands out.
- `attestation` is the Android key-attestation extension, the Google trust anchors, the status
  list and chain checks.
- `keybox` is the keybox XML format.
- `prop` is `key=value` property files that keep their comments and order.
- `android` is the Android system interfaces.

The embedded Google trust anchors (`crates/attestation/roots/google.pem`) are the two roots
`developer.android.com` lists, verified byte-for-byte against `https://android.googleapis.com/attestation/root`
when this crate was written. The app also fetches the live list and can pass it, so a new root does
not require an app update, but the embedded copy means the engine can check a chain offline.

### Signatures are not verified on the device

The chain checks confirm a chain's shape — links, validity periods, revocation, and that it ends in
a Google root by public key — but do not verify the cryptographic signatures. Verifying signatures
on the device that holds the keys is of limited value (a compromised device could be made to accept
anything), and Google's own guidance is to verify on a separate trusted server. What the device can
usefully know is whether the keybox it is about to rely on is revoked, expired, untrusted or
structurally broken, and that is what the checks report.

## Validity of factory keys

Google trusts factory attestation keys after their certificates expire, as long as they are not on
the status list, for chains to the RSA root with subject `SERIALNUMBER=f92009e853b6b045` that carry
no remote-provisioning (RKP) extension. The chain check mirrors this: it skips the validity-period
check for exactly those chains, and enforces it for every other chain, including remotely
provisioned ones, whose shorter validity is part of their threat model.

## Permissions at launch

The app must ask for what it needs while the user is there. Earlier versions read the status
right away with a non-interactive privilege selection: the Shizuku binder had not arrived yet (it
comes only once the app is in the foreground), its permission was never requested, and the app
showed only that no privilege was available. The launch now follows TypeFace Droplet: it waits up
to two seconds for the Shizuku binder, then selects the privilege with `interactive = true`, which
asks for the Shizuku permission before falling back to `su` (whose first use opens the prompt of
Magisk; KernelSU and APatch need the app to be allowed in their manager, which the setup text
says). A refusal is remembered (`permissionDeclined`), because Shizuku keeps none, and asked again
only when the user taps **Grant** or changes the privilege choice. Workers never ask: they select
non-interactively and wait for the Shizuku binder after a boot.

`PrivilegeSelector` and the privileges are the same classes as Droplet's, with two hardening
changes: Shizuku can stop between two of its calls, so `status` turns a `RuntimeException` into
"not running", and `bindUserService` failing resumes the connection with an error instead of
leaving it waiting for the timeout. `ProcessRunner` bounds how long it waits for the output of a
process that left a child holding its pipes.

## Restricted root

Running as uid 0 does not imply the capabilities of root: Magisk's "Restrict" policy drops them.
The engine then could not read the files the app hands it (in the app's private directory) or
end processes of other users, and every operation failed with a misleading I/O error. The engine
checks `CAP_DAC_READ_SEARCH`, `CAP_KILL` and `CAP_SYS_PTRACE` (the ones it uses) before every
command that changes the system and fails with kind `restricted`; `status` reports the missing
ones instead of failing, so the home screen can explain the cause. The list is deliberately the
capabilities actually used, not "all of them", so that a root manager that drops unrelated ones
still works.

## The boot hook

Three defects of the earlier hook were fixed together:

- It ran the engine from the app's native library directory. That path changes with every
  update of the app (`/data/app/~~random/...`), so the hook silently stopped working after an
  update. The hook now runs a copy of the engine in the store (`/data/adb/replay-integrity/replay`),
  copied whenever the hook is installed; this is the approach of Droplet.
- It ran without the user's settings, so the spoof overrides were replaced by the recommended
  flags at every boot. `apply` now saves the settings it applied to the store (`settings.json`),
  and `boot` applies those. A saved file that cannot be read is an error, not the defaults:
  silently applying defaults would undo the user's choices.
- It rebuilt `target.txt` before the framework starts, when `cmd package` does not work, and the
  engine used an empty package list in that case, truncating the list to the Play stack. Now
  `boot` keeps `target.txt` (`ApplyMode::EarlyBoot`), `PackageManager::installed` refuses a list
  without the `android` package, and an `apply` whose package listing fails keeps the existing
  file with a warning. The app's repair after boot rebuilds the list once the system runs.

The hook also removes itself when the app is uninstalled: `boot --package` looks the package up
in `/data/system/packages.list`, which the package manager rewrites as soon as a package is
installed or removed and which is readable before the framework starts. A list that cannot be
read counts as holding the package, so that the hook never removes itself only because it could
not look. Two alternatives were rejected. Asking the package manager fails for the same reason
the target list is kept: it does not run yet. Scanning `/data/app` for `<package>-*` (Droplet's
method) misses applications on adopted storage, which is not mounted at that stage, so the hook
would remove itself at every boot for them.

## Settings

The app keeps its settings as one JSON document (`Settings.Values`) rather than one preference
per field, so that a change is written whole and fields can be added without migration code;
unknown fields are ignored and unknown enum values fall back to defaults, so both newer and older
versions read the document. Only the part the engine uses (`EngineSettings`: extra and excluded
packages, target mode, spoof overrides) is passed with `--settings`; the engine rejects package
names that are not package names, because they are written line by line into `target.txt`, and
overrides of unknown flags. The app compares the settings it would apply with those the engine
saved and shows "changes not applied yet" until they match.

The fingerprint is kept in the store as it was downloaded, and the spoof flags are applied only
to the `custom.pif.prop` the module reads. Earlier versions stored it with the flags, which made
the stored copy depend on the settings of the moment. `status` reads the live `custom.pif.prop`
too, so the app can show which flags another script (such as the module's `autopif`) rewrote.

## Downloads

The sources are settings, so the user is not tied to one mirror. Only HTTPS is accepted, also
for redirects. A keybox may be served as XML or as base64 of it (the default mirror serves
base64); anything else is refused before it reaches the engine. The certificate status list is
cached for an hour; when it cannot be downloaded, a copy up to a week old is used, and without one
the engine reports that revocation was not checked. A failed download never stops the apply:
the installed files stay.

Restarting the keystore ends the Play processes, so a refresh restarts only when an input changed
or on the first apply, and only when the user allows restarts at all. The repair after boot does
not restart the Play processes the system has just started; it restarts the keystore daemon only
when it removed stale keys that the running daemon may still hold.

## Information the app does not take from the engine

The device's own model, Android version, security patch and build fingerprint come from
`android.os.Build` in the app, which Play Integrity Fork does not spoof there. The first API level
comes from the engine (`ro.product.first_api_level` and its fallbacks), because the platform has
no public API for it; reading the property by reflection from the app was rejected as relying on
hidden APIs.

## What was taken from AlwaysStrong, and what was not

AlwaysStrong was reviewed for behaviour that keeps the verdict and that Replay Integrity lacked.
Four pieces were taken over, each reshaped to fit the engine:

- **The package watcher.** AlwaysStrong's `aswatcher` adds a newly installed application to
  `target.txt` at once. Before, Replay Integrity rebuilt the list only on a refresh (every six
  hours by default) or a repair, so an application installed in between, typically a bank's,
  went without attestation for hours. See *The package watcher* below.
- **Disabling conflicting modules.** AlwaysStrong marks conflicting modules for removal at
  installation and at every boot. Replay Integrity only reported them. `disable-conflicts` now
  writes the `disable` marker on request. It is a button, not something done at every boot,
  because an app should not change other modules without the user. It disables rather than
  removes, so the user can undo it in the root manager and loses no files or settings. The marker
  goes into a pending update in `modules_update` too, because that directory replaces the
  installed one at the next boot. Modules that hold a component's ID but are not the supported
  module (`Flavor::Other`) are not disabled: that would leave no module in that place.
- **`custom.pif.json` import.** AlwaysStrong's `import_pif.sh` accepts both formats of
  PlayIntegrityFork. The engine converts the JSON to the prop format and keeps the order of the
  entries (`serde_json::Map` sorts keys; a small visitor reads them in order rather than adding
  the `preserve_order` feature and its dependency). A key with the `//` prefix, which comments out
  an entry in that format, becomes a `#` line. A value or key that could not be written back as
  exactly one `key=value` line (a line break, an `=` in the key, a nested value) rejects the whole
  file, because converting it would add entries the file did not have.
- **Writing only what changed.** TEESimulator-RS reloads `target.txt` and `security_patch.txt`,
  and drops its patched certificate chains on a keybox write, whenever it sees one
  (`FileObserver` on `CLOSE_WRITE` and `MOVED_TO`). `target.txt`, `security_patch.txt`,
  `custom.pif.prop`, the boot scripts and the engine copy are now written only when their contents
  differ (`Files::write_if_changed`). The keybox was already written only on a change.

The rest was left out on purpose:

- **Global property spoofing** (`resetprop` of the verified-boot, build-type and OEM warranty
  properties, `prop_unify.sh`, the ROM spoof-engine block). PlayIntegrityFork does these in its
  own `post-fs-data.sh`, `service.sh` and `common_setup.sh`, and AlwaysStrong has them only
  because it absorbs PlayIntegrityFork into one module. Repeating them would fight the module
  this engine drives. AlwaysStrong itself ships `prop_unify.sh` without running it, because a
  global spoof leaks the Pixel identity to every process.
- **DenyList entries, hiding recovery folders, log cleaning, the VBMeta digest.** These hide root
  from applications, which is a separate concern from attestation, and their safe settings depend
  on the hider in use (AlwaysStrong's own notes on Magisk's built-in Zygisk with enforcement on).
  Doing them silently would surprise users.
- **A watchdog for the keystore daemon.** TEESimulator-RS's `supervisor` already restarts its
  daemon; a second supervisor would only race it.
- **Its own TLS fetcher.** See *The engine performs no network access*.

## The package watcher

`replay watch --package <application>` is a process that runs while the system runs. It waits
until `sys.boot_completed`, rebuilds `target.txt` with the settings saved by the last `apply`,
then waits for `/data/system/packages.list` to change and rebuilds the list again, three seconds
after a change, so that the several writes of one installation cause one rebuild. The package
manager rewrites that file whenever a package is installed, updated or removed. It writes a
temporary file and renames it over the list, so the watch is on the directory (`FileWatch`, an
inotify watch on `/data/system` filtered by name): a watch on the file itself would follow the
replaced inode and see nothing more. A blocking inotify read costs no CPU until the kernel reports
an event. Events of other files in `/data/system` are read and dropped; files in its
subdirectories cause none.

It is started by a second boot script, in `service.d` (the `service` stage, which Magisk, KernelSU
and APatch all run from that directory), in the background so that the root manager never waits
for it. `hook install` starts it at once when it does not run, so that it works without a reboot.
`--no-watch` (the setting **Add new apps at once**) removes the service script and ends the
watcher. Watching needs the boot hook, because the watcher runs the hook's copy of the engine.

One watcher runs at a time: it holds an exclusive `flock` on `watch.lock` in the store and writes
its process ID there. The kernel releases the lock when the process ends, however it ends, so a
crash leaves no stale lock. Whether a watcher runs is decided without touching the lock: the
process ID in the file must name a process whose command line is the store's copy of the engine
running `watch`. Reading `/proc/<pid>/cmdline` tells a reused process ID apart, and unlike
`/proc/<pid>/exe` it still names the path after that file was replaced. Probing the lock instead
was rejected, because a probe at the moment a watcher starts would make that watcher believe
another one runs, and it would exit.

The watcher ends when the application is uninstalled (it removes the boot hook, as `boot` does,
from the same `packages.list` test) and when the boot hook is removed. `hook remove` ends it with
a signal. When `hook install` replaces the engine copy (an update of the application), it ends the
watcher that runs the old copy and starts the new one. A rebuild that fails is logged and the
watcher goes on. It keeps no log lines in memory, and the log file is now rotated before every
line rather than only when a command starts, so a long-running process cannot grow it without
bound.

Alternatives that were set aside: a manifest receiver for `ACTION_PACKAGE_ADDED` receives nothing
since Android 8, because that broadcast is not exempt from the limits on implicit broadcasts. A
receiver registered at run time works only while the app's process lives. A frequent periodic
job (`PackageManager.getChangedPackages`) still leaves a delay of fifteen minutes or more, longer
in Doze. A watcher inside the boot script itself (a shell loop like AlwaysStrong's) would poll or
need tools the device may lack.

### Two writers of one file

The watcher and an `apply` of the app can write `target.txt` at the same moment. `write_atomic`
used one temporary name per file, so one process could delete the other's temporary file and
rename a partly written one into place. The temporary file is now named after the process ID, so
each process renames only its own whole file and the last rename wins. Both build the same list
from the same settings.
