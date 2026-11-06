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

## Keyboxes as mirrors serve them

Replay Integrity and AlwaysStrong download the keybox from the same mirror, yet AlwaysStrong kept
STRONG while Replay Integrity fell to below BASIC with a keybox Google had revoked. The defects
below were found by comparing the two and are fixed whatever the rest of the explanation is.

What was not established is how AlwaysStrong's own setup reads the mirror's latest file: by the
source of `KXmlParser`, TEESimulator-RS reads no key from it either (see below). Whether the
mirror serves other clients other bytes was not tested. The engine does not depend on the
answer: it installs a well-formed keybox of checked keys whatever the mirror serves.

### What the mirror serves

The mirror serves an ECDSA-only keybox with a short-lived chain (leaf, `Droid CA3`, `Droid CA2`,
the 2025 root `Key Attestation CA1`), replaced every few days. Its markup is broken on purpose or
by accident: the latest one had `<Keybox DeviceID="t.me/... @evokerr>` without the closing
quote, and an earlier one added a watermark `<Key algorithm="@evokerr">`. HTTP and HTTPS return
the same bytes.

The unclosed quote puts the following `<Key algorithm="ecdsa">` tag inside the attribute value.
No conforming XML parser reads a key from that document:

- the engine's `quick-xml` stops with "attribute value not closed";
- TEESimulator-RS (`KeyBoxManager.parseKeysFromXml`) uses Android's `XmlPullParser`
  (`KXmlParser`) in its default, non-relaxed mode, which throws at the `<` inside the attribute
  value (`checkRelaxed("Illegal: \"<\" inside attribute value")`). `parseKeyStoreFile` catches
  the exception and returns no keys, so the daemon then has no keybox at all.

### What went wrong in Replay Integrity

1. **A download that does not parse kept the old keybox.** `install-keybox` rejected the
   document, the refresh logged a problem, and the keybox installed earlier stayed. Once that
   keybox was revoked, the device kept attesting with a revoked chain, and the per-application
   keys made with it (see cause 4) kept failing too.
2. **STRONG was judged to need an RSA key.** `is_strong_capable` asked for a usable EC key and
   a usable RSA key. The mirror's keyboxes are EC only, so even a parsed one would have been
   reported as weak, and the repair would have tried to replace a working keybox. Play Integrity
   attests with EC, and TEESimulator-RS signs a request for an RSA key with the EC key when the
   keybox has none (`KeyBoxManager.getAnyAttestationKey`). An RSA key is now optional and still
   reported.
3. **The Play stack used the mode of every other target.** With `Auto`, TEESimulator-RS patches
   the certificates of the device's own keystore when that keystore works. AlwaysStrong forces
   generate mode (`!`) for Play services, its framework and the Play Store, and TEESimulator-RS's
   own README shows `com.google.android.gms!`. The Play stack now has a mode of its own
   (`Settings::play_target_mode`), `Generate` by default. Settings saved before the field
   existed read as `Generate` too, unless their `target_mode` was not `Auto`: that mode was then
   chosen on purpose for every target, the Play stack included, so it is kept (`Settings::parse`
   and the application's `Settings.decode` apply the same rule).

### What the engine does now

- **Recover, then write a well-formed keybox.** `KeyboxDocument::read` parses strictly and, when
  that fails, recovers the keys (`KeyboxDocument::recover`) from the PEM blocks alone: comments
  are removed, every valid PEM block is read in order, each private key begins a key and the
  certificates up to the next private key are its chain, as a keystore daemon takes them. The
  algorithm comes from the private key itself. The markup between the blocks is never read, so
  broken attributes, missing end tags and watermark elements, even one inside a `<Key>`, do not
  matter, and every key is a parsed private key with parsed certificates. Keybox boundaries and
  device IDs are markup too and are not recovered: the result is one keybox without a device ID.
  `defect` is set only when the text is not well-formed XML, which is what makes a daemon read
  no key; a well-formed document that breaks a rule of the format (a wrong declared count) is
  still read by the daemon, which ignores those rules, so it has no `defect`.
- **Install the checked keys, not the downloaded text.** `install-keybox` writes
  `KeyboxDocument::render` of the keys, which every XML parser reads, and only the usable keys
  when there are any (`KeyboxVerdict::keys_to_write`), so the daemon cannot prefer a revoked RSA
  key to a usable EC key. The daemon reads exactly what was checked.
- **Never downgrade on an automatic refresh.** With `--no-downgrade` (`KeyboxPolicy::NoDowngrade`)
  a keybox is installed only when it ranks at least as high as the installed one
  (`KeyboxVerdict::rank`: a usable EC key, then the number of usable keys). `defect` is not part
  of the rank on either side: the offered keybox is written again before it is installed, and an
  installed one with a `defect` is written again by the next `apply`, so the recovered keys are
  what counts. (An earlier draft ranked such an installed file lowest, which let a revoked
  download replace a file whose keys the repair would have made usable.) A keybox that ranks the
  same replaces the installed one, because a mirror rotates its keybox before a leak is listed,
  and expiry is not part of the rank for the same reason. A keybox the user imports is installed
  without this check: it is the user's decision.
- **Repair an installed keybox the daemon cannot read.** `apply` (at every boot, repair and
  refresh) writes the installed keybox again when it has a `defect`, for example one that another
  tool copied there. The daemon reads no key from such a file, so writing the recovered keys
  cannot leave it worse off. Every recovered key is written, because no key is judged without
  the status list, and the original is kept in the store as the previous keybox.
- **Several sources.** The application tries the keybox URL and then the further URLs of the
  settings in order, until the engine installs one or finds it is the installed one. A declined
  keybox is never a refresh problem: the installed one is better, which is the device as it
  should be, and a problem would make the scheduled refresh retry and notify a failure every
  time a mirror serves a worse keybox. A source that cannot be downloaded or checked is a problem
  only when no source was installed or declined.
- **Keys whose private key does not match.** Such a key is never written, and it no longer makes
  the whole keybox uninstallable: a keybox is installable when one key matches.

### Alternatives that were set aside

- **Asking the mirror differently** (another User-Agent, plain HTTP) was not pursued: the bytes
  were the same for every request tried, and making the application pass for another client to
  a server is not a fix this application should depend on.
- **Patching each defect** (accepting an unclosed quote, then the next trick) would repeat the
  watermark fix forever. Recovering from PEM blocks covers every defect of the markup at once.
- **Installing the downloaded bytes when they parse, and rendering only otherwise** would leave
  the daemon reading something other than what was checked whenever the two XML parsers
  disagree, and would keep revoked keys next to usable ones.
- **Relaxing the strict parser** would make `parse` accept documents that are not keyboxes.
  `parse` stays strict, because it states what a well-formed keybox is, and `recover` is a
  separate, smaller reader.
- **Cutting a recovered chain where a certificate does not link** was tried and dropped: it made
  recovery disagree with strict parsing for chains that are given as they are, and a chain that
  does not link is reported as unusable by the chain check in any case.
- **Ranking by expiry** would keep an old keybox over a mirror's replacement until the old one
  stopped working, which for a leaked keybox is the moment of revocation.

### The private key is kept in memory

Rendering needs the private key, so `KeyboxKey` keeps its PEM block (`private_key_block`), where
it used to keep only public information. Its `Debug` form leaves the block out, so a log line or
a panic message never carries the secret. The engine is a short-lived process, and the block is
written only to `keybox.xml` (mode 0600) and the store's copy of the previous keybox.

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

Then, when AlwaysStrong kept STRONG with a keybox that Replay Integrity rejected, three more were
taken over or bettered (see *Keyboxes as mirrors serve them*): generate mode for the Play stack,
EC-only keyboxes counting as STRONG-capable, and accepting the mirror's broken markup. On that last
point the engine goes further than AlwaysStrong, which copies the mirror's bytes as they are and
checks only that they contain the word `Keybox`: the engine writes a well-formed keybox of checked
keys, never replaces a working keybox with a worse one, and falls back to further sources.

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

The watcher ends when the application is uninstalled and when its service script is removed.
Uninstallation is read from `packages.list`, as `boot` does, and confirmed with the package
manager, because while the system runs the list also leaves out applications whose storage is
unmounted (an ejected adopted card); if the package manager cannot answer, nothing is removed.
`hook remove` ends the watcher with a signal and waits until it has ended. When `hook install`
replaces the engine copy (an update of the application), it ends the watcher that runs the old
copy, waits for it to release its lock, and starts the new one; without the wait, the old process
was still listed for a moment and no new one was started. A watcher started by the application
moves itself into the root cgroups and a session of its own, because an `su` that keeps the
child in the application's cgroup would let the system end it with the application. A rebuild that fails is logged and the
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

The watcher and an `apply` of the app can write `target.txt` at the same moment. Two measures
keep this safe. `apply` and each round of the watcher hold `apply.lock` in the store while they
read the settings and write, so the watcher cannot write a list built from settings that an
`apply` has just replaced. And `write_atomic` names its temporary file after the process ID:
with one fixed name, one writer (the boot hook's, another command's) could delete another's
temporary file and rename a partly written one into place. A writer killed between writing and
renaming leaves its temporary file behind; the next write of the same file removes those of
processes that no longer run.
