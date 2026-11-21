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
key that is not in the current keybox (and the key of the Play Integrity API when it attests
another security patch: see "Persisted keys and the security patch"), and deletes them; the daemon regenerates them against the
current keybox the next time each app asks. This runs at every boot (through the root manager's
boot scripts) and on a schedule, so the verdict does not drift. Deleting the file alone is not
enough when the device's own keystore holds a key under the same alias: see "Device keys under
the alias of a stale key".

## Device keys under the alias of a stale key

### What was seen

On a Pixel whose bootloader is locked with a custom AVB key (verified boot state `SelfSigned`,
yellow), Play Integrity reached STRONG on 2026-11-06, yet RCS
in Google Messages started working only a week later, right after the first reboot in five days.
The device's keystore2 database (`/data/misc/keystore/persistent.sqlite`) showed:

- a key of the Play Store, `integrity.api.key.alias` (the key of the Play Integrity API), made by
  the device's TEE on 2026-11-06 at 17:17:12 and attested by its remotely provisioned chain with
  `verifiedBootState = SelfSigned`; Replay Integrity was installed 26 seconds later;
- Replay Integrity's log: "removed a stale persisted key of uid 10140 (integrity.api.key.alias)"
  at 18:35 and 20:22 the same day (uid 10140 is the Play Store);
- nine keys of Play services with attestation chains, made by the TEE on 2026-10-30 and 10-31,
  before TEESimulator-RS was installed.

The logs of the following week were gone, so it was not established that this is what kept RCS
from working; Google Messages keeps no record of failed provisioning once it succeeds. The
mechanism below is established from the source of TEESimulator-RS v6.0.1 and is a defect
whatever caused the RCS delay.

### Why removing the file is not enough

TEESimulator-RS (`Keystore2Interceptor`) answers `getKeyEntry` for an alias with its own key
when it has one. When it has none, the call goes on to keystore2, and the reply is patched
afterwards only when `ConfigurationManager.shouldPatch(uid)` holds, which is the `Auto` and
`Patch` modes. For a `Generate` target (`!`), the default of the Play stack, a key that the
device's TEE made is returned **unpatched**, with the device's own root of trust: an unlocked or
self-signed boot.

Such a device key exists whenever the application made the key while TEESimulator-RS did not
generate its keys: before the module was installed, before the package was a target, or while
it was in `Auto` mode. As long as TEESimulator-RS has a key under that alias, it hides the device
key. Removing the persisted file and restarting the daemon takes the hiding key away, and the
application does not make a new key: it finds the device key under the same alias and uses it,
until it happens to replace it. The repair turns "attested by an old keybox" into "attested as
an unlocked device".

### What the engine does now

Each stale key is deleted through keystore2 itself, with its command-line client
`keystore_cli_v2 delete --name=<alias>` run as the application that owns the key
(`android::DeviceKeystore`). keystore2 names an application's key by the calling user and the
alias (`Domain::APP`), so the client must run as that user; the engine is root, sets the user and
the group (an application's group has the same number as its user, as Zygote sets it), and the
standard library clears the supplementary groups. The client reads the alias with
`GetSwitchValueASCII`, which gives an empty string for any alias that is not ASCII.

The deletion is repeated until the client exits with `KEY_NOT_FOUND` (7), at most
`Engine::STALE_KEY_DELETIONS` times. For a target, TEESimulator-RS answers the first deletion
for its own key (it removes the key from memory and deletes the persisted file), and keystore2
answers the next one for a device key under the alias. When the daemon does not run, as at the
boot hook, keystore2 answers them all: keystore2 is in `class early_hal`, which starts at
`late-fs`, before the hook, and the client asks for it without waiting. The engine then removes
the file if it is still there. Both answers were checked on a device (TEESimulator-RS v6.0.1,
Android 17).

For a package that is no longer a target, TEESimulator-RS passes the deletion to keystore2
without dropping its own key from memory, although it still serves that key to `getKeyEntry`;
the key stays served until the daemon restarts, as before this change. `ApplyMode::Restart`
restarts it, and so does the application after a repair that removed a key.

- **TEESimulator-RS not active.** A device key is deleted only while TEESimulator-RS hides it.
  When the module is not installed, is disabled or is being removed, or waits for the next boot
  in `modules_update`, a device key under the alias is the application's own key, in use (a
  banking application's enrolment, for example), and the persisted file is inert: the file alone
  is removed. A module disabled since the last boot still runs until the next one; it is treated
  as not active, which only gives up the deletion, never deletes a key in use.
- **The keystore cannot delete the alias.** When the client fails (keystore2 cannot be reached
  and the client exits with -1, a binder failure gives `SYSTEM_ERROR`, a policy denies it) or
  the engine cannot run it as the application (it is not root, or lacks `CAP_SETUID` or
  `CAP_SETGID`), the key is **kept** and counted in `ApplyReport::stale_keys_kept`, and the
  status keeps reporting it as stale; every later `apply` tries again. Removing it would bring
  the device key back, which is worse than a chain from an older keybox that may still be valid.
  On a device where the deletion never works, the repair of such keys is given up rather than
  made harmful. `CAP_SETUID` and `CAP_SETGID` are deliberately not in `Engine::CAPABILITIES`:
  only this deletion needs them, and a refresh or a keybox installation must not be refused for
  their lack.
- **No client, or an alias the client cannot take.** AOSP installs `keystore_cli_v2` with
  keystore2 (`keystore2_defaults` requires it), but a device maker can leave it out. When it is
  missing, or the alias was not read exactly (`PersistedKey::alias_exact`: the file holds
  modified UTF-8 that is not UTF-8, so the alias read names another key), or the alias is not
  ASCII, the file alone is removed, as before, with a warning. That is the only repair possible
  there, and keeping a stale key forever would be worse.

Only the alias of a key that is being removed is deleted. While TEESimulator-RS has a key under
an alias, it hides the device key for `getKeyEntry` and for operations alike, so the application
loses nothing it was using. Device keys of `Generate` targets that no persisted key hides (the
keys of Play services from before the module) are left alone: they are served unpatched too, but
nothing tells which of them matter for attestation, and deleting a key such as a Google Pay key
would lose the application's data.

An application that makes its key again while the deletions run (between two of them, or before
the file is removed) loses that new key and makes another one; the bound on the deletions keeps
this from repeating. The race of the file removal existed before this change.

### Alternatives that were set aside

- **Editing keystore2's database.** keystore2 owns it while it runs, and its rows refer to key
  blobs that its own garbage collection deletes from KeyMint. A root process writing it
  underneath is unsafe.
- **A helper that runs `AndroidKeyStore` as the owner through `app_process`.** It would also take
  aliases that are not ASCII, but outside an application the provider is not installed, and
  installing it uses hidden APIs; `keystore_cli_v2` is the client AOSP provides.
- **Patching device keys for `Generate` targets, or switching the Play stack to `Auto`.** The
  first is a change to TEESimulator-RS, not something its configuration can express; the second
  undoes the reason the Play stack generates its keys (see "What went wrong in Replay
  Integrity").
- **Deleting through the keystore only after a daemon restart.** It would reach keystore2 in a
  single deletion, but it would not work in `NoRestart` mode, and an application that makes its
  key between the restart and the deletion would lose it all the same. Deleting until
  `KEY_NOT_FOUND` works whether or not the daemon runs.
- **Removing the file when the deletion keeps failing**, after some number of attempts. It
  would turn a failure to repair into the harm this change prevents; the status already shows
  the stale keys, so the user can see that the repair does not complete.

## Persisted keys and the security patch

### What was seen

AlwaysStrong, on a Pixel 9a spoofing a Pixel 6a, stopped reaching STRONG on the day a new monthly
security patch came out. Its Action and its automatic refresh did not bring it back; reinstalling
the module did. The trigger was the monthly patch; the keybox is not known to have changed. The
explanation below comes from the source of TEESimulator-RS and AlwaysStrong; it was not
reproduced on that device.

### Why

TEESimulator-RS writes the security patch levels in use at generation into the attestation
extension of every key it generates (`osPatchLevel` as `YYYYMM`, `vendorPatchLevel` and
`bootPatchLevel` as `YYYYMMDD`), and keeps that certificate in `persistent_keys/` with the key.
When `security_patch.txt` changes, its `ConfigObserver` only reloads the patch configuration and
leaves the generated keys and their chains as they are; a keybox change does not re-sign them
either (cause 4), and only drops the chains of `Patch`-mode keys kept in memory. A key made before
the change keeps attesting the previous patch, while the fingerprint written with the new patch
makes Google Play services claim the new one. Reinstalling AlwaysStrong worked because its
`uninstall.sh` deletes `persistent_keys/`; its Action writes the new patch but keeps the keys.
Replay Integrity had the same gap: `stale_keys` compared only the signer of each chain.

### What the engine does now

`Engine::outdated_keys` also counts as outdated (`OutdatedReason::OldPatch`) the key of the Play
Integrity API when its attested OS, vendor or boot patch level differs from the configured patch.
That key (`KeyCategory::Integrity`) is one whose alias is in `KeyCategory::INTEGRITY_ALIASES`
(today `integrity.api.key.alias`, the key of the Play Store seen in "Device keys under the alias
of a stale key") and whose packages, from its `attestationApplicationId` or from the package
list by its user, include a package of the Play stack (`TargetList::ALWAYS`). Whether a repair
removes it is a setting (`KeyRemovalSettings::integrity_patch`, on by default; see "Safety and
integrity as settings"). The configured patch is read back from
`security_patch.txt` with `KeystoreConfig::security_patch_of`, the inverse of
`security_patch_contents`. `apply` writes the patch of the installed fingerprint before it looks
for stale keys, so a refresh that brings a new patch removes the key in the same run, and the
Play Store makes it again with the new patch.

- **The integrity key only.** Google Play services holds other device-bound keys as well (tap-and-pay tokens, passkeys, Find Hub), and
  whether they carry an attestation extension with an `attestationApplicationId` was not
  established; if they do, every monthly patch would delete them and the user would have to
  enrol cards or passkeys again. Other applications have the same concern (a banking
  application's enrolment). A genuine device keeps the generation-time patch in a key's
  certificate after an update too, so an older patch alone is no fault. The alias is the only key
  known to serve Play Integrity; another alias is added to the list once it is seen to.
- **Alias and package together.** Another application may use the same alias; the package of the
  attestation keeps its key out. An alias that is not read exactly (`PersistedKey::alias_exact`)
  is not compared.
- **Only the form this engine writes is judged.** TEESimulator-RS also reads a single date,
  `all=`, `prop`, `device_default`, `no`, date keywords and per-package sections, and resolves
  some of them from the device. Reproducing that would mean guessing; any other contents leave the patch out
  of the judgement, and only the signer is compared.
- **A level the certificate does not report, or a certificate that cannot be read, is not
  compared**: nothing shows that the key is wrong, and deleting it could only cost the user.

### Alternatives that were set aside

- **Deleting `persistent_keys/` when the patch changes**, as a reinstall does. It removes every
  application's keys, including those whose enrolment would be lost.
- **Comparing the patch for every target, or for every key of the Play stack.** See "The
  integrity key only" above.
- **Changing TEESimulator-RS to re-sign persisted chains when the patch changes.** That is a
  change to the module, not something its configuration can express.

## Safety and integrity as settings

### What was asked

A user asked whether a keybox update, or the refresh and repair after a monthly security patch,
resets NFC payments. Reading the engine answered it: after a monthly patch, no (only the
integrity key was compared by patch); after a keybox change, very likely yes.

### Why a keybox change reset payments

- `stale_keys` counted as stale **every** persisted key whose chain was signed by a key not in
  the current keybox, whatever the application. The Play stack generates its keys (`Generate`),
  so every key of Play services was among them, and Google Wallet's tap-and-pay tokens, passkeys
  and Find Hub keys live in Play services. Banking and wallet applications that TEESimulator-RS
  generated keys for were among them as well. Each such key was deleted, with what was enrolled
  with it.
- `NoDowngrade` installed a keybox whenever it ranked **at least as high** as the installed one.
  The mirror replaces its keybox every few days, so a working keybox was replaced every few days,
  and every replacement outdated every key.
- The removal did not ask whether the old chain had stopped working. A key on a keybox that is
  merely replaced keeps passing attestation until that keybox is revoked or expires.

That this reset payments was not reproduced on a device; it follows from the code and from where
Google Wallet keeps its tokens.

### What the engine does now

Every choice that trades the user's data, or the device's quiet, against how surely and how
quickly STRONG is reached is a setting, with a default that is the safe choice that still reaches
STRONG almost surely:

- **Which outdated keys a repair removes** (`KeyRemovalSettings`), by `KeyCategory`: the
  integrity key, the other keys of the Play stack, and every other application's keys. Each is
  `KeyRemoval::Never`, `WhenUnusable` (the old chain is known to fail: `PersistedKey::signer_problems`
  reports a problem of the certificates after the key's own, which are those of the keybox key
  that signed it) or `WhenReplaced` (as before). Defaults: `WhenReplaced` for the integrity key,
  `Never` for the others. A key whose packages cannot be told is an application's, the most
  careful category. `integrity_patch` keeps the security-patch rule switchable.
- **Kept keys stay visible and removable.** `Engine::outdated_keys` reports every outdated key
  with its category, packages, reasons and whether a repair removes it (`OutdatedKey`);
  `ApplyReport::outdated_keys_kept` counts those kept. `remove-key --uid --alias`
  (`Engine::remove_key`) removes one the settings keep, through the keystore as a repair would,
  under the lock of `apply`, and refuses any key that is not outdated. The alias is compared as
  reported, so a key whose alias is not read exactly can be removed too; its file alone goes.
- **The device's key of a non-target is never deleted.** A narrower `TargetScope` leaves
  persisted keys of applications that are no longer targets. TEESimulator-RS passes their
  deletion to keystore2, which would delete the application's own key under the alias, so
  `remove_stale_key` removes the file alone unless a package of the key is in `target.txt`, as it
  does while the module is not active.
- **When a downloaded keybox replaces the installed one** (`KeyboxPolicy::WhenNeeded`, the
  application's default): only when the installed keybox will not have a usable EC key at the end
  of a margin (48 hours by default, longer than the longest scheduled refresh), and never with a
  worse one. The decision is `KeyboxPolicy::declines`, so that it is tested without a
  Google-signed keybox. `Declined::NotNeeded` tells the application that the installed keybox is
  fine, so it stops asking the other sources.
- **The certificate status list for the boot hook.** `WhenUnusable` needs revocation, and the
  boot hook runs without the application. `apply` saves the list it is given in the store
  (`Store::status_list`) when it parses, and runs given none, or one that does not parse, judge
  with that copy. A copy misses later revocations, which only keeps keys. A repair and the
  removal of a key pass the application's cached copy and download nothing, as a repair is
  documented to.
- **Which applications are targets** (`TargetScope`): the Play stack only, with the wallet
  applications, or with every third-party application (the default, as before).
- **Whether a restart ends every background application** (`Settings::end_background_applications`,
  off by default). Play Integrity needs only `REFRESH_PROCESSES` ended; `kill_background` ended
  every background application on every restart before.

The application groups these into three protections (`Protection`): `SAFETY`, `BALANCED` (the
defaults) and `INTEGRITY`. Choosing one sets every setting it names; the settings then match no
protection once one is changed, and the screen says "Custom". The protection is not stored: it is
read from the settings, so it can never disagree with them.

### Why these defaults

- **The integrity key is removed when replaced in every protection.** It holds nothing of the
  user's, the Play Store makes it again, and a key on an old chain fails Play Integrity
  (cause 4). There is nothing to trade.
- **Other keys of the Play stack are kept by default.** Play Integrity attests a key made for the
  request, with a fresh challenge; a key that is reused with an old chain, as the integrity key
  is, is what makes it fail. That no other key of Play services is reused this way was not
  established on a device. If one is, `WhenUnusable` or `WhenReplaced` for the Play stack brings
  STRONG back at the cost of the cards, and `INTEGRITY` sets it.
- **`WhenNeeded` for the keybox.** With it the keybox changes mostly because it had to (revoked,
  expiring), so the integrity key is renewed rarely and the other keys stay current. A mirror's
  newer keybox would avoid the window between a revocation and the next refresh; the scheduled
  refresh (6 hours by default) and the status list cached for an hour bound that window.
- **`SAFETY` keeps the Play stack's keys in the device's keystore (`Auto`).** Keys that
  TEESimulator-RS generates are kept in files under `/data/adb`, outside the secure hardware.
  `Auto` patches the certificates of the device's own keys while that keystore works, so the
  keys stay in hardware; STRONG then depends on the device's keystore, which is why it is not
  the default. It also leaves third-party applications out of the targets and restarts nothing.

### Alternatives that were set aside

- **One switch between "safe" and "integrity".** The choices are independent (a user may accept
  losing a bank's enrolment but not cards), and the user asked to adjust everything.
- **The protections in the engine.** The engine reads settings, not intentions; a protection is a
  way to choose settings, and the boot hook applies the settings that were chosen. Keeping it in
  the application keeps the engine's settings a plain description of what it does.
- **Remembering the signers of earlier keyboxes** to judge an old chain. The persisted key holds
  that chain already; judging the chain itself also covers a keybox that another tool installed.
- **Removing the other Play keys by patch too.** See "Persisted keys and the security patch".

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
- **Never downgrade on an automatic refresh.** With `--policy no-downgrade` (`KeyboxPolicy::NoDowngrade`, and `WhenNeeded`, which adds to it)
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
  settings in order, until the engine installs one, finds it is the installed one, or keeps the
  installed one because it is not to be replaced yet (`Declined::NotNeeded`). A declined
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
  update. The hook now runs a copy of the engine in the store (`/data/adb/replay-integrity/replay-integrity`),
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
packages, target scope and modes, spoof overrides, key removal, ending background applications)
is passed with `--settings`; the engine rejects package
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
the engine reports that revocation was not checked. `apply` keeps a copy in the store for the boot
hook (see "Safety and integrity as settings"). A failed download never stops the apply:
the installed files stay.

Restarting the keystore ends the Play processes, so a refresh restarts only when an input changed
or on the first apply, and only when the user allows restarts at all. The repair after boot does
not restart the Play processes the system has just started; it restarts the keystore daemon only
when it removed stale keys that the running daemon may still hold.

## Other users and profiles

`target.txt` names packages, not users. Earlier versions built it from `cmd package list
packages`, which without `--user` lists the packages of the system user only. An application
installed only in another user or profile was then never a target: a work profile, Samsung's
Secure Folder, Xiaomi's Second Space, or a secondary user. The engine now lists the packages
(and the third-party ones) of every user that `cmd package list users` names and adds them to
those of the system user (`Engine::installed_packages`). The list of the system user must still
succeed and hold the `android` package, as before; a user whose packages cannot be listed is
skipped with a warning, so another user can only add targets, never shorten the list. An
application installed in several users appears once. `--user all` was not used, because what it
does differs between releases of the package manager; asking for each user is defined on every
release.

## Background work of the application

- **A stopped worker is not a failure.** WorkManager stops a running worker when its quota or
  runtime runs out, a constraint is lost, or a device maker's battery manager (MIUI/HyperOS,
  ColorOS, One UI) stops jobs, and it does so by cancelling the coroutine. The workers used to
  catch that cancellation as an error: the repair after boot notified a failure that was none,
  and the refresh counted it as a problem. They now let it through, so WorkManager runs the work
  again.
- **The repair after boot is enqueued with `KEEP`.** `BOOT_COMPLETED` normally comes once per
  boot, but a broadcast sent again (by a device maker's ROM or by hand) made `REPLACE` stop a
  repair in the middle of an engine command. `KEEP` is the safe choice in any case.
- **The hook is installed again after an update** (`MY_PACKAGE_REPLACED`, `HookWorker`). The boot
  hook and the package watcher run the copy of the engine in the store, which only installing the
  hook replaces; before, the previous engine kept running until the next refresh, or for ever with
  the refresh turned off. Nothing else is done then. A failure (Shizuku not started yet after the
  update) is retried three times with a backoff and not notified, because nothing is worse than
  before the update. An application that a cleaner force-stopped may not receive the broadcast;
  the next refresh then installs the hook. `QUICKBOOT_POWERON` of some device makers was not added: it
  is a resume from a deep sleep, not a boot, so the boot hook did not run and nothing needs repair.
- **Settings are written without blocking the screen.** `Settings.update` wrote with `commit` on
  the main thread, which stalls the screen on slow storage. On the main thread it now uses
  `apply`; off it (the workers), it still writes before returning, so that a process the system
  ends right after the work keeps what it did.
- **A Shizuku connection that times out or fails is released** (`unbindUserService`), instead of
  staying registered and adding one more connection at every attempt. The release is posted to
  the main thread, where Shizuku walks its connections, because releasing from a worker's thread
  while Shizuku delivers a connection could modify its set during that walk. A connection is not
  bound at all when the caller was cancelled before it started.
- **A download has a deadline** (`Downloader.TOTAL_TIMEOUT_MILLIS`). The timeout of each read
  never ends a server that sends a byte now and then, and a read blocked on a socket answers
  neither to the timeout nor to the cancellation of the coroutine; a refresh could hold the lock
  of the operations for hours. A watchdog closes the connection when the time is up or the caller
  is cancelled. Redirects are counted as such: five are followed, where four were.
- **Keyboxes do not stay in the cache.** A downloaded keybox, and one the user chose, holds
  private keys; it is deleted once it was installed or dismissed, so that they are kept only
  where the keystore reads them and in the store.
- **File pickers.** A ROM without a documents application has no activity for `OpenDocument`; the
  application now says so instead of ending.

## The user interface

The screens were laid out again once the settings had grown to some thirty choices on one page
and the target rules pushed the target list below the fold.

- **Settings is a list of pages**, one concern each (`SettingsScreen.Page`), each listed with a
  summary of its values. One long page made the protection presets, the key removal, the
  sources and the boot hook hard to find and easy to change by a stray scroll. Navigation is
  plain state in `ReplayApp` (a destination and an optional page, saved across configuration
  changes) with `BackHandler`; `navigation-compose` was not added, because four destinations and
  one level of pages do not need it and every dependency must be verified
  (`gradle/verification-metadata.xml`).
- **A choice of several values is a list item that opens a dialog** (`Widgets.ChoiceItem`), with
  the meaning of each option under it. Segmented buttons were used before; with five options
  (the refresh interval) or longer translated labels they did not fit a phone,
  and they left no room to say what each option does.
- **The notices are the same on every screen** (`Notices`): the outcome of the last operation and
  the "changes not applied yet" notice. Before, the outcome was shown on the home screen only,
  and elsewhere a failure became a snackbar and a success was not shown at all until the user
  went home; a change made on the targets screen said it was pending there, but one made in the
  settings did not.
- **Wide windows** get a navigation rail instead of the bar (from 600 dp) and centre the content
  at a readable width; the home screen puts the checklist beside the verdict from 840 dp. The
  window size is read from `LocalWindowInfo`, again without the adaptive library.
- **Both applications share their frame and their status card** (`Frame`, `Widgets.Hero`): the
  frame was written twice, line for line, and the cards of the home screens differed only in
  their emblem. The emblem is the rounded hexagon of the application icon, coloured by the state
  (primary when it is as wanted, the error colour when it needs the user, a neutral outline
  while it is unknown); it turns when the state becomes good, and back when it no longer is.
- **The settings list the pages of the application first**, and those every application of the
  kind has last: Privilege, then About. About shows the icon and the version of the application,
  where its engine keeps its files, and a link to its source.
- **A status that cannot be read is a state of its own** (`HomeScreen.Condition.UNREADABLE`).
  Before, a failed `status` left the status empty, which the home screen took for "still
  checking": it showed a spinner and "Checking" for ever, and the failure replaced the outcome of
  the operation that had just succeeded. The failure is now kept apart (`UiState.statusError`),
  the verdict says the device could not be read and offers **Check again**, the engine log of the
  failed reading becomes the log, and the outcome stays. A reading refused for a restricted root
  is the one exception: it also becomes the outcome, so that the frame's dialog explains how to
  grant full root, as it did before.
- **After a failed operation the device is read again.** An operation can fail half-way (a refresh
  that installed a keybox and then failed to apply); the screens showed the state from before it
  until the next check. Checking a chosen file changes nothing and is not followed by a reading.
- **Shortcuts open the page they are about**: the boot item of the checklist opens "Applying and
  boot", the privilege and refresh details open their pages. Choosing Settings in the navigation
  always opens its list, also from one of its pages.
- **No input or output on the main thread**: the name of a chosen file is asked of its provider
  (which may be a slow cloud provider) and the engine directory is created off the main thread.
- **One privilege probe per check.** `check` selected the privilege, then `Replay.status` selected
  it again, running `su -c id -u` (or a Shizuku query) twice for every reading of the device.

## Robustness of the engine

- **An unreadable installed keybox no longer stops `apply`.** `apply` caught a keybox it could not
  read (not UTF-8, no key recoverable even leniently) and kept it, but the judging of persisted
  keys then read it again and failed, so every `apply` and every boot hook stopped half-way: the
  target list and the spoof flags written, nothing restarted, `applied_at` not recorded. Such a
  keybox now gives no signers, as a missing one does, so no key is judged outdated against it.
  `status` and `apply` still warn of it.
- **`install-keybox` and `install-fingerprint` take the apply lock.** Only the app's own mutex kept
  them apart from `apply`; another process running the engine (the boot hook, the package
  watcher, a second copy of the app, a manual run) could have an `apply` write the old keys or the
  old fingerprint's files over those just installed.
- **The package watcher gets its own session.** It was started as the leader of a process group of
  its own, and `setsid`, which `detach` calls, refuses a process-group leader, so it stayed in the
  session of the `su` that started it. The group is no longer made: the session makes one.
- **Tests that need Linux run only there.** The inotify and `flock` tests ran on every host and
  failed on macOS, where the engine is developed but never runs; they still run in CI on Linux.

- **A wrong clock does not make a key unusable.** Early in a boot, when the boot hook judges the
  persisted keys, the clock of many devices is behind (the time is set from the network later).
  The chain of an old keybox then read as "not valid yet", which counted as unusable, and
  `WhenUnusable` removed keys that still worked, the enrolments it exists to keep. A certificate
  of such a chain that is not valid yet means the clock is behind, because the chain was valid
  when the key was made: the validity periods then tell nothing, and only the other problems
  count (`PersistedKey::is_unusable`).
- **Keyboxes are judged with the saved status list** when the application gives none (it cannot
  download it, and the system cleared its cache), as persisted keys already were; a revoked
  keybox no longer looks unrevoked then when it is installed or when the state is read, which
  run as root. Checking a file the user chose runs as the application, which cannot read the
  store, and tells that revocation was not checked when it has no list of its own. The application keeps a downloaded list only when it
  has the shape of one, so that an error page served with success never replaces a good copy.
  With `WhenNeeded`, a keybox whose revocation is not known is still kept when it is usable:
  replacing a working keybox may cost the enrolments of the keys attested with it.
- **Nesting in a keybox document is bounded** (`Node::MAX_DEPTH`): the parser keeps its own
  stack, but the tree is dropped recursively, and a document nested a million levels deep (well
  under the size of a download) overflowed the stack of the engine.
- **A watcher that runs an earlier copy of the engine is ended** whenever the hook is installed
  (`PackageWatcher::is_outdated`), not only when the copy was just replaced: when ending it timed
  out once, the next installation found the copy unchanged and left the old engine watching.

- **The engine leaves the cgroup of the application** (`ControlGroup` of `crates/android`). Android
  keeps a group for every application process (`/apps/uid_<uid>/pid_<pid>` of the unified
  hierarchy on Android 17), freezes it while the application is cached (seen on the emulator:
  `cgroup.events` reads `frozen 1` some seconds after the application went to the background)
  and ends every process in it with the application (`killProcessGroup` of libprocessgroup). The
  `su` of KernelSU and APatch raises the calling process itself (KernelSU's `execve` hook calls
  `ksu_escape_to_root` on it), so the engine, and every process it started, stayed in that group;
  Magisk's `su` has its daemon start the root process, outside it. An engine run as root now
  moves itself into the root groups first, when it finds itself in the group of an application
  process, and the processes it starts are outside the group too. The keystore supervisor that
  a restart starts inherits it, and so does the package watcher, which moved itself already.
  Moving every engine run was preferred to moving only the long-lived processes: a command that
  holds the lock of the store must not be frozen with the application either. Running the
  operations of the screens as expedited work or in a foreground service was set aside: it keeps
  the application running, but neither stops the system from ending it.

Not changed, but known: removing the service script by hand does not stop a running watcher until
the package list next changes (`hook remove` and `--no-watch` do stop it), and a keystore daemon
that does not come back within the restart timeout fails the whole `apply`, although the
configuration was already written. `Engine::restart` ends the Play processes (and, when the settings
say so, the background applications) also after a repair at boot; and
`KeystoreConfig::fingerprint_directory` names the store of the engine.

## Information the app does not take from the engine

The device's own model, Android version, security patch and build fingerprint come from
`android.os.Build` in the app, which Play Integrity Fork does not spoof there. The first API level
comes from the engine (`ro.product.first_api_level`), which reads system properties directly.
The device maker sets that property and never updates it. Earlier versions fell back to
`ro.board.first_api_level` and `ro.board.api_level` when it was missing. Those describe the
vendor image of the chipset, not the device: `ro.board.first_api_level`
(`BOARD_SHIPPING_API_LEVEL`) is the level the chipset's software first shipped with, which on a
device whose vendor image is frozen on an older chipset release is older than the device, and
`ro.board.api_level` (`BOARD_API_LEVEL`) is the current vendor API level, which on recent
releases is a `YYYYMM` number such as `202404` rather than an SDK level. The screen showed a wrong
level on such devices (common outside the Pixel line).
The level is now unknown when the property is missing. Guessing it from `ro.build.version.sdk`
was rejected for the same reason: an upgraded device would show its current release.
`Build.VERSION.DEVICE_INITIAL_SDK_INT` reads the same property; the engine stays the source
because the status report already carries the value, and moving it would change the format
between the two halves for no gain.

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

`replay-integrity watch --package <application>` is a process that runs while the system runs. It waits
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

## Code shared with TypeFace Droplet

Replay Integrity and TypeFace Droplet are built the same way, and parts of them were written once and copied.
The copies had drifted apart, each with fixes the other lacked, so they were brought together:
for every part, the better of the two versions was taken, and both repositories now hold the
same code. The parts are:

- **`crates/android`**, the whole crate, byte for byte. It holds every Android interface either
  engine uses: the font service (`FontService`), the keystore (`DeviceKeystore`), watches of
  files (`FileWatch`) and `/data/system/packages.list` (`PackageList`) as well as the package
  manager, the activity manager, processes, capabilities and properties. Each engine uses only
  some of them; the unused ones are left out of the binary by the linker, and one crate
  for both is simpler to keep equal than two crates that differ by a few modules.
- **`crates/replay-integrity/src/log.rs`**, byte for byte.
- **The `privilege` package** of the application (`Privilege`, `PrivilegeSelector`,
  `RootPrivilege`, `ShizukuPrivilege`, `CommandService`, `ProcessRunner` and
  `ICommandService.aidl`), which differs only in its `package` line.
- **`engine/EngineProtocol.kt`**: how the application reads what its engine prints (the
  response, its log, `EngineException`, `EngineResult`). The two copies of `Engine.decode` and
  `Engine.result` had drifted (one told the output of `su` when the engine printed nothing, the
  other did not). The JSON settings stay each application's (`EngineJson`), because Replay
  Integrity coerces unknown values to their defaults and TypeFace Droplet must not: it would
  rewrite a configuration of a newer version with values it does not know replaced.
- **`ui/Widgets.kt`**, the parts every screen is made of, including the status card of the home
  screen (`Hero`, with the hexagon of the application icon as its emblem), its buttons
  (`Actions`) and the name of the application with its icon (`Identity`). Parts that belong to
  one application stay out of it (the editor of variation axes is `CustomizeScreen.Axes` in
  TypeFace Droplet).
- **`ui/Frame.kt`**, the frame: the top bar, the navigation (a bar, or a rail in a wide window)
  and the screen of the route, generic over the destinations of each application
  (`Frame.Destination`), with the dialog of a restricted root and the sheet of the engine log.
- **`ui/Privileges.kt`**, what the screens show of the privilege: its words, the guide to get one
  (`Setup`) and the page of the settings that chooses it (`Choices`).
- The shared labels at the top of `ui/Labels` (`rootManager`, `rootManagers`), the shape of the
  application (`Navigator`, `Route`, `ScreenData` with its `pending`) and of the notice of
  changes not applied yet (`Notices.Pending`).
- The build files outside the application's own steps: `build.gradle.kts`, `gradle.properties`,
  `gradle/libs.versions.toml`, `rustfmt.toml`, and `app/proguard-rules.pro` apart from its package names.

Each shared Kotlin file differs only in its `package` line and the package names of its
imports. A change to one of these parts is made in both repositories, in the same words. The copies are
checked with `diff -r crates/android ../typeface-droplet/crates/android`, and with `diff` after
replacing the package names for the Kotlin files.

Sharing them through a third repository was considered: a Git submodule, or a Cargo Git
dependency and a published Gradle library. It was set aside for now. Each repository builds on
its own today, from one checkout, with every Gradle dependency verified
(`gradle/verification-metadata.xml`); a submodule makes every checkout and the CI depend on a
second repository, and a published library must be published and verified on every change.

## Names of the engine

The core crate of each engine had a short name (`replay`), the name of its executable, of the
library the application packages (`libreplay.so`) and of the copy the boot hook runs. Every crate now
bears the full name of its application, `replay-integrity` (the library `replay_integrity`), and so do the
executable, `libreplay-integrity.so` (a hyphen is allowed in the name of a native library:
`isFilenameSafe` of `frameworks/base/libs/androidfw/ApkParsing.cpp` accepts it) and the copy in
the store. The names of the data in the store (its log, state and configuration) are kept, so an
update loses nothing.

The copy of the engine under its earlier name keeps running until the boot hook is installed
again by the updated application: the scripts of the earlier version name it. Installing the hook
writes the scripts that name the new copy first, and only then removes the earlier copy
(`LEGACY_EXECUTABLES`), so no script ever names a missing file. A package watcher that an
earlier version started runs that copy, and is recognised by either name, so that installing the
hook ends it (`PackageWatcher::is_watcher`).

The Gradle property that limits the ABIs of a local build is `engine.abis` in both applications,
so that the build files differ only in the names of the application.

## Dependencies

Every dependency is verified (`gradle/verification-metadata.xml`, SHA-256). The file is generated
by Gradle (`--write-verification-metadata sha256` with the tasks of the CI and of a local build:
`:app:testDebugUnitTest :app:assembleRelease :app:assembleDebug :app:lintDebug`), after its
components were emptied, so that versions no longer used leave it, and with an empty Gradle home
(`-g <empty directory>`): Gradle records only what it downloads, and the BOMs and parent POMs that
an earlier build left in the cache were missing, which failed the CI, whose cache is empty. Gradle records the artifacts of
the machine it runs on only: `aapt2` comes in one jar per system, and the jar for Linux, where the
CI builds, is added by hand from Google's Maven repository. Both applications share the file.

Material 3 is 1.5.0, its first stable release with the Expressive components, which needs Compose
1.12 and so stays with the Compose BOM 2026.09.00. The next BOM (2026.11.01, Compose 1.13)
requires `compileSdk` 37.1, a platform the build machines do not have yet; it was left for a
change of its own.
