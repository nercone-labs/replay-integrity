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
