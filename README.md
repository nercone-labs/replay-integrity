<img width="1920" src="https://raw.githubusercontent.com/nercone-dev/assets/refs/heads/main/images/projects/labs/replay-integrity/header.png" />

# Replay Integrity

An app that keeps Play Integrity at `STRONG` on a rooted device, and keeps it there.

Replay Integrity drives two well-known modules rather than replacing them:

- **[TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS)** (`tricky_store`) simulates hardware key attestation from a keybox.
- **[PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork)** (`playintegrityfix`) spoofs the build of Google Play services.

It installs and updates these modules through your root manager, writes their configuration, checks the keybox against the Google trust anchors and the certificate status list, and — the part most setups get wrong — stops the verdict from decaying over the following days.

Works with rooted Shizuku/Sui and a root manager: Magisk, KernelSU, APatch.

## Why the verdict decays, and what this app does about it

A fresh `STRONG` setup tends to drop to `DEVICE`, then `BASIC`, within a few days. The causes are not mysterious once separated:

1. **The keybox is revoked or expires.** Google publishes a [certificate status list](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status) and leaked keyboxes are added to it. Replay Integrity checks the installed keybox against that list and the trust anchors, and refreshes it before it stops working. Mirrors often serve keyboxes with broken XML, which the keystore reads no key from; Replay Integrity recovers the keys, checks them, and installs them as a well-formed keybox with only the usable keys — and never replaces a working keybox with a worse one, trying further sources instead.
2. **The Pixel build stops being accepted.** Canary fingerprints have a short life. Replay Integrity refreshes the fingerprint and keeps the spoofed security patch in step with it.
3. **The modules' own refresh scripts reset the spoof flags.** Replay Integrity re-applies the flags that reach `STRONG` after every change.
4. **Stale per-application keys.** This is the subtle one. TEESimulator keeps the keys it generates for each app, together with the certificate chain it attested them with. When the keybox changes, those apps keep receiving a chain built from the **old** keybox — so once the old keybox is revoked or expires, their attestation fails even though a valid keybox is installed. Reinstalling the module "fixes" it only because it wipes those keys. Replay Integrity finds the keys whose chains were signed by a key no longer in the keybox and removes them, so the app regenerates them against the current keybox. This is `Repair`, and it runs at every boot and on a schedule.

Between those runs, a package watcher started by the boot hook adds an application to the attestation targets as soon as it is installed, and the app can disable modules that conflict with the two above.

## How it is built

Like [TypeFace Droplet](https://github.com/nercone-labs/typeface-droplet), the app is split into a small GUI (Kotlin, Material 3 Expressive) and a core engine (Rust), with the trust-critical work in the engine:

- `crates/der` — an ASN.1 DER reader (X.690).
- `crates/x509` — X.509 certificates, keys and PEM (RFC 5280, RFC 7468).
- `crates/attestation` — the Android key-attestation extension, the Google trust anchors, the certificate status list, and chain checks.
- `crates/keybox` — the attestation keybox XML format.
- `crates/prop` — `key=value` property files that keep their comments and order.
- `crates/android` — Android system interfaces (properties, the package manager, processes, capabilities).
- `crates/replay` — the engine binary that ties these together and drives the two modules.

The network is left to the app, which has ordinary TLS: it downloads the keybox, the fingerprint and the status list and hands the bytes to the engine, which parses, checks and installs them. The engine performs no network access and never makes a trust decision from unchecked input.

## Credits

Replay Integrity stands on the work of [TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) (Enginex0, JingMatrix), [PlayIntegrityFork](https://github.com/osm0sis/PlayIntegrityFork) (osm0sis, chiteroman) and the keybox and fingerprint sources that the [AlwaysStrong](https://gitlab.com/Evokerr/AlwaysStrong) module uses (Evokerr).
