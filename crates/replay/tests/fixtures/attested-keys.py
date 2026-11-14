"""Generates the attested-key certificates of these fixtures.

Each certificate is a self-signed EC P-256 certificate with the Android key-attestation
extension (OID 1.3.6.1.4.1.11129.2.1.17), whose KeyDescription is encoded here by hand from the
schema of https://source.android.com/docs/security/features/keystore/attestation:
attestation and KeyMint version 300, TrustedEnvironment, an attestationApplicationId [709] in
softwareEnforced, and rootOfTrust [704], osVersion [705], osPatchLevel [706],
vendorPatchLevel [718] and bootPatchLevel [719] in hardwareEnforced.

Run with Python 3 and `cryptography`: python3 attested-keys.py (writes into its directory).
"""

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def length(size):
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, contents):
    return tag + length(len(contents)) + contents


def integer(value):
    return tlv(b"\x02", value.to_bytes(value.bit_length() // 8 + 1, "big"))


def explicit(number, contents):
    # A context-specific, constructed tag in the high-tag-number form (X.690 8.1.2.4).
    digits = []
    while True:
        digits.insert(0, number & 0x7F)
        number >>= 7
        if number == 0:
            break
    encoded = bytes([digit | 0x80 for digit in digits[:-1]] + [digits[-1]])
    return tlv(b"\xbf" + encoded, contents)


def key_description(package, os_patch, long_patch):
    # long_patch None leaves vendorPatchLevel and bootPatchLevel out, as when they are not reported.
    sequence = lambda *parts: tlv(b"\x30", b"".join(parts))
    application_id = sequence(
        tlv(b"\x31", sequence(tlv(b"\x04", package.encode()), integer(1))),
        tlv(b"\x31", tlv(b"\x04", b"\x00" * 32)),
    )
    software = sequence(explicit(709, tlv(b"\x04", application_id)))
    root_of_trust = sequence(tlv(b"\x04", b"\xaa" * 32), tlv(b"\x01", b"\xff"), tlv(b"\x0a", b"\x00"), tlv(b"\x04", b"\xbb" * 32))
    hardware = sequence(
        explicit(704, root_of_trust),
        explicit(705, integer(160000)),
        explicit(706, integer(os_patch)),
        *([explicit(718, integer(long_patch)), explicit(719, integer(long_patch))] if long_patch is not None else []),
    )
    return sequence(
        integer(300), tlv(b"\x0a", b"\x01"), integer(300), tlv(b"\x0a", b"\x01"),
        tlv(b"\x04", b"challenge"), tlv(b"\x04", b""), software, hardware,
    )


def certificate(package, os_patch, long_patch):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.TITLE, "TEE")])
    extension = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), key_description(package, os_patch, long_patch))
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(start).not_valid_after(start.replace(year=2048))
        .add_extension(extension, critical=False)
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


directory = pathlib.Path(__file__).parent
(directory / "play-key-2026-10-05.der").write_bytes(certificate("com.google.android.gms", 202610, 20261005))
(directory / "app-key-2026-10-05.der").write_bytes(certificate("com.example.bank", 202610, 20261005))
(directory / "play-store-key-2026-10-05.der").write_bytes(certificate("com.android.vending", 202610, 20261005))
(directory / "play-key-2026-10.der").write_bytes(certificate("com.google.android.gms", 202610, None))
