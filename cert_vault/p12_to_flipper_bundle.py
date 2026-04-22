#PS D:\prueb_con> Set-Location 'd:\prueb_con\flipper'; C:/py314/python.exe .\tools\p12_to_flipper_bundle.py '.\entrada.p12' --output '.\salida.fvp12' --p12-password 'XXX' --vault-pin 'XXX'



from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

FORMAT_VERSION = "FVP12-1"
KEYSET_VERSION = "1"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a PKCS#12 (.p12/.pfx) file into a Flipper-installable vault bundle (.fvp12)."
    )
    parser.add_argument("input", type=Path, help="Path to the source .p12/.pfx file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output bundle path (.fvp12). Defaults to the source stem with .fvp12 extension.",
    )
    parser.add_argument("--alias", help="Override the generated alias used inside the bundle")
    parser.add_argument("--p12-password", help="Password used to open the PKCS#12 file")
    parser.add_argument("--vault-pin", help="PIN/passphrase used to wrap the original PKCS#12 for Flipper storage")
    return parser.parse_args()


def prompt_secret(value: str | None, prompt: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt)


def safe_alias(text: str) -> str:
    alias = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._")
    return alias or "cert"


def subject_value(cert, attr_name: str) -> str:
    for attribute in cert.subject:
        if attribute.oid._name == attr_name:
            return attribute.value
    return ""


def classify_key(private_key) -> str:
    key_type_name = private_key.__class__.__name__.lower()
    if "rsa" in key_type_name:
        return "RSA"
    if "ellipticcurve" in key_type_name or "ecprivate" in key_type_name:
        return "EC"
    if "dsa" in key_type_name:
        return "DSA"
    return private_key.__class__.__name__


def derive_key(vault_pin: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(vault_pin.encode("utf-8"))


def build_keyset_payload(certificate, additional_certificates, private_key) -> bytes:
    payload = {
        "keyset_version": KEYSET_VERSION,
        "private_key_format": "pkcs8-der",
        "certificate_format": "x509-der",
        "private_key_der_b64": base64.b64encode(
            private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        ).decode("ascii"),
        "certificate_der_b64": base64.b64encode(certificate.public_bytes(Encoding.DER)).decode(
            "ascii"
        ),
        "chain_der_b64": [
            base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")
            for cert in additional_certificates
        ],
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def build_bundle_text(
    input_path: Path,
    alias: str,
    cert,
    additional_certificates,
    private_key,
    vault_pin: str,
) -> str:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    serial_hex = format(cert.serial_number, "X")
    aad = f"{FORMAT_VERSION}|{alias}|{serial_hex}".encode("utf-8")
    key = derive_key(vault_pin, salt)
    keyset_payload = build_keyset_payload(cert, additional_certificates, private_key)
    ciphertext = AESGCM(key).encrypt(nonce, keyset_payload, aad)

    lines = [
        f"format={FORMAT_VERSION}",
        "bundle_kind=vault_keyset",
        f"alias={alias}",
        f"source_name={input_path.name}",
        f"subject={cert.subject.rfc4514_string()}",
        f"issuer={cert.issuer.rfc4514_string()}",
        f"serial={serial_hex}",
        f"not_before={cert.not_valid_before_utc.isoformat()}",
        f"not_after={cert.not_valid_after_utc.isoformat()}",
        f"key_type={classify_key(private_key)}",
        f"common_name={subject_value(cert, 'commonName')}",
        f"cert_sha1={cert.fingerprint(hashes.SHA1()).hex().upper()}",
        f"chain_count={1 + len(additional_certificates)}",
        "cipher=AES-256-GCM",
        "kdf=PBKDF2-HMAC-SHA256",
        "payload_encoding=json",
        f"keyset_version={KEYSET_VERSION}",
        f"iterations={PBKDF2_ITERATIONS}",
        f"salt_hex={salt.hex()}",
        f"nonce_hex={nonce.hex()}",
        f"aad={aad.decode('utf-8')}",
        f"wrapped_keyset_b64={base64.b64encode(ciphertext).decode('ascii')}",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        raise SystemExit(f"Input file not found: {args.input}")

    p12_password = prompt_secret(args.p12_password, "PKCS#12 password (leave empty if none): ")
    vault_pin = prompt_secret(args.vault_pin, "Vault PIN/passphrase for Flipper storage: ")
    if not vault_pin:
        raise SystemExit("Vault PIN/passphrase cannot be empty.")

    p12_bytes = args.input.read_bytes()
    password_bytes = p12_password.encode("utf-8") if p12_password else None

    try:
        private_key, certificate, additional_certificates = load_key_and_certificates(
            p12_bytes, password_bytes
        )
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Failed to open PKCS#12 file: {exc}") from exc

    if private_key is None or certificate is None:
        raise SystemExit("The PKCS#12 file does not contain both a private key and its leaf certificate.")

    alias_seed = args.alias or subject_value(certificate, "commonName") or args.input.stem
    alias = safe_alias(alias_seed)
    output_path = args.output or args.input.with_suffix(".fvp12")
    bundle_text = build_bundle_text(
        args.input,
        alias,
        certificate,
        additional_certificates or [],
        private_key,
        vault_pin,
    )

    output_path.write_text(bundle_text, encoding="utf-8")
    print(f"Bundle created: {output_path}")
    print(f"Alias: {alias}")
    print(f"Subject: {certificate.subject.rfc4514_string()}")
    print(f"Key type: {classify_key(private_key)}")
    print(f"Chain certificates: {1 + len(additional_certificates or [])}")
    print("Bundle payload: encrypted native keyset (no raw PKCS#12 stored)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())