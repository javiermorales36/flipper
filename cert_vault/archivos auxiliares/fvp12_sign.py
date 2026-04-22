#PS D:\prueb_con\flipper> Set-Location 'd:\prueb_con\flipper'; C:/py314/python.exe .\tools\fvp12_sign.py '.\entrada.fvp12' '.\README.md' --vault-pin 'XXX' --signature-format base64 --output '.\README.md.sig.b64' --export-cert '.\README_cert.pem'



from __future__ import annotations

import argparse
import base64
import getpass
from pathlib import Path

from fvp12_core import (
    certificate_to_pem_bytes,
    decrypt_bundle,
    load_signing_material,
    public_key_summary,
    read_bundle,
    sign_bytes,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign a file using a Flipper vault bundle (.fvp12)."
    )
    parser.add_argument("bundle", type=Path, help="Path to the .fvp12 bundle")
    parser.add_argument("input", type=Path, help="Path to the file to sign")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Detached signature output path. Defaults to <input>.sig",
    )
    parser.add_argument(
        "--vault-pin", help="Vault PIN/passphrase used when the .fvp12 bundle was generated"
    )
    parser.add_argument(
        "--p12-password",
        help="Original PKCS#12 password. Only needed for legacy pkcs12-based bundles.",
    )
    parser.add_argument(
        "--signature-format",
        choices=["binary", "base64"],
        default="binary",
        help="Write the detached signature as raw bytes or Base64 text",
    )
    parser.add_argument(
        "--algorithm",
        choices=["auto", "rsa-pkcs1v15", "rsa-pss", "ecdsa"],
        default="auto",
        help="Signature scheme to use. 'auto' selects a sensible default from the key type.",
    )
    parser.add_argument(
        "--export-cert",
        type=Path,
        help="Optional path to export the leaf certificate in PEM format",
    )
    return parser.parse_args()


def prompt_secret(value: str | None, prompt: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt)


def write_signature(output_path: Path, signature: bytes, signature_format: str) -> None:
    if signature_format == "binary":
        output_path.write_bytes(signature)
    else:
        output_path.write_text(base64.b64encode(signature).decode("ascii"), encoding="utf-8")


def export_certificate(export_path: Path, certificate) -> None:
    export_path.write_bytes(certificate_to_pem_bytes(certificate))


def main() -> int:
    args = parse_args()
    bundle_metadata = read_bundle(args.bundle)
    vault_pin = prompt_secret(args.vault_pin, "Vault PIN/passphrase: ")
    p12_password = None
    if bundle_metadata["bundle_kind"] == "pkcs12":
        p12_password = prompt_secret(args.p12_password, "Original PKCS#12 password: ")

    payload = args.input.read_bytes()
    decrypted_payload = decrypt_bundle(bundle_metadata, vault_pin)
    private_key, certificate = load_signing_material(bundle_metadata, decrypted_payload, p12_password)

    output_path = args.output or args.input.with_suffix(args.input.suffix + ".sig")
    signature = sign_bytes(private_key, payload, args.algorithm)
    write_signature(output_path, signature, args.signature_format)

    if args.export_cert is not None:
        export_certificate(args.export_cert, certificate)

    print(f"Bundle alias: {bundle_metadata['alias']}")
    print(f"Subject: {bundle_metadata.get('subject', '')}")
    print(f"Bundle kind: {bundle_metadata['bundle_kind']}")
    print(f"Signature written to: {output_path}")
    print(f"Public key: {public_key_summary(certificate)}")
    if args.export_cert is not None:
        print(f"Certificate exported to: {args.export_cert}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())