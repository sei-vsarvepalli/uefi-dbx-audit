#!/usr/bin/env python3
import os
import json
import requests
import hashlib
import sys
import subprocess
import argparse
import tempfile
import re

DBX_JSON = "dbx_info_msft_latest.json"
DBX_URL = f"https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/{DBX_JSON}"
DEFAULT_EFI_PATH = "/boot/efi"

# ------------------------------------------------------------
# Optional signify support
# ------------------------------------------------------------

USE_SIGNIFY = False
try:
    from signify.authenticode import SignedPEFile
    USE_SIGNIFY = True
    print("[*] Using signify for Authenticode hashing")
except Exception:
    print("[*] signify not available, falling back to osslsigncode")


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _normalize_hex(s):
    return re.sub(r"[^0-9a-fA-F]", "", s).lower()


# ------------------------------------------------------------
# DBX Handling
# ------------------------------------------------------------

def download_dbx_json(url):
    print(f"[*] Downloading DBX JSON from {url} ...")
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()

def local_dbx_json(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Local DBX file {file_path} not found.")
    except json.JSONDecodeError:
        print(f"[!] Failed to parse JSON from {file_path}.")
    return None

def extract_x64_hashes(dbx_json):
    print("[*] Extracting x64 Authenticode hashes...")
    hashes = set()

    images = dbx_json.get("images", {})
    x64_entries = images.get("x64", [])

    for entry in x64_entries:
        h = entry.get("authenticodeHash")
        if h:
            hashes.add(h.lower())

    print(f"[*] Loaded {len(hashes)} x64 hashes from DBX")
    return hashes

def extract_revoked_cert_thumbprints(dbx_json):
    """
    DBX JSON provides revoked certificates in top-level `certificates`.
    The field `thumbprint` appears to be a SHA-1 fingerprint (40 hex chars).
    Returns dict sha1_thumbprint_hex -> cert_entry
    """
    revoked = {}
    certs = dbx_json.get("certificates", [])
    if not isinstance(certs, list):
        return revoked

    for c in certs:
        if not isinstance(c, dict):
            continue
        tp = c.get("thumbprint")
        if isinstance(tp, str) and tp.strip():
            tp_norm = _normalize_hex(tp)
            if tp_norm:
                revoked[tp_norm] = c

    print(f"[*] Loaded {len(revoked)} revoked certificate thumbprints from DBX")
    return revoked


# ------------------------------------------------------------
# Lightweight PE Validation
# ------------------------------------------------------------

def looks_like_pe(filepath):
    """
    Minimal PE validation:
    - MZ header
    - Valid PE signature at e_lfanew
    """
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b"MZ":
                return False

            f.seek(0x3C)
            offset_bytes = f.read(4)
            if len(offset_bytes) != 4:
                return False

            pe_offset = int.from_bytes(offset_bytes, "little")

            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return False

        return True
    except Exception:
        return False


# ------------------------------------------------------------
# Authenticode Hashing (binary hash)
# ------------------------------------------------------------

def compute_authenticode_hash_signify(filepath):
    try:
        with open(filepath, "rb") as f:
            pe = SignedPEFile(f)
            digest = pe.get_fingerprint(hashlib.sha256())
            return digest.hex().lower()
    except Exception:
        return None

def compute_authenticode_hash_ossl(filepath):
    try:
        result = subprocess.run(
            ["osslsigncode", "verify", "-in", filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20
        )

        for line in result.stdout.splitlines():
            if "Hash of file (sha256):" in line:
                return line.split(":")[-1].strip().lower()
            if "Calculated message digest" in line:
                return line.split(":")[-1].strip().lower()

    except Exception as e:
        print(f"Warning: No osslsigncode failed with execption {e} for {filepath}")
        return None

    print(f"Warning: osslsigncode could not find authenticode hash for {filepath}")
    return None


# ------------------------------------------------------------
# Certificate extraction (OpenSSL) for revoked signer checks
# ------------------------------------------------------------

def extract_pkcs7_der_from_pe(filepath):
    """
    Extract Authenticode PKCS#7 (DER) bytes from PE attribute certificate table.
    Returns bytes or None.
    """
    try:
        with open(filepath, "rb") as f:
            # DOS header -> e_lfanew
            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), "little")

            # NT signature
            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return None

            # Optional header starts after COFF header (20 bytes)
            coff_off = e_lfanew + 4
            opt_off = coff_off + 20

            f.seek(opt_off)
            magic = int.from_bytes(f.read(2), "little")

            if magic == 0x10B:      # PE32
                data_dir_off = opt_off + 96
            elif magic == 0x20B:    # PE32+
                data_dir_off = opt_off + 112
            else:
                return None

            # IMAGE_DIRECTORY_ENTRY_SECURITY = 4
            security_entry_off = data_dir_off + (4 * 8)
            f.seek(security_entry_off)
            cert_table_off = int.from_bytes(f.read(4), "little")  # file offset, not RVA
            cert_table_size = int.from_bytes(f.read(4), "little")

            if cert_table_off == 0 or cert_table_size == 0:
                return None

            # WIN_CERTIFICATE
            f.seek(cert_table_off)
            dw_length = int.from_bytes(f.read(4), "little")
            _w_revision = int.from_bytes(f.read(2), "little")
            _w_cert_type = int.from_bytes(f.read(2), "little")

            if dw_length < 8:
                return None

            pkcs7_len = dw_length - 8
            pkcs7_der = f.read(pkcs7_len)
            if len(pkcs7_der) != pkcs7_len:
                return None

            return pkcs7_der
    except Exception:
        return None

def _openssl_fingerprint(cert_pem_path, algo):
    r = subprocess.run(
        ["openssl", "x509", "-in", cert_pem_path, "-noout", "-fingerprint", f"-{algo}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if r.returncode != 0 or "Fingerprint=" not in r.stdout:
        return None
    return _normalize_hex(r.stdout.split("Fingerprint=")[-1])

def get_embedded_cert_sha1_fingerprints_openssl(filepath):
    """
    Returns set of SHA1 fingerprints (hex lowercase, no colons) for all certs embedded
    in the Authenticode PKCS#7 signature.
    """
    pkcs7_der = extract_pkcs7_der_from_pe(filepath)
    if not pkcs7_der:
        return set()

    with tempfile.TemporaryDirectory() as td:
        p7b_path = os.path.join(td, "sig.p7b")
        with open(p7b_path, "wb") as f:
            f.write(pkcs7_der)

        r = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-in", p7b_path, "-print_certs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if r.returncode != 0 or "BEGIN CERTIFICATE" not in r.stdout:
            return set()

        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            r.stdout,
            flags=re.DOTALL,
        )

        fps = set()
        for i, block in enumerate(blocks):
            cert_path = os.path.join(td, f"cert{i}.pem")
            with open(cert_path, "w") as f:
                f.write(block + "\n")
            sha1 = _openssl_fingerprint(cert_path, "sha1")
            if sha1:
                fps.add(sha1)

        return fps

def signer_cert_is_revoked(filepath, revoked_thumbprints):
    """
    revoked_thumbprints: dict sha1_hex -> cert_entry
    Returns (True, cert_entry, matched_thumbprint) or (False, None, None)
    """
    embedded = get_embedded_cert_sha1_fingerprints_openssl(filepath)
    if not embedded:
        return (False, None, None)

    for fp in embedded:
        if fp in revoked_thumbprints:
            return (True, revoked_thumbprints[fp], fp)

    return (False, None, None)


# ------------------------------------------------------------
# Scanning
# ------------------------------------------------------------

def scan_efi_folder(dbx_hashes, revoked_cert_thumbprints, efi_path):
    print(f"[*] Scanning {efi_path} ...")

    total_files = 0
    pe_files = 0
    hash_matches = []
    cert_matches = []

    for root, dirs, files in os.walk(efi_path):
        for name in files:
            total_files += 1
            full_path = os.path.join(root, name)

            if not looks_like_pe(full_path):
                continue

            pe_files += 1

            # Check 1: revoked binary hash (existing behavior)
            if USE_SIGNIFY:
                hash_value = compute_authenticode_hash_signify(full_path)
            else:
                hash_value = compute_authenticode_hash_ossl(full_path)

            if hash_value and hash_value in dbx_hashes:
                hash_matches.append((full_path, hash_value))
                print(f"[!] DBX HASH MATCH: {full_path}")

            # Check 2: revoked certificate thumbprint (new behavior)
            revoked, cert_entry, fp = signer_cert_is_revoked(full_path, revoked_cert_thumbprints)
            if revoked:
                cert_matches.append((full_path, fp, cert_entry))
                subj = cert_entry.get("subjectName", "")
                print(f"[!] DBX CERT MATCH: {full_path} (thumbprint={fp})")
                if subj:
                    print(f"    subjectName: {subj}")
                desc = cert_entry.get("description", "")
                if desc:
                    print(f"    description: {desc}")

    print("\n===== Scan Summary =====")
    print(f"Total files scanned: {total_files}")
    print(f"PE files detected: {pe_files}")
    print(f"Revoked binary hash matches found: {len(hash_matches)}")
    print(f"Revoked certificate matches found: {len(cert_matches)}")

    return hash_matches, cert_matches


# ------------------------------------------------------------
# CLI / Main
# ------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan an EFI directory for revoked binaries (DBX authenticodeHash) and revoked signing certificates (DBX certificates thumbprints)."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help=f"Path to scan (default: {DEFAULT_EFI_PATH})"
    )
    parser.add_argument(
        "-p", "--path",
        dest="path_flag",
        default=None,
        help=f"Path to scan (overrides positional PATH; default: {DEFAULT_EFI_PATH})"
    )
    parser.add_argument(
        "-j", "--dbx-json",
        dest="dbx_json_path",
        default=None,
        help=f"Use this local DBX JSON file instead of downloading (default: use ./{DBX_JSON} if present, else download)."
    )
    return parser.parse_args(argv)

def resolve_scan_path(args):
    scan_path = args.path_flag or args.path or DEFAULT_EFI_PATH

    if not os.path.exists(scan_path):
        print(f"[!] Scan path does not exist: {scan_path}")
        sys.exit(1)

    if not os.path.isdir(scan_path):
        print(f"[!] Scan path is not a directory: {scan_path}")
        sys.exit(1)

    return scan_path

def load_dbx(args):
    if args.dbx_json_path:
        dbx_json = local_dbx_json(args.dbx_json_path)
        if not dbx_json:
            sys.exit(1)
        return dbx_json

    if os.path.exists(DBX_JSON):
        dbx_json = local_dbx_json(DBX_JSON)
        if not dbx_json:
            sys.exit(1)
        return dbx_json

    return download_dbx_json(DBX_URL)

def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    efi_path = resolve_scan_path(args)

    dbx_json = load_dbx(args)
    dbx_hashes = extract_x64_hashes(dbx_json)
    revoked_certs = extract_revoked_cert_thumbprints(dbx_json)

    hash_matches, cert_matches = scan_efi_folder(dbx_hashes, revoked_certs, efi_path)

    if not hash_matches and not cert_matches:
        print("[+] No revoked EFI binaries or revoked signer certificates detected.")
    else:
        if hash_matches:
            print("\n[!] Revoked EFI binaries (DBX authenticodeHash):")
            for path, h in hash_matches:
                print(f"{path} -> {h}")

        if cert_matches:
            print("\n[!] EFI binaries signed with revoked certificates (DBX certificates thumbprints):")
            for path, fp, cert_entry in cert_matches:
                subj = cert_entry.get("subjectName", "")
                print(f"{path} -> thumbprint={fp}" + (f" subjectName={subj}" if subj else ""))

        # non-zero exit for automation/compliance
        sys.exit(2)

if __name__ == "__main__":
    main()