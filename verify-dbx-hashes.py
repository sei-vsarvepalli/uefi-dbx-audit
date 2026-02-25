#!/usr/bin/env python3
import os
import json
import requests
import hashlib
import sys
import subprocess

DBX_JSON = "dbx_info_msft_latest.json"
DBX_URL = f"https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/{DBX_JSON}"
EFI_PATH = "/boot/efi"

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
# DBX Handling
# ------------------------------------------------------------

def download_dbx_json(url):
    print("[*] Downloading DBX JSON...")
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
# Authenticode Hashing
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
# Scanning
# ------------------------------------------------------------

def scan_efi_folder(dbx_hashes):
    print(f"[*] Scanning {EFI_PATH} ...")

    total_files = 0
    pe_files = 0
    matches = []

    for root, dirs, files in os.walk(EFI_PATH):
        for name in files:
            total_files += 1
            full_path = os.path.join(root, name)

            if not looks_like_pe(full_path):
                continue

            pe_files += 1

            if USE_SIGNIFY:
                hash_value = compute_authenticode_hash_signify(full_path)
            else:
                hash_value = compute_authenticode_hash_ossl(full_path)

            if not hash_value:
                continue

            if hash_value in dbx_hashes:
                matches.append((full_path, hash_value))
                print(f"[!] MATCH FOUND: {full_path}")

    print("\n===== Scan Summary =====")
    print(f"Total files scanned: {total_files}")
    print(f"PE files detected: {pe_files}")
    print(f"Revoked matches found: {len(matches)}")

    return matches


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    if os.path.exists(DBX_JSON):
        dbx_json = local_dbx_json(DBX_JSON)
        if not dbx_json:
            sys.exit(1)
    else:
        dbx_json = download_dbx_json(DBX_URL)

    dbx_hashes = extract_x64_hashes(dbx_json)
    matches = scan_efi_folder(dbx_hashes)

    if not matches:
        print("[+] No revoked EFI binaries detected.")
    else:
        print("\n[!] Revoked EFI binaries:")
        for path, h in matches:
            print(f"{path} -> {h}")
        sys.exit(2)  # Non-zero exit for automation/compliance


if __name__ == "__main__":
    main()
