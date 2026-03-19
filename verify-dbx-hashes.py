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
import platform
import struct

DBX_JSON = "dbx_info_msft_latest.json"
DBX_URL = f"https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PreSignedObjects/DBX/{DBX_JSON}"
DEFAULT_EFI_PATH = "/boot/efi"

EFI_DBX_EFIVAR_PATH_DEFAULT = "/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"

EFI_CERT_X509_GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
EFI_CERT_SHA256_GUID = "c1c41626-504c-4092-aca9-41f936934328"

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
# DBX JSON handling
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

def extract_arch_hashes(dbx_json, arch_key):
    images = dbx_json.get("images", {})
    arch_entries = images.get(arch_key, [])
    hashes = set()
    if not isinstance(arch_entries, list):
        arch_entries = []
    for entry in arch_entries:
        if not isinstance(entry, dict):
            continue
        h = entry.get("authenticodeHash")
        if h:
            hashes.add(h.lower())
    print(f"[*] Loaded {len(hashes)} {arch_key} hashes from DBX JSON")
    return hashes

def extract_revoked_cert_thumbprints(dbx_json):
    revoked = {}
    certs = dbx_json.get("certificates", [])
    if not isinstance(certs, list):
        return revoked
    for c in certs:
        if not isinstance(c, dict):
            continue
        tp = c.get("thumbprint")
        if isinstance(tp, str) and tp.strip():
            revoked[_normalize_hex(tp)] = c
    print(f"[*] Loaded {len(revoked)} revoked certificate thumbprints from DBX JSON")
    return revoked


# ------------------------------------------------------------
# Architecture detection
# ------------------------------------------------------------

def detect_arch_key():
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("i386", "i686", "x86"):
        return "ia32"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return None


# ------------------------------------------------------------
# Lightweight PE Validation
# ------------------------------------------------------------

def looks_like_pe(filepath):
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            off = f.read(4)
            if len(off) != 4:
                return False
            pe_offset = int.from_bytes(off, "little")
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


# ------------------------------------------------------------
# Authenticode binary hash
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
    except Exception:
        return None
    return None


# ------------------------------------------------------------
# PE Authenticode PKCS#7 extraction
# ------------------------------------------------------------

def extract_pkcs7_der_from_pe(filepath):
    """
    Extract Authenticode PKCS#7 (DER) bytes from PE attribute certificate table.
    Returns bytes or None.
    """
    try:
        with open(filepath, "rb") as f:
            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), "little")

            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return None

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

            security_entry_off = data_dir_off + (4 * 8)
            f.seek(security_entry_off)
            cert_table_off = int.from_bytes(f.read(4), "little")  # file offset
            cert_table_size = int.from_bytes(f.read(4), "little")

            if cert_table_off == 0 or cert_table_size == 0:
                return None

            f.seek(cert_table_off)
            dw_length = int.from_bytes(f.read(4), "little")
            _w_revision = int.from_bytes(f.read(2), "little")
            _w_cert_type = int.from_bytes(f.read(2), "little")

            if dw_length < 8:
                return None

            pkcs7_der = f.read(dw_length - 8)
            if len(pkcs7_der) != dw_length - 8:
                return None

            return pkcs7_der
    except Exception:
        return None


# ------------------------------------------------------------
# Extract certs from PKCS#7 and compute hashes (probe support)
# ------------------------------------------------------------

def find_cert_candidates_in_efi(efi_path):
    """
    Return list of extracted cert info:
      sha1(DER cert) to match JSON thumbprint,
      sha256(DER cert),
      sha256(DER SPKI pubkey).
    """
    pkcs7_der = extract_pkcs7_der_from_pe(efi_path)
    if not pkcs7_der:
        return []

    out = []
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
            return []

        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            r.stdout,
            flags=re.DOTALL,
        )

        for i, block in enumerate(blocks):
            pem_path = os.path.join(td, f"cert{i}.pem")
            with open(pem_path, "w") as f:
                f.write(block + "\n")

            # DER(cert)
            der_proc = subprocess.run(
                ["openssl", "x509", "-in", pem_path, "-outform", "DER"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if der_proc.returncode != 0 or not der_proc.stdout:
                continue
            der_bytes = der_proc.stdout

            sha1_thumb = hashlib.sha1(der_bytes).hexdigest().lower()
            sha256_der = hashlib.sha256(der_bytes).hexdigest().lower()

            # DER(SPKI)
            pubkey_pem = subprocess.run(
                ["openssl", "x509", "-in", pem_path, "-pubkey", "-noout"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            sha256_spki = None
            if pubkey_pem.returncode == 0 and pubkey_pem.stdout:
                spki_der = subprocess.run(
                    ["openssl", "pkey", "-pubin", "-outform", "DER"],
                    input=pubkey_pem.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if spki_der.returncode == 0 and spki_der.stdout:
                    sha256_spki = hashlib.sha256(spki_der.stdout).hexdigest().lower()

            subj = subprocess.run(
                ["openssl", "x509", "-in", pem_path, "-noout", "-subject"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            iss = subprocess.run(
                ["openssl", "x509", "-in", pem_path, "-noout", "-issuer"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            out.append({
                "sha1_thumbprint": sha1_thumb,
                "sha256_der_cert": sha256_der,
                "sha256_spki": sha256_spki,
                "subject": subj.stdout.strip() if subj.returncode == 0 else "",
                "issuer": iss.stdout.strip() if iss.returncode == 0 else "",
            })

    return out

def cert_thumbprint_present_via_dbx_sha256(json_thumbprint_sha1, efi_path, local_dbx_sha256):
    """
    Best-effort proof for SHA256-only DBX:
    find cert in EFI chain by SHA1 thumbprint, then check for sha256(DER(cert)) or sha256(SPKI)
    in local DBX SHA256 entries.
    """
    target = _normalize_hex(json_thumbprint_sha1)
    certs = find_cert_candidates_in_efi(efi_path)

    for c in certs:
        if _normalize_hex(c["sha1_thumbprint"]) != target:
            continue

        hits = []
        if c["sha256_der_cert"] in local_dbx_sha256:
            hits.append(("sha256_der_cert", c["sha256_der_cert"]))
        if c["sha256_spki"] and c["sha256_spki"] in local_dbx_sha256:
            hits.append(("sha256_spki", c["sha256_spki"]))

        return (len(hits) > 0, {
            "thumbprint_sha1": target,
            "subject": c.get("subject", ""),
            "issuer": c.get("issuer", ""),
            "hits": hits,
            "tested": {
                "sha256_der_cert": c["sha256_der_cert"],
                "sha256_spki": c["sha256_spki"],
            }
        })

    return (False, None)


# ------------------------------------------------------------
# Local DBX parsing (efivar/esl)
# ------------------------------------------------------------

def _guid_bytes_to_str(b):
    d1 = struct.unpack("<I", b[0:4])[0]
    d2 = struct.unpack("<H", b[4:6])[0]
    d3 = struct.unpack("<H", b[6:8])[0]
    d4 = b[8:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0]:02x}{d4[1]:02x}-{d4[2]:02x}{d4[3]:02x}{d4[4]:02x}{d4[5]:02x}{d4[6]:02x}{d4[7]:02x}"

def summarize_dbx_sigtypes(raw):
    off = 0
    counts = {}
    while off + 28 <= len(raw):
        sig_type_guid = _guid_bytes_to_str(raw[off:off+16])
        sig_list_size, sig_hdr_size, sig_size = struct.unpack("<III", raw[off+16:off+28])
        if sig_list_size < 28 or sig_size == 0 or off + sig_list_size > len(raw):
            break
        counts[sig_type_guid] = counts.get(sig_type_guid, 0) + 1
        off += sig_list_size
    return counts

def read_efivar_dbx(path):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 4:
        raise ValueError("efivar dbx file too small")
    attrs = struct.unpack("<I", blob[0:4])[0]
    data = blob[4:]
    return attrs, data

def parse_efi_signature_lists(data):
    """
    Returns:
      sha256_hashes: set of hex sha256 (64)
      x509_der: list of DER cert blobs (if present)
      sigtypes: dict guid->count of signature lists
    """
    off = 0
    sha256_hashes = set()
    x509_der = []
    sigtypes = {}

    while off + 28 <= len(data):
        sig_type_guid = _guid_bytes_to_str(data[off:off+16])
        sig_list_size, sig_hdr_size, sig_size = struct.unpack("<III", data[off+16:off+28])

        if sig_list_size < 28 or sig_size == 0:
            break
        if off + sig_list_size > len(data):
            break

        sigtypes[sig_type_guid] = sigtypes.get(sig_type_guid, 0) + 1

        header_off = off + 28
        sig_data_off = header_off + sig_hdr_size
        entry_bytes = sig_list_size - 28 - sig_hdr_size
        if entry_bytes < 0:
            off += sig_list_size
            continue

        count = entry_bytes // sig_size
        for i in range(count):
            eoff = sig_data_off + (i * sig_size)
            if eoff + sig_size > off + sig_list_size:
                break

            sigdata = data[eoff+16:eoff+sig_size]  # skip owner GUID
            if sig_type_guid == EFI_CERT_SHA256_GUID and len(sigdata) == 32:
                sha256_hashes.add(sigdata.hex())
            elif sig_type_guid == EFI_CERT_X509_GUID and len(sigdata) > 0:
                x509_der.append(sigdata)

        off += sig_list_size

    return sha256_hashes, x509_der, sigtypes


# ------------------------------------------------------------
# Scan filesystem for revoked hashes/certs (optional)
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

            # revoked binary hash
            if USE_SIGNIFY:
                hash_value = compute_authenticode_hash_signify(full_path)
            else:
                hash_value = compute_authenticode_hash_ossl(full_path)

            if hash_value and hash_value in dbx_hashes:
                hash_matches.append((full_path, hash_value))
                print(f"[!] DBX HASH MATCH: {full_path}")

            # revoked cert thumbprint (from embedded chain)
            certs = find_cert_candidates_in_efi(full_path)
            for c in certs:
                tp = c.get("sha1_thumbprint")
                if tp and tp in revoked_cert_thumbprints:
                    cert_entry = revoked_cert_thumbprints[tp]
                    cert_matches.append((full_path, tp, cert_entry))
                    print(f"[!] DBX CERT MATCH: {full_path} (thumbprint={tp})")
                    desc = cert_entry.get("description", "")
                    if desc:
                        print(f"    description: {desc}")
                    break

    print("\n===== Scan Summary =====")
    print(f"Total files scanned: {total_files}")
    print(f"PE files detected: {pe_files}")
    print(f"Revoked binary hash matches found: {len(hash_matches)}")
    print(f"Revoked certificate matches found: {len(cert_matches)}")

    return hash_matches, cert_matches


# ------------------------------------------------------------
# Local DBX superset check (with probe-cert-efi hack)
# ------------------------------------------------------------

def local_dbx_superset_check(dbx_json, arch_key, efivar_path, list_missing=False, probe_cert_efi=None):
    # JSON expected (arch-specific) hashes
    json_hashes = extract_arch_hashes(dbx_json, arch_key)

    # JSON cert thumbprints (sha1)
    json_cert_thumbprints = []
    certs = dbx_json.get("certificates", [])
    if isinstance(certs, list):
        for c in certs:
            if isinstance(c, dict) and c.get("thumbprint"):
                json_cert_thumbprints.append(_normalize_hex(c["thumbprint"]))

    # Local DBX
    attrs, raw = read_efivar_dbx(efivar_path)
    local_sha256, local_x509_der, sigtypes = parse_efi_signature_lists(raw)
    local_sha256 = {h.lower() for h in local_sha256}

    has_x509 = (EFI_CERT_X509_GUID in sigtypes)

    # Missing hashes are always checkable (SHA256 GUID exists on your platform)
    missing_hashes = json_hashes - local_sha256

    cert_check_mode = None
    missing_certs = set()
    cert_probe_details = None

    if not json_cert_thumbprints:
        cert_check_mode = "no_json_certs"
    elif has_x509:
        # Direct check possible (compute sha1 thumbprints from DER cert blobs in dbx)
        local_cert_thumbprints = {hashlib.sha1(der).hexdigest().lower() for der in local_x509_der}
        missing_certs = set(json_cert_thumbprints) - local_cert_thumbprints
        cert_check_mode = "x509_direct"
    else:
        # SHA256-only DBX: cannot directly compare SHA1 thumbprints.
        # Hack: if only one cert and probe EFI provided, attempt to validate via SHA256 candidates.
        cert_check_mode = "sha256_only"
        if len(json_cert_thumbprints) == 1 and probe_cert_efi:
            present, details = cert_thumbprint_present_via_dbx_sha256(
                json_thumbprint_sha1=json_cert_thumbprints[0],
                efi_path=probe_cert_efi,
                local_dbx_sha256=local_sha256,
            )
            cert_probe_details = details
            if not present:
                missing_certs = {json_cert_thumbprints[0]}
        else:
            # Skip marking as missing; caller can treat as skipped-with-warning.
            #missing_certs = set()
            missing_certs = set(json_cert_thumbprints)
            

    rep = {
        "arch": arch_key,
        "efivar_path": efivar_path,
        "efivar_attrs": attrs,
        "sigtypes": sigtypes,
        "json_hash_count": len(json_hashes),
        "json_cert_count": len(json_cert_thumbprints),
        "local_hash_count": len(local_sha256),
        "missing_hash_count": len(missing_hashes),
        "missing_cert_count": len(missing_certs),
        "cert_check_mode": cert_check_mode,
        "cert_probe_used": bool(probe_cert_efi),
        "cert_probe_details": cert_probe_details,
        "cert_check_skipped": (cert_check_mode == "sha256_only" and not (len(json_cert_thumbprints) == 1 and probe_cert_efi)),
    }

    if list_missing:
        rep["missing_hashes"] = sorted(missing_hashes)
        if missing_certs:
            rep["missing_cert_thumbprints"] = sorted(missing_certs)

    return rep


# ------------------------------------------------------------
# CLI / Main
# ------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Scan EFI for revoked binaries (DBX authenticodeHash) and revoked certs (DBX certificates.thumbprint). Optionally verify local firmware DBX is a superset of the JSON DBX."
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
    parser.add_argument(
        "--check-local-dbx",
        action="store_true",
        help="Compare local firmware DBX (efivar) against JSON DBX for detected architecture. Local DBX expected to be a superset."
    )
    parser.add_argument(
        "--efivar-dbx-path",
        default=EFI_DBX_EFIVAR_PATH_DEFAULT,
        help=f"Path to efivarfs DBX variable (default: {EFI_DBX_EFIVAR_PATH_DEFAULT})"
    )
    parser.add_argument(
        "--arch",
        choices=["x64", "ia32", "arm64"],
        default=None,
        help="Override detected architecture for selecting images.<arch> from JSON DBX."
    )
    parser.add_argument(
        "--list-missing",
        action="store_true",
        help="List missing entries (hashes/thumbprints) when using --check-local-dbx."
    )
    parser.add_argument(
        "--probe-cert-efi",
        default=None,
        help="Path to an EFI binary whose Authenticode chain includes the revoked cert from JSON. Used to validate cert revocation presence on SHA256-only DBX systems."
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
    dbx_json = load_dbx(args)

    # Local DBX check mode
    if args.check_local_dbx:
        arch_key = args.arch or detect_arch_key()
        if not arch_key:
            print("[!] Could not detect architecture. Use --arch x64|ia32|arm64.")
            sys.exit(1)

        rep = local_dbx_superset_check(
            dbx_json=dbx_json,
            arch_key=arch_key,
            efivar_path=args.efivar_dbx_path,
            list_missing=args.list_missing,
            probe_cert_efi=args.probe_cert_efi,
        )

        print("\n===== Local DBX Superset Check =====")
        print(f"Architecture key: {rep['arch']}")
        print(f"EFIVAR DBX path: {rep['efivar_path']}")
        print(f"dbx efivar attrs=0x{rep['efivar_attrs']:08x}")
        print(f"SignatureList types present: {rep['sigtypes']}")
        print(f"JSON expected: hashes={rep['json_hash_count']} certs={rep['json_cert_count']}")
        print(f"Local DBX has: hashes={rep['local_hash_count']}")
        print(f"Missing from local DBX: hashes={rep['missing_hash_count']} certs={rep['missing_cert_count']}")
        print(f"Cert check mode: {rep['cert_check_mode']} (probe used: {rep['cert_probe_used']})")

        if rep.get("cert_check_skipped"):
            print("[*] Note: Local DBX contains no X509 signature lists. "
                  "Certificate thumbprints cannot be directly compared. "
                  "If you have an EFI file that was signed by the revoked certificate, "
                  "provide --probe-cert-efi to attempt a best-effort validation (only "
                  "supports 1 JSON cert).")

        if rep.get("cert_probe_details"):
            d = rep["cert_probe_details"]
            print("[*] Probe details:")
            print(f"    thumbprint_sha1: {d.get('thumbprint_sha1')}")
            print(f"    subject: {d.get('subject')}")
            print(f"    issuer: {d.get('issuer')}")
            print(f"    tested sha256_der_cert: {d.get('tested', {}).get('sha256_der_cert')}")
            print(f"    tested sha256_spki: {d.get('tested', {}).get('sha256_spki')}")
            if d.get("hits"):
                print("    matches in local DBX:")
                for kind, val in d["hits"]:
                    print(f"      {kind}: {val}")
            else:
                print("    matches in local DBX: (none)")

        if args.list_missing:
            if rep.get("missing_hashes"):
                print("\nMissing revoked image hashes (sha256):")
                for h in rep["missing_hashes"]:
                    print(f"  {h}")
            if rep.get("missing_cert_thumbprints"):
                print("\nMissing revoked cert thumbprints (sha1):")
                for tp in rep["missing_cert_thumbprints"]:
                    print(f"  {tp}")

        missing_any = rep["missing_hash_count"] or (rep["missing_cert_count"] if not rep.get("cert_check_skipped") else 0)
        if missing_any:
            sys.exit(3)
        sys.exit(0)

    # Normal scan mode
    efi_path = resolve_scan_path(args)
    arch_key = args.arch or detect_arch_key() or "x64"

    dbx_hashes = extract_arch_hashes(dbx_json, arch_key)
    revoked_certs = extract_revoked_cert_thumbprints(dbx_json)

    hash_matches, cert_matches = scan_efi_folder(dbx_hashes, revoked_certs, efi_path)

    if not hash_matches and not cert_matches:
        print("[+] No revoked EFI binaries or revoked signer certificates detected.")
        sys.exit(0)

    if hash_matches:
        print("\n[!] Revoked EFI binaries (DBX authenticodeHash):")
        for path, h in hash_matches:
            print(f"{path} -> {h}")

    if cert_matches:
        print("\n[!] EFI binaries signed with revoked certificates (DBX certificates.thumbprint):")
        for path, fp, cert_entry in cert_matches:
            subj = cert_entry.get("subjectName", "")
            print(f"{path} -> thumbprint={fp}" + (f" subjectName={subj}" if subj else ""))

    sys.exit(2)

if __name__ == "__main__":
    main()
