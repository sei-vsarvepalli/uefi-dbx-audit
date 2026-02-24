# uefi-dbx-audit

Audit a mounted Linux EFI System Partition (ESP) for binaries revoked by Microsoft's Secure Boot DBX. 

---

## Overview

`uefi-dbx-audit` scans a mounted EFI filesystem (default: `/boot/efi`) and checks whether any EFI binaries, shims, or bootloader blobs match Microsoft’s latest revoked Authenticode hashes (DBX).

If no revoked binaries are found, a system administrator can safely proceed with a manual DBX update if automated tooling (such as fwupd) is unavailable or broken.

This tool is diagnostic and educational by design. It does **not** attempt to automate the entire Secure Boot lifecycle.

Ideally, systems that have the latest version of fwupd with working plugins, can use (LVFS)[https://fwupd.org/lvfs] and use the commands below to stay up to date:
```
fwupdmgr get-devices
fwupdmgr get-updates
```
Firmware updates typically require a reboot. Regularly scheduling maintenance windows for firmware updates is strongly recommended.

---

## Why This Exists

Secure Boot DBX updates are typically delivered via:

- `fwupdmgr`
- `fwupdtool`
- The `uefi_dbx` plugin from fwupd

In practice, administrators may encounter:

- Plugin dependency issues
- Distribution packaging problems
- Partial Secure Boot setups
- Shim/bootloader layering complexity
- Firmware inconsistencies

When the normal update path fails, administrators may choose to install the DBX blob manually.  
This script provides a verification step before doing so.

It also exists to raise awareness about how UEFI DBX revocation actually works.

Long-term DBX lifecycle management belongs to OS vendors and firmware ecosystems — not to this script.

---

## What It Does

1. Downloads (or reads locally) the latest: `dbx_info_msft_latest.json`
2. Extracts revoked **x64 Authenticode SHA-256 hashes**
3. Recursively scans `/boot/efi`
4. Detects valid PE binaries
5. Computes their Authenticode hash
6. Compares against the DBX revoked list
7. Reports any matches

## When To Use This

Use this tool if:

- `fwupdmgr` DBX updates fail
- The `uefi_dbx` plugin has dependency issues
- You plan to manually install the DBX blob
- You are performing Secure Boot auditing
- You want visibility into revoked EFI binaries before updating DBX

---

## Manual DBX Installation

If the script reports: 
```
[+] No revoked EFI binaries detected.
```

You may manually install the latest DBX blob.

Download:

https://github.com/microsoft/secureboot_objects/blob/main/PostSignedObjects/DBX/amd64/DBXUpdate.bin

Install with:
`fwupdtool --plugins uefi_dbx install-blob DBXUpdate.bin`


---

## How It Works

### 1. DBX JSON Retrieval

- Uses local `dbx_info_msft_latest.json` if present
- Otherwise downloads from Microsoft's Secure Boot repository

### 2. Lightweight PE Validation

Each file under `/boot/efi` is validated for:

- `MZ` header
- Valid `PE\0\0` signature

Non-PE files are skipped.

### 3. Authenticode Hashing

Two methods are supported:

| Method        | Requirement        | Notes        |
|---------------|-------------------|-------------|
| `signify`     | Python library     | Preferred   |
| `osslsigncode`| External binary    | Fallback    |

If `signify` is available, it is used automatically.

### 4. Matching

The computed Authenticode SHA-256 fingerprint is compared against Microsoft's revoked hash list.

---

## Example Output

### Clean System
```
[] Loaded 47 x64 hashes from DBX
[] Scanning /boot/efi ...
===== Scan Summary =====
Total files scanned: 132
PE files detected: 8
Revoked matches found: 0
[+] No revoked EFI binaries detected.
```


### Revoked Binary Found
```
[!] MATCH FOUND: /boot/efi/EFI/ubuntu/shimx64.efi
Revoked matches found: 1
```


---

## Exit Codes

| Code | Meaning |
|------|----------|
| 0    | No revoked binaries detected |
| 1    | JSON load/parse error |
| 2    | Revoked binaries found |

---

## Requirements

- Python 3
- `requests`

Optional:

- `signify` (preferred)
- `osslsigncode` (fallback)

---

## Important Notes

- Run as root (read access to `/boot/efi` required)
- Ensure `/boot/efi` is mounted
- Back up systems before applying DBX updates
- Test in staging where possible

---

## What This Tool Does NOT Do

- Does not remove revoked binaries
- Does not modify the EFI partition
- Does not manage Secure Boot keys
- Does not automate DBX lifecycle management
- Does not replace OS vendor tooling

This tool is intentionally minimal.

Its purpose is to:

- Improve administrator understanding
- Increase visibility into DBX mechanics
- Encourage informed DBX updates
- Reduce blind revocation deployments

---

## Long-Term Perspective

UEFI Secure Boot DBX updates are reactive and ongoing.  
Revoking compromised bootloaders while maintaining system bootability is a complex and evolving challenge.

This project does not attempt to solve that ecosystem-level problem.

It exists to help administrators better understand it.

