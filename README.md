# uefi-dbx-audit

A UEFI Secure Boot DBX audit toolkit for Linux.

---

## Overview

This project provides a Secure Boot audit toolkit for Linux. It is inspired by
[Check-UEFISecureBootVariables](https://github.com/cjee21/Check-UEFISecureBootVariables).

It audits whether your UEFI forbidden-signature database (**DBX**) is up to date
with Microsoft’s published Secure Boot revocations (via the open-source
[SecureBoot Objects](https://github.com/microsoft/secureboot_objects/wiki) project).
It can also audit a mounted Linux EFI System Partition (**ESP**) for binaries that
match entries revoked by Microsoft’s Secure Boot DBX.

By default, the script `verify-dbx-hashes.py` scans a mounted EFI filesystem (default:
`/boot/efi`) and checks whether any EFI binaries, shims, or bootloader files match
Microsoft’s revoked Authenticode hashes (DBX). If it finds matches, it reports them.

---

## Install

### Requirements

- Python 3
- `pip install requests`
- `pip install signify` (preferred)  
- `apt-get install osslsigncode` || `dnf install osslsigncode` (fallback)
[Of the last options two one of them is required]

### Download and install

- `git clone https://github.com/sei-vsarvepalli/uefi-dbx-audit`
- `cd uefi-dbx-audit`
- `python3 verify-dbx.py -h`



## Learn by Examples

### Example 1: Default operation (no revoked binaries found)
[Depending on you system configuration, you may need to do "sudo" ]
```
bash:~$  python3 verify-dbx.py 
[*] signify not available, falling back to osslsigncode
[*] Loaded 431 x64 hashes from DBX JSON
[*] Loaded 1 revoked certificate thumbprints from DBX JSON
[*] Scanning /boot/efi ...

===== Scan Summary =====
Total files scanned: 9
PE files detected: 6
Revoked binary hash matches found: 0
Revoked certificate matches found: 0
[+] No revoked EFI binaries or revoked signer certificates detected.
```

### Example 2: Default operation (a revoked EFI found in `/boot/efi`)

```
bash:~$ python3 verify-dbx.py 
[*] signify not available, falling back to osslsigncode
[*] Loaded 431 x64 hashes from DBX JSON
[*] Loaded 1 revoked certificate thumbprints from DBX JSON
[*] Scanning /boot/efi ...
[!] DBX HASH MATCH: /boot/efi/EFI/BOOT/VU529659.efi

===== Scan Summary =====
Total files scanned: 10
PE files detected: 7
Revoked binary hash matches found: 1
Revoked certificate matches found: 0

[!] Revoked EFI binaries (DBX authenticodeHash):
/boot/efi/EFI/BOOT/VU529659.efi -> cdb7c90d3ab8833d5324f5d8516d41fa990b9ca721fe643fffaef9057d9f9e48
```


### Example 3: Scan a specific folder (e.g., `/tmp`)

This scans a specific folder and shows a vulnerable bootloader present on your
filesystem. In this example, the file is revoked due to a Windows-specific
certificate, and it may not be relevant to most Linux systems. However, it can
still be useful to know it exists on disk.

```
bash:~$  python3 verify-dbx.py /tmp
[*] signify not available, falling back to osslsigncode
[*] Loaded 431 x64 hashes from DBX JSON
[*] Loaded 1 revoked certificate thumbprints from DBX JSON
[*] Scanning /tmp ...
[!] DBX CERT MATCH: /tmp/bootmgfw.efi (thumbprint=580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d)
    description: Windows Bootmgr signing certificate authority since 2011. Revoked due to CVE-2023-24932

===== Scan Summary =====
Total files scanned: 8
PE files detected: 1
Revoked binary hash matches found: 0
Revoked certificate matches found: 1

[!] EFI binaries signed with revoked certificates (DBX certificates.thumbprint):
/tmp/bootmgfw.efi -> thumbprint=580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d subjectName=CN = Microsoft Windows Production PCA 2011
```


### Example 4: Check whether the local DBX is up to date (and list missing entries)

This checks whether the DBX currently present in firmware is a superset of the
expected Microsoft DBX data and reports missing entries. In this example, the
certificate thumbprint for “Microsoft Windows Production PCA 2011” is reported as
missing. Depending on your system and threat model, this may or may not be
directly relevant, but it can be useful for tracking DBX coverage (e.g., in the
context of BlackLotus-related revocations).


```
bash:~$ python3 verify-dbx.py --check-local-dbx  --list-missing
[*] signify not available, falling back to osslsigncode
[*] Loaded 431 x64 hashes from DBX JSON

===== Local DBX Superset Check =====
Architecture key: x64
EFIVAR DBX path: /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
dbx efivar attrs=0x00000027
SignatureList types present: {'c1c41626-504c-4092-aca9-41f936934328': 7}
JSON expected: hashes=431 certs=1
Local DBX has: hashes=482
Missing from local DBX: hashes=0 certs=1
Cert check mode: sha256_only (probe used: False)
[*] Note: Local DBX contains no X509 signature lists. Certificate thumbprints cannot be directly compared. If you have an EFI file that was signed by the revoked certificate, provide --probe-cert-efi to attempt a best-effort validation (only supports 1 JSON cert).

Missing revoked cert thumbprints (sha1):
  580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d
```



### Example 5: Missing signatures (could be due to limited firmware storage)

This is similar to Example 4, but shows missing signatures. In some cases, a
system may not have enough available firmware/NVRAM space to store additional
DBX entries. Consider getting new hardware, as you cannot avoid BootKits! 

```
bash:~$ python3 verify-dbx-hashes.py --check-local-dbx   --list-missing
[*] signify not available, falling back to osslsigncode
[*] Loaded 431 x64 hashes from DBX JSON

===== Local DBX Superset Check =====
Architecture key: x64
EFIVAR DBX path: /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
dbx efivar attrs=0x00000027
SignatureList types present: {'c1c41626-504c-4092-aca9-41f936934328': 8}
JSON expected: hashes=431 certs=1
Local DBX has: hashes=464
Missing from local DBX: hashes=20 certs=1
Cert check mode: sha256_only (probe used: False)
[*] Note: Local DBX contains no X509 signature lists. Certificate thumbprints cannot be directly compared. If you have an EFI file that was signed by the revoked certificate, provide --probe-cert-efi to attempt a best-effort validation (only supports 1 JSON cert).

Missing revoked image hashes (sha256):
  0bc4f078388d41ab039f87ae84cf8d39302ccbdd70c4ade02263ebfce6def0f5
  5c39f0e5e0e7fa3be05090813b13d161acaf48494fde6233b452c416d29cddbe
  63f67824fda998798964ff33b87441857da92f3a8ee3e04166eec315e6600fd1
  6b4328ebcbe46ed9118ff2d4472de329d70ba83016df7a6f50f8af923883bc54
  7eac80a915c84cd4afec638904d94eb168a8557951a4d539b0713028552b6b8c
  804e354c6368bb27a90fae8e498a57052b293418259a019c4f53a2007254490f
  9b1f35052cfc5fb06dab5e8f7b47f081da28d722db59ade253b9e38ab5a19847
  9d7e7174c281c6526b44c632baa8c3320add0c77dc90778cc148938829f45e5e
  9e19dd645235341a555da6c065594543ae1e3918ecd37df22dfebe91e71c3a59
  b4e1880425f7857b741b921d04fd9276130927cf90a427c454b970e7a28eb88b
  c54a4060b3a76fa045b7b60eaebc8389780376ba3ef1f63d417ba1b55be3a093
  c87efd057497f90321d62a69b311912be8ef8a045fe9c5e6bd5c8c1a41d6b295
  cbfa2a86144eb21d65a6b17245bad4f73058436c7292be56dc6ebab29da61606
  cda0b4a59390b36e1b654850428cbb5b4c7b5e4349e87acde97fb5437d64d9fc
  cdb7c90d3ab8833d5324f5d8516d41fa990b9ca721fe643fffaef9057d9f9e48
  e14c88dc48339c0555686849a4e3f8986d558e65c4fc863a1a4f1d40478bd47c
  e2aec271b9596a461eb6d54d8b1785e4e4c615cfad5f4504bcc0a329433a9747
  e3c5e55e84371d3f2fbca2241ef0711ff80876ebf71bab07d8e6e45aaa8b45af
  e7681f153121ea1e67f74bbcb0cdc5e502702c1b8cc55fb65d702dfba948b5f4
  ee093913abbd3d4cb85ea31375179a8b55a298353c03afe5055aa4e8ebd10ec2

Missing revoked cert thumbprints (sha1):
  580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d
```

### Example 6: SBAT Policy check mismatches in /tmp/super folder

This is specific to checking if SBAT violation exists where an older
version of a SHIM or GRUB exists that should be updated appropriately
as well. The NVRAM Variable in the SBATLevelRT is not checked, we start
with RedHat's rhboot/shim repository as the latest policy.

```
bash:~$ python3 verify-dbx-hashes.py -p /tmp/super/
[*] signify not available, falling back to osslsigncode
[*] Downloading SBAT CSV from https://raw.githubusercontent.com/rhboot/shim/refs/heads/main/SbatLevel_Variable.txt ...
[*] Loaded SBAT policy as {'sbat': 1, 'grub': 5, 'shim': 4}
[*] Loaded 431 x64 hashes from DBX JSON
[*] Loaded 1 revoked certificate thumbprints from DBX JSON
[*] Scanning /tmp/super/ ...

===== Scan Summary =====
Total files scanned: 8
PE files detected: 8
Revoked binary hash matches found: 0
Revoked certificate matches found: 0

[!] SBAT version check failed for :
/tmp/super/mmia32.efi -> Expected version: 4, Seen version: 2
/tmp/super/BOOTX64.EFI -> Expected version: 4, Seen version: 2
/tmp/super/BOOTIA32.EFI -> Expected version: 4, Seen version: 2
/tmp/super/mmx64.efi -> Expected version: 4, Seen version: 2
```

### Help command - explore all options available.

```
bash:~$ python3 verify-dbx-hashes.py -h
[*] signify not available, falling back to osslsigncode
usage: verify-dbx-hashes.py [-h] [-p PATH_FLAG] [-j DBX_JSON_PATH] [--check-local-dbx]
                            [--efivar-dbx-path EFIVAR_DBX_PATH]
                            [--arch {x64,ia32,arm64}] [--list-missing]
                            [--probe-cert-efi PROBE_CERT_EFI]
                            [path]

Scan EFI for revoked binaries (DBX authenticodeHash) and revoked certs (DBX
certificates.thumbprint). Optionally verify local firmware DBX is a superset of the JSON
DBX.

positional arguments:
  path                  Path to scan (default: /boot/efi)

options:
  -h, --help            show this help message and exit
  -p PATH_FLAG, --path PATH_FLAG
                        Path to scan (overrides positional PATH; default: /boot/efi)
  -j DBX_JSON_PATH, --dbx-json DBX_JSON_PATH
                        Use this local DBX JSON file instead of downloading (default:
                        use ./dbx_info_msft_latest.json if present, else download).
  --check-local-dbx     Compare local firmware DBX (efivar) against JSON DBX for
                        detected architecture. Local DBX expected to be a superset.
  --efivar-dbx-path EFIVAR_DBX_PATH
                        Path to efivarfs DBX variable (default:
                        /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-
                        dad00e67656f)
  --arch {x64,ia32,arm64}
                        Override detected architecture for selecting images.<arch> from
                        JSON DBX.
  --list-missing        List missing entries (hashes/thumbprints) when using --check-
                        local-dbx.
  --probe-cert-efi PROBE_CERT_EFI
                        Path to an EFI binary whose Authenticode chain includes the
                        revoked cert from JSON. Used to validate cert revocation
                        presence on SHA256-only DBX systems.
```			

Still want to learn more? Continue in [DeepDive.md](DeepDive.md).

