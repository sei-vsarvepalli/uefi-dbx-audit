#!/usr/bin/env python3
import sys
import struct

def extract_esl(input_file, output_file):
    with open(input_file, "rb") as f:
        data = f.read()

    # EFI_VARIABLE_AUTHENTICATION_2 begins with EFI_TIME (16 bytes)
    # Followed by WIN_CERTIFICATE_UEFI_GUID:
    #
    # typedef struct {
    #   UINT32  dwLength;
    #   UINT16  wRevision;
    #   UINT16  wCertificateType;
    #   EFI_GUID CertType;
    #   UINT8   CertData[...];
    # } WIN_CERTIFICATE_UEFI_GUID;

    if len(data) < 16 + 4:
        raise ValueError("File too small to be valid")

    offset = 0

    # Skip EFI_TIME (16 bytes)
    offset += 16

    # Parse WIN_CERTIFICATE header
    dwLength = struct.unpack_from("<I", data, offset)[0]

    if dwLength <= 0 or dwLength > len(data):
        raise ValueError("Invalid WIN_CERTIFICATE length")

    # Skip entire WIN_CERTIFICATE_UEFI_GUID structure
    offset += dwLength

    # Remaining data should be concatenated EFI_SIGNATURE_LIST structures
    esl_data = data[offset:]

    if len(esl_data) == 0:
        raise ValueError("No ESL data found after authentication header")

    with open(output_file, "wb") as out:
        out.write(esl_data)

    print(f"[+] Extracted {len(esl_data)} bytes of ESL data")
    print(f"[+] Written to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: extract_esl.py <DBXUpdate.bin> <output.esl>")
        sys.exit(1)

    extract_esl(sys.argv[1], sys.argv[2])
