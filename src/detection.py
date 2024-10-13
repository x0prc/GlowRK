import hashlib
import os
import pefile
import sys

os.system("pip install pefile")

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_pe_hash(pe_file):
    return calculate_sha256(pe_file)

def integrity_check(pe_file, expected_hash):
    calculated_hash = get_pe_hash(pe_file)
    print(f"Calculated Hash: {calculated_hash}")
    print(f"Expected Hash: {expected_hash}")

    if calculated_hash == expected_hash:
        print("Integrity Check Passed: The file is unmodified.")
    else:
        print("Integrity Check Failed: The file has been modified!")

def get_iat(pe):
    iat = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iat.append((entry.dll, imp.name, imp.address))
    return iat

def display_iat(iat):
    print(f"{'DLL Name':<30} {'Function Name':<30} {'Address':<20}")
    print("=" * 80)
    for dll_name, func_name, address in iat:
        print(f"{dll_name.decode('utf-8'):<30} {func_name.decode('utf-8') if func_name else 'N/A':<30} {hex(address):<20}")

# Main analysis function
def analyze_pe(pe_file, expected_hash):
    try:
        pe = pefile.PE(pe_file)
        print(f"Valid PE file: {pe_file}")

        # Perform integrity check
        integrity_check(pe_file, expected_hash)

        # Extract and display IAT
        iat = get_iat(pe)
        display_iat(iat)

    except pefile.PEFormatError:
        print("Error: The specified file is not a valid PE file.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python detection.py <path_to_pe_file> <expected_sha256_hash>")
        sys.exit(1)

    pe_file_path = sys.argv[1]
    expected_sha256 = sys.argv[2]
    
    analyze_pe(pe_file_path, expected_sha256)