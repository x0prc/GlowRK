import os
import pefile
import sys

os.system("pip install pefile")


def get_iat(pe):
    """Extracts the Import Address Table (IAT) from a PE file."""
    iat = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iat.append((entry.dll, imp.name, imp.address))
    return iat

def display_iat(iat):
    """Displays the IAT entries."""
    print(f"{'DLL Name':<30} {'Function Name':<30} {'Address':<20}")
    print("=" * 80)
    for dll_name, func_name, address in iat:
        print(f"{dll_name.decode('utf-8'):<30} {func_name.decode('utf-8') if func_name else 'N/A':<30} {hex(address):<20}")

def main(pe_file):
    """Main function to read a PE file and extract its IAT."""
    try:
        pe = pefile.PE(pe_file)
        iat = get_iat(pe)
        display_iat(iat)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python iat_detection.py <path_to_pe_file>")
        sys.exit(1)

    pe_file_path = sys.argv[1]
    main(pe_file_path)