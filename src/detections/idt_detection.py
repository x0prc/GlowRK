# Interrupt Desciptor Table (Windows)
import ctypes
import struct
import os

IDT_SIZE = 256  
IDT_ENTRY_SIZE = 16 

# Define the IDT entry structure
class IDTEntry(ctypes.Structure):
    _fields_ = [
        ("offset_low", ctypes.c_uint16),
        ("selector", ctypes.c_uint16),
        ("ist_index", ctypes.c_uint8),
        ("type_attributes", ctypes.c_uint8),
        ("offset_middle", ctypes.c_uint16),
        ("offset_high", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32)
    ]

# Function to get the IDTR (IDT Register)
def get_idtr():
    idtr = ctypes.create_string_buffer(8)  
    ctypes.windll.kernel32.RtlGetInterruptDescriptorTable(ctypes.byref(idtr))
    base, limit = struct.unpack("<II", idtr)
    return base, limit

# Function to read the IDT entries
def read_idt(base, limit):
    idt_entries = []
    for i in range(IDT_SIZE):
        entry_offset = base + (i * IDT_ENTRY_SIZE)
        entry = IDTEntry.from_address(entry_offset)
        idt_entries.append(entry)
    return idt_entries

# Function to display IDT entries
def display_idt_entries(idt_entries):
    for i, entry in enumerate(idt_entries):
        print(f"Entry {i}: Offset Low: {entry.offset_low}, Selector: {entry.selector}, "
              f"Ist Index: {entry.ist_index}, Type Attributes: {entry.type_attributes}, "
              f"Offset Middle: {entry.offset_middle}, Offset High: {entry.offset_high}")

def main():
    # Get the base address and limit of the IDT
    base, limit = get_idtr()
    
    print(f"IDT Base Address: {hex(base)}")
    print(f"IDT Limit: {limit}")

    # Read and display IDT entries
    idt_entries = read_idt(base, limit)
    display_idt_entries(idt_entries)

if __name__ == "__main__":
    main()