![A](https://github.com/user-attachments/assets/f90e7e50-df29-48be-8f8b-c2bdf93585bc)
# GlowRK - x64 Rootkit Analysis - PoC

## Motivation
This Proof-of-Concept Project is prepared to explain the working of a Rootkit and Detecting it on a system. There are various methods and tools used along with a comfortable interface to test out various situations.

## Methods 
- Memory Dumps
  - Crash Dumps
  - Raw Dumps
  - vmem. (Created by VMWare)
  - hiberfil.sys (During Hibernation)
- Signature Based
- Interception Detection
    - IDT (Interrupt Descriptor Table)
    - SSDT (System Service Descriptor Table)
    - IAT (Import Address Table)
- Integrity Check
- Via WinDbg (Debugger)

## Tools Used
- [chkrootkit](https://www.chkrootkit.org/)
- [rkhunter](https://rkhunter.sourceforge.net/)
- [AIDE](https://aide.github.io/doc/)
- Unusual .pcapng files

## Replacement Notes
- In [src/memory_analysis.py](https://github.com/x0prc/GlowRK/src/memory_analysis.py) `path/to/memdump.mem` and `Win7SP1x64` with your actual memory dump file path and operating system profile.
- 
