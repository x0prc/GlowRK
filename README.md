![A](https://github.com/user-attachments/assets/f90e7e50-df29-48be-8f8b-c2bdf93585bc)
# GlowRK - x64 Rootkit Analysis - PoC

## Motivation
This Proof-of-Concept Project is prepared to explain the working of a Rootkit and Detecting it on a system. There are various methods and tools used along with a comfortable interface to test out various situations.
It detects potential rootkits by examining various system components such as the Interrupt Descriptor Table (IDT), System Service Descriptor Table (SSDT), Import Address Table (IAT), and performs integrity checks on critical system files.

## Features 
- Upload memory dump files for analysis.
- Detect modifications in IDT, SSDT, and IAT.
- Perform integrity checks on system files.
- View detailed analysis results in an intuitive dashboard.

## Prerequisites
Before you begin, ensure you have met the following requirements:
- [Node.js](https://nodejs.org/) (LTS version recommended)
- [Python](https://www.python.org/) (for running the analysis engine)
- [Volatility Framework](https://github.com/volatilityfoundation/volatility) (installed and accessible)

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


## Contributing
- Contributions are welcome! If you have suggestions or improvements, please fork the repository and submit a pull request.
- Fork the project.
- Create your feature branch (git checkout -b feature/AmazingFeature).
- Commit your changes (git commit -m 'Add some AmazingFeature').
- Push to the branch (git push origin feature/AmazingFeature).
- Open a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
