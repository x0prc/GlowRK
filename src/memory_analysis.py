import subprocess
import json

def run_volatility(command):
    """Run a Volatility command and return the output."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise Exception(f"Error running command: {result.stderr.strip()}")
        return result.stdout
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_process_list(memory_dump_path, profile):
    """Get a list of processes from the memory dump."""
    command = ['python', 'vol.py', '--profile', profile, 'pslist', '-f', memory_dump_path]
    output = run_volatility(command)
    
    if output:
        # Parse the output to extract process information
        process_list = []
        lines = output.splitlines()
        for line in lines[4:]: 
            parts = line.split()
            if len(parts) >= 5:
                process_info = {
                    'PID': parts[0],
                    'PPID': parts[1],
                    'Name': parts[2],
                    'Offset': parts[3],
                    'Threads': parts[4]
                }
                process_list.append(process_info)
        return process_list
    return []

def get_dll_list(memory_dump_path, profile):
    """Get a list of loaded DLLs from the memory dump."""
    command = ['python', 'vol.py', '--profile', profile, 'dlllist', '-f', memory_dump_path]
    output = run_volatility(command)

    if output:
        dll_list = []
        lines = output.splitlines()
        for line in lines[4:]:  # Skip the header lines
            parts = line.split()
            if len(parts) >= 3:
                dll_info = {
                    'Base': parts[0],
                    'Name': parts[1],
                    'Path': parts[2]
                }
                dll_list.append(dll_info)
        return dll_list
    return []

def analyze_memory_dump(memory_dump_path, profile):
    """Analyze the memory dump and return a summary."""
    processes = get_process_list(memory_dump_path, profile)
    dlls = get_dll_list(memory_dump_path, profile)

    analysis_summary = {
        'Process Count': len(processes),
        'Processes': processes,
        'DLL Count': len(dlls),
        'DLLs': dlls
    }

    return json.dumps(analysis_summary, indent=4)

if __name__ == "__main__":
    memory_dump_path = "path/to/memdump.mem"  # Update with your memory dump path
    profile = "Win7SP1x64"  # Update with your OS profile

    summary = analyze_memory_dump(memory_dump_path, profile)
    print(summary)