import os
import logging

def setup_logging(log_file='app.log'):
    """Set up logging configuration."""
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s:%(levelname)s:%(message)s'
    )
    logging.info("Logging is set up.")

def is_valid_pe_file(file_path):
    """Check if the provided file path is a valid PE file."""
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        return False
    
    if not file_path.lower().endswith('.exe'):
        logging.error(f"Invalid file type: {file_path}. Expected a .exe file.")
        return False
    
    logging.info(f"Valid PE file: {file_path}")
    return True

def read_file_contents(file_path):
    """Read the contents of a file and return it."""
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

def write_to_file(file_path, content):
    """Write content to a file."""
    try:
        with open(file_path, 'w') as f:
            f.write(content)
        logging.info(f"Successfully wrote to {file_path}.")
    except Exception as e:
        logging.error(f"Error writing to file {file_path}: {e}")

def clear_console():
    """Clear the console output."""
    os.system('cls' if os.name == 'nt' else 'clear')


if __name__ == "__main__":
    setup_logging()
    
    
    test_file = "test.txt"
    
    write_to_file(test_file, "This is a test.")
    
    content = read_file_contents(test_file)
    print(content)
    
    print("Is valid PE file:", is_valid_pe_file(test_file))
