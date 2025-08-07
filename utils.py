import logging
import os
import subprocess
import tempfile
import shutil
from datetime import datetime

def setup_logging():
    """Setup logging configuration"""
    logger = logging.getLogger()
    
    # Проверяем, не настроено ли уже логирование
    if not logger.handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('zipcrypt.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

def to_binary(text):
    """Convert text to binary representation"""
    binary = ' '.join(format(ord(char), '08b') for char in text)
    return binary

def to_binary_base64(text):
    """Convert text to binary and then to base64 for use as password"""
    import base64
    # Convert to binary first
    binary = ''.join(format(ord(char), '08b') for char in text)
    # Convert binary string to base64
    binary_bytes = binary.encode('utf-8')
    base64_result = base64.b64encode(binary_bytes).decode('utf-8')
    return base64_result

def to_base64(data):
    """Convert data to base64"""
    import base64
    return base64.b64encode(data).decode('utf-8')

def to_ascii(data):
    """Convert data to ASCII representation"""
    return ''.join(chr(byte) for byte in data)

def find_7zip_executable(version=None):
    """Find 7zip executable based on version"""
    if version is None:
        # Try to find any available version
        versions = ['7zip_24.08', '7zip_920', '7zip_2501_extra']
        for ver in versions:
            path = os.path.join('7zip', ver, '7za.exe')
            if os.path.exists(path):
                return path
    else:
        path = os.path.join('7zip', f'7zip_{version}', '7za.exe')
        if os.path.exists(path):
            return path
    return None

def find_openssl_executable(version=None):
    """Find OpenSSL executable based on version"""
    if version is None:
        # Try to find any available version
        versions = ['OpenSSL_3.5.1', 'OpenSSL_3.5.1_Light', 'OpenSSL_3.2.4']
        for ver in versions:
            path = os.path.join('OpenSSL', ver, 'openssl.exe')
            if os.path.exists(path):
                return path
    else:
        path = os.path.join('OpenSSL', f'OpenSSL_{version}', 'openssl.exe')
        if os.path.exists(path):
            return path
    return None

def run_command(command, capture_output=True, timeout=30):
    """Run a command and return the result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            encoding='utf-8'
        )
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {command}")
        return None
    except Exception as e:
        logging.error(f"Error running command '{command}': {e}")
        return None

def create_temp_directory():
    """Create a temporary directory in the program's directory"""
    import tempfile
    import time
    
    # Get the program's directory
    program_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Create temp directory in program's directory
    timestamp = int(time.time())
    temp_dir = os.path.join(program_dir, f'temp_zipcrypt_{timestamp}')
    
    # Create the directory
    os.makedirs(temp_dir, exist_ok=True)
    logging.info(f"Created temporary directory: {temp_dir}")
    return temp_dir

def cleanup_temp_directory(temp_dir):
    """Clean up temporary directory"""
    try:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logging.info(f"Cleaned up temporary directory: {temp_dir}")
    except Exception as e:
        logging.error(f"Error cleaning up temporary directory {temp_dir}: {e}")

def cleanup_all_temp_directories():
    """Clean up all temporary directories created by the program"""
    import glob
    import time
    
    # Get the program's directory
    program_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Find all temp directories
    temp_pattern = os.path.join(program_dir, 'temp_zipcrypt_*')
    temp_dirs = glob.glob(temp_pattern)
    
    for temp_dir in temp_dirs:
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logging.info(f"Cleaned up old temporary directory: {temp_dir}")
        except Exception as e:
            logging.error(f"Error cleaning up old temporary directory {temp_dir}: {e}")

def get_file_size(file_path):
    """Get file size in human readable format"""
    try:
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except Exception:
        return "Unknown"

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Пароль не может быть пустым"
    
    if len(password) < 3:
        return False, "Пароль должен содержать минимум 3 символа"
    
    return True, "Пароль валиден"

def copy_to_clipboard(text):
    """Copy text to clipboard"""
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except ImportError:
        # Fallback for systems without pyperclip
        try:
            import subprocess
            process = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
            process.communicate(input=text.encode())
            return True
        except Exception:
            return False
    except Exception:
        return False 

def test_encryption_functionality():
    """Test encryption/decryption functionality automatically"""
    import tempfile
    import os
    import shutil
    
    print("Testing encryption/decryption functionality...")
    
    # Create test file
    test_content = "ZipCrypt test file - encryption/decryption verification"
    test_file = "startup_test.txt"
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    try:
        # Import crypto engine
        from crypto_engines import CryptoEngine
        
        # Create crypto engine
        engine = CryptoEngine()
        
        # Test encryption
        password = "startup_test_123"
        encrypted_file = "startup_test_encrypted.dll"
        
        def progress_callback(message):
            # Silent callback for startup test
            pass
        
        # Encrypt
        result = engine.encrypt_files([test_file], password, encrypted_file, progress_callback)
        if not result:
            print("❌ Encryption test failed")
            return False
            
        # Test decryption
        output_dir = "startup_test_output"
        
        # Decrypt
        result = engine.decrypt_files(encrypted_file, password, output_dir, progress_callback)
        if not result:
            print("❌ Decryption test failed")
            return False
            
        # Verify decrypted file
        decrypted_file = os.path.join(output_dir, "startup_test.txt")
        if os.path.exists(decrypted_file):
            with open(decrypted_file, 'r', encoding='utf-8') as f:
                decrypted_content = f.read()
            if decrypted_content == test_content:
                print("✅ Encryption/decryption test passed")
                return True
            else:
                print("❌ Content verification failed")
                return False
        else:
            print("❌ Decrypted file not found")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir) 