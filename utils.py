import logging
import os
import subprocess
import tempfile
import shutil
import json
from datetime import datetime

def setup_logging():
    """Setup logging configuration"""
    logger = logging.getLogger()
    
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
    binary = ''.join(format(ord(char), '08b') for char in text)
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
        versions = ['7zip_24.08', '7zip_920', '7zip_2501_extra', '7zip_24.09_zstandard']
        for ver in versions:
            path = os.path.join('7zip', ver, '7za.exe')
            if os.path.exists(path):
                return path
    else:
        path = os.path.join('7zip', f'7zip_{version}', '7za.exe')
        if os.path.exists(path):
            return path
    return None

def find_zstd_executable(version=None):
    """Find Zstandard executable based on version"""
    if version is None:
        versions = ['zstd_1.5.7']
        for ver in versions:
            path = os.path.join('zstd', ver, 'zstd.exe')
            if os.path.exists(path):
                return path
    else:
        path = os.path.join('zstd', f'zstd_{version}', 'zstd.exe')
        if os.path.exists(path):
            return path
    return None

def find_openssl_executable(version=None):
    """Find OpenSSL executable based on version"""
    if version is None:
        versions = ['OpenSSL_3.5.1', 'OpenSSL_3.5.1_Light', 'OpenSSL_3.2.4', 'OpenSSL_4.1.0_LibreSSL']
        for ver in versions:
            path = os.path.join('OpenSSL', ver, 'openssl.exe')
            if os.path.exists(path):
                return path
    else:
        path = os.path.join('OpenSSL', f'OpenSSL_{version}', 'openssl.exe')
        if os.path.exists(path):
            return path
    return None

def get_openssl_ciphers():
    """Fetch the list of supported ciphers from OpenSSL"""
    try:
        openssl_path = find_openssl_executable()
        if not openssl_path:
            logging.error("OpenSSL executable not found")
            return ['aes-256-cbc']  # Fallback

        cmd = f'"{openssl_path}" list -cipher-algorithms'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        if result.returncode != 0:
            logging.error(f"Failed to fetch ciphers: {result.stderr}")
            return ['aes-256-cbc']
        
        # Parse ciphers from output
        ciphers = []
        # Убираем только действительно нежелательные режимы, но оставляем GCM
        unsupported_modes = ['ccm', 'ocb', 'siv', 'chacha20', 'wrap', 'xts']
        # Примечание: GCM — это AEAD, но он широко поддерживается и безопасен
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and '=>' not in line:  # Исключаем алиасы
                cipher = line.split()[0].lower().replace('_', '-')
                if not any(mode in cipher for mode in unsupported_modes):
                    ciphers.append(cipher)
        
        # Убедимся, что хотя бы базовые AES есть
        if not ciphers:
            ciphers = [
                'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
                'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm'
            ]
        
        return sorted(set(ciphers))
    except Exception as e:
        logging.error(f"Error fetching OpenSSL ciphers: {e}")
        return ['aes-256-cbc']

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
    import time
    program_dir = os.path.dirname(os.path.abspath(__file__))
    timestamp = int(time.time())
    temp_dir = os.path.join(program_dir, f'temp_zipcrypt_{timestamp}')
    os.makedirs(temp_dir, exist_ok=True)
    logging.info(f"Created temporary directory: {temp_dir}")
    return temp_dir

def load_settings():
    """Load settings from settings.json"""
    default_settings = {
        'delete_temp_files': True,
        'cipher_algorithm': 'aes-256-cbc',
        'use_salt': True,
        'use_pbkdf2': True
    }
    try:
        if os.path.exists('settings.json'):
            with open('settings.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return default_settings
    except Exception as e:
        logging.error(f"Error loading settings: {e}")
        return default_settings

def cleanup_temp_directory(temp_dir):
    """Clean up temporary directory if enabled in settings"""
    try:
        settings = load_settings()
        if settings.get('delete_temp_files', True) and temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logging.info(f"Cleaned up temporary directory: {temp_dir}")
    except Exception as e:
        logging.error(f"Error cleaning up temporary directory {temp_dir}: {e}")

def cleanup_all_temp_directories():
    """Clean up all temporary directories created by the program if enabled in settings"""
    try:
        settings = load_settings()
        if not settings.get('delete_temp_files', True):
            return
        
        import glob
        import time
        program_dir = os.path.dirname(os.path.abspath(__file__))
        temp_pattern = os.path.join(program_dir, 'temp_zipcrypt_*')
        temp_dirs = glob.glob(temp_pattern)
        
        for temp_dir in temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    logging.info(f"Cleaned up old temporary directory: {temp_dir}")
            except Exception as e:
                logging.error(f"Error cleaning up old temporary directory {temp_dir}: {e}")
    except Exception as e:
        logging.error(f"Error in cleanup_all_temp_directories: {e}")

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
    
    test_content = "ZipCrypt test file - encryption/decryption verification"
    test_file = "startup_test.txt"
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    try:
        from crypto_engines import CryptoEngine
        engine = CryptoEngine()
        
        password = "startup_test_123"
        encrypted_file = "startup_test_encrypted.dll"
        
        def progress_callback(message):
            pass
        
        result = engine.encrypt_files([test_file], password, encrypted_file, progress_callback)
        if not result:
            print("❌ Encryption test failed")
            return False
            
        output_dir = "startup_test_output"
        result = engine.decrypt_files(encrypted_file, password, output_dir, progress_callback)
        if not result:
            print("❌ Decryption test failed")
            return False
            
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
        settings = load_settings()
        if settings.get('delete_temp_files', True):
            if os.path.exists(test_file):
                os.remove(test_file)
            if os.path.exists(encrypted_file):
                os.remove(encrypted_file)
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)