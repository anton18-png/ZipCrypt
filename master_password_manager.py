import os
import json
import tempfile
import shutil
import logging
from utils import create_temp_directory, find_openssl_executable, run_command

class MasterPasswordManager:
    def __init__(self):
        self.stored_password = None
        self.password_file = 'master_password.enc'

    def set_stored_password(self, password):
        """Set the stored master password"""
        self.stored_password = password

    def get_stored_password(self):
        """Get the stored master password"""
        return self.stored_password

    def encrypt_master_password(self):
        """Encrypt and save the master password"""
        if not self.stored_password:
            if os.path.exists(self.password_file):
                os.remove(self.password_file)
            return

        temp_dir = None
        try:
            temp_dir = create_temp_directory()
            temp_file = os.path.join(temp_dir, 'master_password.txt')
            
            # Save password to temporary file
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump({'master_password': self.stored_password}, f)
            
            # Encrypt with OpenSSL
            openssl_path = find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
            
            encrypt_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{temp_file}" -out "{self.password_file}" -pass pass:{self.stored_password}'
            
            result = run_command(encrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL encryption failed: {result.stderr}")
            
            logging.info("Master password encrypted and saved")
            
        except Exception as e:
            logging.error(f"Error encrypting master password: {e}")
            raise
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    def decrypt_master_password(self, input_password):
        """Decrypt and return the stored master password"""
        if not os.path.exists(self.password_file):
            return None

        temp_dir = None
        try:
            temp_dir = create_temp_directory()
            temp_decrypted = os.path.join(temp_dir, 'master_password.dec')
            
            # Decrypt with OpenSSL
            openssl_path = find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
            
            decrypt_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -d -in "{self.password_file}" -out "{temp_decrypted}" -pass pass:{input_password}'
            
            result = run_command(decrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL decryption failed: {result.stderr}")
            
            # Read decrypted password
            with open(temp_decrypted, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('master_password')
                
        except Exception as e:
            logging.error(f"Error decrypting master password: {e}")
            return None
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)