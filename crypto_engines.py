import os
import subprocess
import re
import tempfile
import shutil
import logging
from utils import to_binary, to_binary_base64, run_command, find_7zip_executable, find_openssl_executable, find_zstd_executable, create_temp_directory, clean_password

class CryptoEngine:
    def __init__(self):
        self.settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'normal',
            '7zip_version': '24.08',
            'zstd_version': '1.5.7',
            'openssl_version': '3.5.1',
            'cipher_algorithm': 'aes-256-cbc',
            'use_salt': True,
            'use_pbkdf2': True,
            'use_pbkdf2_iterations': True,
            'pbkdf2_iterations': 200000,
            'theme': 'Classic',
            'telegram_token': '',
            'master_password': '',
            'show_passwords': False,
            'delete_temp_files': True
        }
        self.unsupported_ciphers = ['chacha20', 'chacha20-poly1305', 'gcm', 'ccm', 'ocb', 'siv', 'wrap', 'xts']
        
    def update_settings(self, settings):
        """Update engine settings"""
        self.settings.update(settings)
        
    def get_settings(self):
        """Get current settings"""
        return self.settings.copy()
        
    def log_step(self, message):
        """Log a processing step"""
        logging.info(message)
        return message
        
    def find_7zip_executable(self, version=None):
        """Find 7zip executable based on version"""
        if version is None:
            version = self.settings.get('7zip_version', '24.08')
        return find_7zip_executable(version)
        
    def find_zstd_executable(self, version=None):
        """Find Zstandard executable based on version"""
        if version is None:
            version = self.settings.get('zstd_version', '1.5.7')
        return find_zstd_executable(version)
        
    def find_openssl_executable(self, version=None):
        """Find OpenSSL executable based on version"""
        if version is None:
            version = self.settings.get('openssl_version', '3.5.1')
        return find_openssl_executable(version)
        
    def run_command(self, command, capture_output=True, timeout=30):
        """Run a command and return the result"""
        return run_command(command, capture_output, timeout)
        
    def build_openssl_cmd(self, base_cmd, use_salt=True, use_pbkdf2=True):
        """Build OpenSSL command with conditional salt and PBKDF2 options"""
        cmd = base_cmd
        cipher = self.settings.get('cipher_algorithm', 'aes-256-cbc')
        # Disable salt and PBKDF2 for ciphers that don't support them
        if any(unsupported in cipher.lower() for unsupported in self.unsupported_ciphers):
            logging.warning(f"Cipher {cipher} does not support -salt or -pbkdf2. Skipping these options.")
        else:
            if use_salt and self.settings.get('use_salt', True):
                cmd += " -salt"
            if use_pbkdf2 and self.settings.get('use_pbkdf2', True):
                cmd += " -pbkdf2"
                if self.settings.get('use_pbkdf2_iterations', True):
                    iterations = self.settings.get('pbkdf2_iterations', 200000)
                    cmd += f" -iter {iterations}"
        # Добавляем совместимость с различными версиями OpenSSL
        cmd += " -md sha256"  # Используем SHA256 для совместимости
        return cmd
        
    def validate_cipher(self):
        """Validate if the selected cipher is supported"""
        cipher = self.settings.get('cipher_algorithm', 'aes-256-cbc')
        if cipher == 'id-aes256-GCM':
            logging.warning("Cipher id-aes256-GCM is not supported by OpenSSL 'enc' command. Falling back to aes-256-cbc.")
            self.settings['cipher_algorithm'] = 'aes-256-cbc'
            return False
        if any(unsupported in cipher.lower() for unsupported in self.unsupported_ciphers):
            logging.error(f"Unsupported cipher selected: {cipher}. Falling back to aes-256-cbc.")
            self.settings['cipher_algorithm'] = 'aes-256-cbc'
            return False
        return True

    def _get_compression_level(self):
        """Get compression level based on settings"""
        compression_method = self.settings.get('compression_method', 'normal')
        return {
            'none': '0',
            'fast': '1',
            'medium': '3',
            'normal': '5',
            'high': '7',
            'ultra': '9',
            'custom': '9'  # default for custom
        }.get(compression_method, '9')  # default to normal if not found
        
    def encrypt_files(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt files using the specified method"""
        try:
            if not self.validate_cipher():
                raise ValueError(f"Unsupported cipher: {self.settings['cipher_algorithm']}")
                
            method = self.settings['file_methods']
            
            if method == 'binary_openssl_7zip':
                return self._encrypt_binary_openssl_7zip(file_paths, password, output_path, progress_callback)
            elif method == 'secure_openssl_7zip':
                return self._encrypt_secure_openssl_7zip(file_paths, password, output_path, progress_callback)
            elif method == 'openssl_only':
                return self._encrypt_openssl_only(file_paths, password, output_path, progress_callback)
            elif method == 'openssl_7zip':
                return self._encrypt_openssl_7zip(file_paths, password, output_path, progress_callback)
            elif method == 'binary_openssl_7zip_no_pass_enc':
                return self._encrypt_binary_openssl_7zip_no_pass_enc(file_paths, password, output_path, progress_callback)
            elif method == 'binary_openssl_7zip_no_pass':
                return self._encrypt_binary_openssl_7zip_no_pass(file_paths, output_path, progress_callback)
            else:
                raise ValueError(f"Unknown encryption method: {method}")
                
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise

    def decrypt_files(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt files using the specified method"""
        try:
            if not self.validate_cipher():
                raise ValueError(f"Unsupported cipher: {self.settings['cipher_algorithm']}")
                
            method = self.settings['file_methods']
            
            if method == 'binary_openssl_7zip':
                return self._decrypt_binary_openssl_7zip(encrypted_file, password, output_dir, progress_callback)
            elif method == 'secure_openssl_7zip':
                return self._decrypt_secure_openssl_7zip(encrypted_file, password, output_dir, progress_callback)
            elif method == 'openssl_only':
                return self._decrypt_openssl_only(encrypted_file, password, output_dir, progress_callback)
            elif method == 'openssl_7zip':
                return self._decrypt_openssl_7zip(encrypted_file, password, output_dir, progress_callback)
            elif method == 'binary_openssl_7zip_no_pass_enc':
                return self._decrypt_binary_openssl_7zip_no_pass_enc(encrypted_file, password, output_dir, progress_callback)
            elif method == 'binary_openssl_7zip_no_pass':
                return self._decrypt_binary_openssl_7zip_no_pass(encrypted_file, output_dir, progress_callback)
            else:
                raise ValueError(f"Unknown decryption method: {method}")
                
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise

    def encrypt_password(self, password):
        """Encrypt password using current settings"""
        if not password:
            return ""
            
        openssl_path = self.find_openssl_executable()
        if not openssl_path:
            raise FileNotFoundError("OpenSSL executable not found")
            
        temp_in = os.path.join(tempfile.gettempdir(), 'zipcrypt_pwd_temp_in.txt')
        temp_out = os.path.join(tempfile.gettempdir(), 'zipcrypt_pwd_temp_out.enc')
        
        try:
            # Записываем пароль во временный файл
            with open(temp_in, 'w', encoding='utf-8') as f:
                f.write(password)
                
            cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
            cmd = self.build_openssl_cmd(cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            cmd += f' -in "{temp_in}" -out "{temp_out}" -pass pass:{password}'
            
            # Запускаем команду без захвата вывода (так как он бинарный)
            result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
            if result.returncode != 0:
                raise Exception(f"Password encryption failed: {result.stderr.decode('utf-8', errors='replace')}")
                
            # Читаем зашифрованные данные как бинарные
            with open(temp_out, 'rb') as f:
                encrypted = f.read().decode('utf-8')  # Декодируем только после чтения
                
            return encrypted
        finally:
            if os.path.exists(temp_in):
                os.remove(temp_in)
            if os.path.exists(temp_out):
                os.remove(temp_out)
                
    def decrypt_password(self, encrypted_password, password):
        """Decrypt password using current settings"""
        if not encrypted_password or not password:
            return ""
            
        openssl_path = self.find_openssl_executable()
        if not openssl_path:
            raise FileNotFoundError("OpenSSL executable not found")
            
        temp_in = os.path.join(tempfile.gettempdir(), 'zipcrypt_pwd_temp_in.enc')
        temp_out = os.path.join(tempfile.gettempdir(), 'zipcrypt_pwd_temp_out.txt')
        
        try:
            # Записываем зашифрованные данные во временный файл
            with open(temp_in, 'w', encoding='utf-8') as f:
                f.write(encrypted_password)
                
            cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
            cmd = self.build_openssl_cmd(cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            cmd += f' -in "{temp_in}" -out "{temp_out}" -pass pass:{password}'
            
            # Запускаем команду без захвата вывода
            result = subprocess.run(cmd, shell=True, stderr=subprocess.PIPE)
            if result.returncode != 0:
                raise Exception(f"Password decryption failed: {result.stderr.decode('utf-8', errors='replace')}")
                
            # Читаем расшифрованный пароль
            with open(temp_out, 'r', encoding='utf-8') as f:
                decrypted = f.read().strip()
                
            return decrypted
        finally:
            if os.path.exists(temp_in):
                os.remove(temp_in)
            if os.path.exists(temp_out):
                os.remove(temp_out)

    def _encrypt_binary_openssl_7zip_no_pass_enc(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using binary conversion -> OpenSSL -> 7zip without password encryption"""
        temp_dir = create_temp_directory()
        try:
            # Шаг 1: Преобразование пароля
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            
            if progress_callback:
                progress_callback(f"Преобразование пароля в двоичный код и Base64")

            # Шаг 2: Шифрование файлов через OpenSSL
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypted_files_dir = os.path.join(temp_dir, 'encrypted_files')
            os.makedirs(encrypted_files_dir)
            
            for file_path in file_paths:
                original_name = os.path.basename(file_path)
                encrypted_file = os.path.join(encrypted_files_dir, original_name + '.enc')
                
                openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                openssl_cmd += f' -in "{file_path}" -out "{encrypted_file}" -pass pass:{binary_base64}'
                
                if progress_callback:
                    progress_callback(f"Шифрование файла {original_name} через OpenSSL")
                    
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")

            # Шаг 3: Архивация через 7zip с паролем в открытом виде
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            clean_password_value = clean_password(password) or "defaultPass123"
            compression_level = self._get_compression_level()
            
            compression_cmd = f'"{compression_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{clean_password_value} "{output_path}" "{encrypted_files_dir}\\*"'
            
            if progress_callback:
                progress_callback(f"Архивация через 7zip с паролем в открытом виде")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _decrypt_binary_openssl_7zip_no_pass_enc(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using binary conversion -> OpenSSL -> 7zip without password encryption"""
        temp_dir = create_temp_directory()
        try:
            # Шаг 1: Распаковка архива 7zip с паролем в открытом виде
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            clean_password_value = clean_password(password) or "defaultPass123"
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            compression_cmd = f'"{compression_path}" x "{encrypted_file}" -o"{extracted_dir}" -p{clean_password_value}'
            
            if progress_callback:
                progress_callback(f"Распаковка архива 7zip с паролем в открытом виде")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")

            # Шаг 2: Расшифровка файлов через OpenSSL
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            os.makedirs(output_dir, exist_ok=True)
            
            for file_name in os.listdir(extracted_dir):
                if file_name.endswith('.enc'):
                    encrypted_file_path = os.path.join(extracted_dir, file_name)
                    decrypted_file = os.path.join(output_dir, file_name[:-4])
                    
                    openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
                    openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                    openssl_cmd += f' -in "{encrypted_file_path}" -out "{decrypted_file}" -pass pass:{binary_base64}'
                    
                    if progress_callback:
                        progress_callback(f"Расшифровка файла {file_name}")
                        
                    result = self.run_command(openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                        
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
















    def _encrypt_secure_openssl_7zip(self, file_paths, password, output_path, progress_callback=None):
        """Simplified secure encryption using same password for both steps"""
        temp_dir = create_temp_directory()
        try:
            if progress_callback:
                progress_callback(f"Начало шифрования с паролем: {password[:3]}...")

            # Step 1: Encrypt files with OpenSSL using original password
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypted_files_dir = os.path.join(temp_dir, 'encrypted_files')
            os.makedirs(encrypted_files_dir)
            
            for file_path in file_paths:
                original_name = os.path.basename(file_path)
                encrypted_file = os.path.join(encrypted_files_dir, original_name + '.enc')
                
                openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                openssl_cmd += f' -in "{file_path}" -out "{encrypted_file}" -pass pass:{password}'
                
                if progress_callback:
                    progress_callback(f"Шифрование файла {original_name}")
                    
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")

            # Step 2: Archive with 7zip using original password
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            compression_level = self._get_compression_level()
            compression_cmd = f'"{compression_path}" a -t7z -m0=lzma2 -mx={compression_level} -p"{password}" "{output_path}" "{encrypted_files_dir}\\*"'
            
            if progress_callback:
                progress_callback(f"Архивация через 7zip")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _decrypt_secure_openssl_7zip(self, encrypted_file, password, output_dir, progress_callback=None):
        """Simplified secure decryption using same password for both steps"""
        temp_dir = create_temp_directory()
        try:
            if progress_callback:
                progress_callback(f"Начало расшифровки с паролем: {password[:3]}...")

            # Step 1: Extract archive with 7zip using original password
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            compression_cmd = f'"{compression_path}" x "{encrypted_file}" -o"{extracted_dir}" -p"{password}"'
            
            if progress_callback:
                progress_callback(f"Распаковка архива 7zip")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")

            # Step 2: Decrypt files with OpenSSL using original password
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            os.makedirs(output_dir, exist_ok=True)
            
            for file_name in os.listdir(extracted_dir):
                if file_name.endswith('.enc'):
                    encrypted_file_path = os.path.join(extracted_dir, file_name)
                    decrypted_file = os.path.join(output_dir, file_name[:-4])
                    
                    openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
                    openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                    openssl_cmd += f' -in "{encrypted_file_path}" -out "{decrypted_file}" -pass pass:{password}'
                    
                    if progress_callback:
                        progress_callback(f"Расшифровка файла {file_name}")
                        
                    result = self.run_command(openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                        
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)



























    def _encrypt_binary_openssl_7zip_no_pass(self, file_paths, output_path, progress_callback=None):
        """Encrypt using binary conversion -> OpenSSL -> 7zip without password"""
        temp_dir = create_temp_directory()
        try:
            # Шаг 1: Шифрование файлов через OpenSSL с фиксированным паролем
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypted_files_dir = os.path.join(temp_dir, 'encrypted_files')
            os.makedirs(encrypted_files_dir)
            
            # Используем фиксированный пароль для OpenSSL
            fixed_password = "default_encryption_password"
            binary_base64 = to_binary_base64(fixed_password)
            
            for file_path in file_paths:
                original_name = os.path.basename(file_path)
                encrypted_file = os.path.join(encrypted_files_dir, original_name + '.enc')
                
                openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                openssl_cmd += f' -in "{file_path}" -out "{encrypted_file}" -pass pass:{binary_base64}'
                
                if progress_callback:
                    progress_callback(f"Шифрование файла {original_name} через OpenSSL")
                    
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")

            # Шаг 2: Архивация через 7zip без пароля
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            compression_level = self._get_compression_level()
            compression_cmd = f'"{compression_path}" a -t7z -m0=lzma2 -mx={compression_level} "{output_path}" "{encrypted_files_dir}\\*"'
            
            if progress_callback:
                progress_callback(f"Архивация через 7zip без пароля")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _decrypt_binary_openssl_7zip_no_pass(self, encrypted_file, output_dir, progress_callback=None):
        """Decrypt using binary conversion -> OpenSSL -> 7zip without password"""
        temp_dir = create_temp_directory()
        try:
            # Шаг 1: Распаковка архива 7zip без пароля
            compression_path = self.find_7zip_executable()
            if not compression_path:
                raise FileNotFoundError("7zip executable not found")
                
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            compression_cmd = f'"{compression_path}" x "{encrypted_file}" -o"{extracted_dir}"'
            
            if progress_callback:
                progress_callback(f"Распаковка архива 7zip без пароля")
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")

            # Шаг 2: Расшифровка файлов через OpenSSL с фиксированным паролем
            fixed_password = "default_encryption_password"
            binary_base64 = to_binary_base64(fixed_password)
            
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            os.makedirs(output_dir, exist_ok=True)
            
            for file_name in os.listdir(extracted_dir):
                if file_name.endswith('.enc'):
                    encrypted_file_path = os.path.join(extracted_dir, file_name)
                    decrypted_file = os.path.join(output_dir, file_name[:-4])
                    
                    openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
                    openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                    openssl_cmd += f' -in "{encrypted_file_path}" -out "{decrypted_file}" -pass pass:{binary_base64}'
                    
                    if progress_callback:
                        progress_callback(f"Расшифровка файла {file_name}")
                        
                    result = self.run_command(openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                        
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _encrypt_binary_openssl_7zip(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using binary conversion -> OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            # Шифруем пароль для OpenSSL
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            
            # Очищаем пароль для 7zip (только буквы/цифры)
            clean_7zip_password = clean_password(password)
            if not clean_7zip_password:
                clean_7zip_password = "defaultPass123"  # fallback
                
            step1_msg = f"переводим пароль {password} в двоичный код -> {binary_password} -> base64: {binary_base64}"
            self.log_step(step1_msg)
            if progress_callback:
                progress_callback(step1_msg)
                
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypted_files_dir = os.path.join(temp_dir, 'encrypted_files')
            os.makedirs(encrypted_files_dir)
            
            for file_path in file_paths:
                if os.path.isfile(file_path):
                    original_name = os.path.basename(file_path)
                    encrypted_file = os.path.join(encrypted_files_dir, original_name + '.enc')
                    file_openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                    file_openssl_cmd = self.build_openssl_cmd(file_openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                    file_openssl_cmd += f' -in "{file_path}" -out "{encrypted_file}" -pass pass:{binary_base64}'
                    
                    step2_msg = f"шифруем файл {original_name} паролем {binary_base64} через openssl"
                    self.log_step(step2_msg)
                    if progress_callback:
                        progress_callback(step2_msg)
                        
                    result = self.run_command(file_openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"File encryption failed: {result.stderr}")
                        
                elif os.path.isdir(file_path):
                    original_name = os.path.basename(file_path)
                    archive_path = os.path.join(temp_dir, f"{original_name}.tar.gz")
                    tar_cmd = f'tar -czf "{archive_path}" -C "{os.path.dirname(file_path)}" "{os.path.basename(file_path)}"'
                    self.run_command(tar_cmd)
                    
                    encrypted_archive = os.path.join(encrypted_files_dir, f"{original_name}.tar.gz.enc")
                    archive_openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                    archive_openssl_cmd = self.build_openssl_cmd(archive_openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                    archive_openssl_cmd += f' -in "{archive_path}" -out "{encrypted_archive}" -pass pass:{binary_base64}'
                    
                    step2_msg = f"шифруем архив {original_name}.tar.gz паролем {binary_base64} через openssl"
                    self.log_step(step2_msg)
                    if progress_callback:
                        progress_callback(step2_msg)
                        
                    result = self.run_command(archive_openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"Archive encryption failed: {result.stderr}")
                        
            compression_path = self.find_7zip_executable()
            if not compression_path and self.settings.get('7zip_version') == '24.09_zstandard':
                compression_path = self.find_zstd_executable()
                if not compression_path:
                    raise FileNotFoundError("Zstandard executable not found")
                compression_cmd = f'"{compression_path}" -z "{encrypted_files_dir}" -o "{output_path}"'
            else:
                if not compression_path:
                    raise FileNotFoundError("7zip executable not found")
                compression_level = {
                    'normal': '5',
                    'fast': '1',
                    'ultra': '9'
                }.get(self.settings['compression_method'], '5')
                
                # Используем очищенный пароль для 7zip
                compression_cmd = f'"{compression_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{clean_7zip_password} "{output_path}" "{encrypted_files_dir}\\*"'
            
            step3_msg = f"архивируем через 7zip с очищенным паролем (только буквы/цифры)"
            self.log_step(step3_msg)
            if progress_callback:
                progress_callback(step3_msg)
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Compression failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
            
    def _decrypt_binary_openssl_7zip(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using binary conversion -> OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            # Очищаем пароль для 7zip
            clean_7zip_password = clean_password(password)
            if not clean_7zip_password:
                clean_7zip_password = "defaultPass123"  # fallback
                
            compression_path = self.find_7zip_executable()
            if not compression_path and self.settings.get('7zip_version') == '24.09_zstandard':
                compression_path = self.find_zstd_executable()
                if not compression_path:
                    raise FileNotFoundError("Zstandard executable not found")
                extracted_dir = os.path.join(temp_dir, 'extracted')
                os.makedirs(extracted_dir)
                compression_cmd = f'"{compression_path}" -d "{encrypted_file}" -o "{extracted_dir}"'
            else:
                if not compression_path:
                    raise FileNotFoundError("7zip executable not found")
                extracted_dir = os.path.join(temp_dir, 'extracted')
                os.makedirs(extracted_dir)
                compression_cmd = f'"{compression_path}" x "{encrypted_file}" -o"{extracted_dir}" -p{clean_7zip_password}'
            
            step1_msg = f"распаковываем архив через 7zip с очищенным паролем"
            self.log_step(step1_msg)
            if progress_callback:
                progress_callback(step1_msg)
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Extraction failed: {result.stderr}")
                
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            step2_msg = f"переводим пароль {password} в двоичный код -> {binary_password} -> base64: {binary_base64}"
            self.log_step(step2_msg)
            if progress_callback:
                progress_callback(step2_msg)
                
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            os.makedirs(output_dir, exist_ok=True)
            
            extracted_files = os.listdir(extracted_dir)
            logging.info(f"Found files in extracted directory: {extracted_files}")
            
            if not extracted_files:
                raise Exception("No files found in extracted archive")
                
            encrypted_files_found = [f for f in extracted_files if f.endswith('.enc')]
            if not encrypted_files_found:
                raise Exception(f"No .enc files found in extracted directory. Available files: {extracted_files}")
                
            for file_path in encrypted_files_found:
                encrypted_file = os.path.join(extracted_dir, file_path)
                decrypted_file = os.path.join(output_dir, file_path[:-4])
                decrypt_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
                decrypt_cmd = self.build_openssl_cmd(decrypt_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                decrypt_cmd += f' -in "{encrypted_file}" -out "{decrypted_file}" -pass pass:{binary_base64}'
                
                step3_msg = f"расшифровываем файл {file_path} паролем {binary_base64} через openssl ({decrypt_cmd})"
                self.log_step(step3_msg)
                if progress_callback:
                    progress_callback(step3_msg)
                    
                result = self.run_command(decrypt_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"File decryption failed: {result.stderr}")
                    
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
            
    def _encrypt_openssl_only(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using OpenSSL only"""
        temp_dir = create_temp_directory()
        try:
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            if len(file_paths) == 1 and os.path.isfile(file_paths[0]):
                openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                openssl_cmd += f' -in "{file_paths[0]}" -out "{output_path}" -pass pass:{password}'
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                return True
            else:
                archive_path = os.path.join(temp_dir, 'archive.tar.gz')
                tar_cmd = f'tar -czf "{archive_path}" {" ".join(file_paths)}'
                self.run_command(tar_cmd)
                
                openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
                openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
                openssl_cmd += f' -in "{archive_path}" -out "{output_path}" -pass pass:{password}'
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                return True
                
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
    def _decrypt_openssl_only(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using OpenSSL only"""
        openssl_path = self.find_openssl_executable()
        if not openssl_path:
            raise FileNotFoundError("OpenSSL executable not found")
            
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, 'decrypted_file')
        openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
        openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
        openssl_cmd += f' -in "{encrypted_file}" -out "{output_file}" -pass pass:{password}'
        result = self.run_command(openssl_cmd)
        
        if result and result.returncode == 0:
            try:
                import tarfile
                with tarfile.open(output_file, 'r:gz') as tar:
                    tar.extractall(output_dir)
                os.remove(output_file)
            except:
                os.rename(output_file, os.path.join(output_dir, 'decrypted'))
            return True
        else:
            raise Exception(f"OpenSSL decryption failed: {result.stderr}")
        
    def _encrypt_openssl_7zip(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            archive_path = os.path.join(temp_dir, 'archive.tar.gz')
            tar_cmd = f'tar -czf "{archive_path}" {" ".join(file_paths)}'
            self.run_command(tar_cmd)
            
            encrypted_archive = os.path.join(temp_dir, 'archive.enc')
            openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a'
            openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            openssl_cmd += f' -in "{archive_path}" -out "{encrypted_archive}" -pass pass:{password}'
            result = self.run_command(openssl_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                
            compression_path = self.find_7zip_executable()
            if not compression_path and self.settings.get('7zip_version') == '24.09_zstandard':
                compression_path = self.find_zstd_executable()
                if not compression_path:
                    raise FileNotFoundError("Zstandard executable not found")
                compression_cmd = f'"{compression_path}" -z "{encrypted_archive}" -o "{output_path}"'
            else:
                if not compression_path:
                    raise FileNotFoundError("7zip executable not found")
                compression_level = {
                    'normal': '5',
                    'fast': '1',
                    'ultra': '9'
                }.get(self.settings['compression_method'], '5')
                compression_cmd = f'"{compression_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{password} "{output_path}" "{encrypted_archive}"'
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Compression failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
    def _decrypt_openssl_7zip(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            compression_path = self.find_7zip_executable()
            if not compression_path and self.settings.get('7zip_version') == '24.09_zstandard':
                compression_path = self.find_zstd_executable()
                if not compression_path:
                    raise FileNotFoundError("Zstandard executable not found")
                extracted_dir = os.path.join(temp_dir, 'extracted')
                os.makedirs(extracted_dir)
                compression_cmd = f'"{compression_path}" -d "{encrypted_file}" -o "{extracted_dir}"'
            else:
                if not compression_path:
                    raise FileNotFoundError("7zip executable not found")
                extracted_dir = os.path.join(temp_dir, 'extracted')
                os.makedirs(extracted_dir)
                compression_cmd = f'"{compression_path}" x "{encrypted_file}" -o"{extracted_dir}" -p{password}'
                
            result = self.run_command(compression_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Extraction failed: {result.stderr}")
                
            files = [f for f in os.listdir(extracted_dir) if f.endswith('.enc')]
            if not files:
                raise Exception("No encrypted file found")
                
            encrypted_file_path = os.path.join(extracted_dir, files[0])
            
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            decrypted_archive = os.path.join(temp_dir, 'decrypted.tar.gz')
            openssl_cmd = f'"{openssl_path}" {self.settings["cipher_algorithm"]} -a -d'
            openssl_cmd = self.build_openssl_cmd(openssl_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            openssl_cmd += f' -in "{encrypted_file_path}" -out "{decrypted_archive}" -pass pass:{password}'
            result = self.run_command(openssl_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                
            os.makedirs(output_dir, exist_ok=True)
            tar_cmd = f'tar -xzf "{decrypted_archive}" -C "{output_dir}"'
            result = self.run_command(tar_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Archive extraction failed: {result.stderr}")
                
            return True
            
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)