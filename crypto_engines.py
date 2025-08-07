import os
import subprocess
import tempfile
import shutil
import logging
from utils import to_binary, to_binary_base64, run_command, find_7zip_executable, find_openssl_executable, create_temp_directory

class CryptoEngine:
    def __init__(self):
        self.settings = {
            'file_methods': 'binary_openssl_7zip',  # binary_openssl_7zip, openssl_only, openssl_7zip
            'compression_method': 'normal',  # normal, fast, ultra
            '7zip_version': '24.08',
            'openssl_version': '3.5.1',
            'theme': 'Classic',  # Classic, Light, Dark, Catppuccin
            'telegram_token': '',
            'master_password': '',
            'show_passwords': False
        }
        
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
        
    def find_openssl_executable(self, version=None):
        """Find OpenSSL executable based on version"""
        if version is None:
            version = self.settings.get('openssl_version', '3.5.1')
        return find_openssl_executable(version)
        
    def run_command(self, command, capture_output=True, timeout=30):
        """Run a command and return the result"""
        return run_command(command, capture_output, timeout)
        
    def encrypt_files(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt files using the specified method"""
        try:
            method = self.settings['file_methods']
            
            if method == 'binary_openssl_7zip':
                return self._encrypt_binary_openssl_7zip(file_paths, password, output_path, progress_callback)
            elif method == 'openssl_only':
                return self._encrypt_openssl_only(file_paths, password, output_path, progress_callback)
            elif method == 'openssl_7zip':
                return self._encrypt_openssl_7zip(file_paths, password, output_path, progress_callback)
            else:
                raise ValueError(f"Unknown encryption method: {method}")
                
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise
            
    def decrypt_files(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt files using the specified method"""
        try:
            method = self.settings['file_methods']
            
            if method == 'binary_openssl_7zip':
                return self._decrypt_binary_openssl_7zip(encrypted_file, password, output_dir, progress_callback)
            elif method == 'openssl_only':
                return self._decrypt_openssl_only(encrypted_file, password, output_dir, progress_callback)
            elif method == 'openssl_7zip':
                return self._decrypt_openssl_7zip(encrypted_file, password, output_dir, progress_callback)
            else:
                raise ValueError(f"Unknown decryption method: {method}")
                
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise
            
    def _encrypt_binary_openssl_7zip(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using binary conversion -> OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            # Step 1: Convert password to binary and then to base64
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            step1_msg = f"переводим пароль {password} в двоичный код -> {binary_password} -> base64: {binary_base64}"
            self.log_step(step1_msg)
            if progress_callback:
                progress_callback(step1_msg)
                
            # Step 2: Encrypt files with binary base64 password
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypted_files_dir = os.path.join(temp_dir, 'encrypted_files')
            os.makedirs(encrypted_files_dir)
            
            for file_path in file_paths:
                if os.path.isfile(file_path):
                    # Encrypt single file
                    original_name = os.path.basename(file_path)
                    encrypted_file = os.path.join(encrypted_files_dir, original_name + '.enc')
                    file_openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{file_path}" -out "{encrypted_file}" -pass pass:{binary_base64}'
                    
                    step2_msg = f"шифруем файл {original_name} паролем {binary_base64} через openssl ({file_openssl_cmd})"
                    self.log_step(step2_msg)
                    if progress_callback:
                        progress_callback(step2_msg)
                        
                    result = self.run_command(file_openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"File encryption failed: {result.stderr}")
                        
                elif os.path.isdir(file_path):
                    # Create archive and encrypt
                    original_name = os.path.basename(file_path)
                    archive_path = os.path.join(temp_dir, f"{original_name}.tar.gz")
                    tar_cmd = f'tar -czf "{archive_path}" -C "{os.path.dirname(file_path)}" "{os.path.basename(file_path)}"'
                    self.run_command(tar_cmd)
                    
                    encrypted_archive = os.path.join(encrypted_files_dir, f"{original_name}.tar.gz.enc")
                    archive_openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{archive_path}" -out "{encrypted_archive}" -pass pass:{binary_base64}'
                    
                    step2_msg = f"шифруем архив {original_name}.tar.gz паролем {binary_base64} через openssl ({archive_openssl_cmd})"
                    self.log_step(step2_msg)
                    if progress_callback:
                        progress_callback(step2_msg)
                        
                    result = self.run_command(archive_openssl_cmd)
                    if result and result.returncode != 0:
                        raise Exception(f"Archive encryption failed: {result.stderr}")
                        
            # Step 3: Create final archive with 7zip
            sevenzip_path = self.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            compression_level = {
                'normal': '5',
                'fast': '1',
                'ultra': '9'
            }.get(self.settings['compression_method'], '5')
            
            sevenzip_cmd = f'"{sevenzip_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{password} "{output_path}" "{encrypted_files_dir}\\*"'
            
            step3_msg = f"архивируем и зашифровываем зашифрованные файлы через 7zip ({sevenzip_cmd})"
            self.log_step(step3_msg)
            if progress_callback:
                progress_callback(step3_msg)
                
            result = self.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            return True
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    def _decrypt_binary_openssl_7zip(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using binary conversion -> OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            # Step 1: Extract from 7zip with user password
            sevenzip_path = self.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            sevenzip_cmd = f'"{sevenzip_path}" x "{encrypted_file}" -o"{extracted_dir}" -p{password}'
            
            step1_msg = f"распаковываем архив через 7zip ({sevenzip_cmd})"
            self.log_step(step1_msg)
            if progress_callback:
                progress_callback(step1_msg)
                
            result = self.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")
                
            # Step 2: Convert password to binary and then to base64 (same as encryption)
            binary_password = to_binary(password)
            binary_base64 = to_binary_base64(password)
            step2_msg = f"переводим пароль {password} в двоичный код -> {binary_password} -> base64: {binary_base64}"
            self.log_step(step2_msg)
            if progress_callback:
                progress_callback(step2_msg)
                
            # Step 3: Decrypt files using the binary base64 password
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            os.makedirs(output_dir, exist_ok=True)
            
            # List all files in extracted directory
            extracted_files = os.listdir(extracted_dir)
            logging.info(f"Found files in extracted directory: {extracted_files}")
            
            if not extracted_files:
                raise Exception("No files found in extracted archive")
                
            encrypted_files_found = [f for f in extracted_files if f.endswith('.enc')]
            if not encrypted_files_found:
                raise Exception(f"No .enc files found in extracted directory. Available files: {extracted_files}")
                
            for file_path in encrypted_files_found:
                encrypted_file = os.path.join(extracted_dir, file_path)
                decrypted_file = os.path.join(output_dir, file_path[:-4])  # Remove .enc extension
                
                decrypt_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -d -in "{encrypted_file}" -out "{decrypted_file}" -pass pass:{binary_base64}'
                
                step3_msg = f"расшифровываем файл {file_path} паролем {binary_base64} через openssl ({decrypt_cmd})"
                self.log_step(step3_msg)
                if progress_callback:
                    progress_callback(step3_msg)
                    
                result = self.run_command(decrypt_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"File decryption failed: {result.stderr}")
                    
            return True
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    def _encrypt_openssl_only(self, file_paths, password, output_path, progress_callback=None):
        """Encrypt using OpenSSL only"""
        temp_dir = create_temp_directory()
        try:
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            # For single file, encrypt directly
            if len(file_paths) == 1 and os.path.isfile(file_paths[0]):
                openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{file_paths[0]}" -out "{output_path}" -pass pass:{password}'
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                return True
            else:
                # For multiple files or directories, create archive first
                archive_path = os.path.join(temp_dir, 'archive.tar.gz')
                tar_cmd = f'tar -czf "{archive_path}" {" ".join(file_paths)}'
                self.run_command(tar_cmd)
                
                openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{archive_path}" -out "{output_path}" -pass pass:{password}'
                result = self.run_command(openssl_cmd)
                if result and result.returncode != 0:
                    raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                return True
                
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        
    def _decrypt_openssl_only(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using OpenSSL only"""
        openssl_path = self.find_openssl_executable()
        if not openssl_path:
            raise FileNotFoundError("OpenSSL executable not found")
            
        os.makedirs(output_dir, exist_ok=True)
        
        # Try to decrypt as single file first
        output_file = os.path.join(output_dir, 'decrypted_file')
        openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -d -in "{encrypted_file}" -out "{output_file}" -pass pass:{password}'
        result = self.run_command(openssl_cmd)
        
        if result and result.returncode == 0:
            # Check if it's an archive
            try:
                import tarfile
                with tarfile.open(output_file, 'r:gz') as tar:
                    tar.extractall(output_dir)
                os.remove(output_file)  # Remove the archive file
            except:
                # Not an archive, rename to original name
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
                
            # Create archive first
            archive_path = os.path.join(temp_dir, 'archive.tar.gz')
            tar_cmd = f'tar -czf "{archive_path}" {" ".join(file_paths)}'
            self.run_command(tar_cmd)
            
            # Encrypt with OpenSSL
            encrypted_archive = os.path.join(temp_dir, 'archive.enc')
            openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{archive_path}" -out "{encrypted_archive}" -pass pass:{password}'
            result = self.run_command(openssl_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                
            # Compress with 7zip
            sevenzip_path = self.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            compression_level = {
                'normal': '5',
                'fast': '1',
                'ultra': '9'
            }.get(self.settings['compression_method'], '5')
            
            sevenzip_cmd = f'"{sevenzip_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{password} "{output_path}" "{encrypted_archive}"'
            result = self.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            return True
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        
    def _decrypt_openssl_7zip(self, encrypted_file, password, output_dir, progress_callback=None):
        """Decrypt using OpenSSL -> 7zip method"""
        temp_dir = create_temp_directory()
        try:
            # Extract from 7zip
            sevenzip_path = self.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            sevenzip_cmd = f'"{sevenzip_path}" x "{encrypted_file}" -o"{extracted_dir}" -p{password}'
            result = self.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")
                
            # Find encrypted file
            files = [f for f in os.listdir(extracted_dir) if f.endswith('.enc')]
            if not files:
                raise Exception("No encrypted file found")
                
            encrypted_file_path = os.path.join(extracted_dir, files[0])
            
            # Decrypt with OpenSSL
            openssl_path = self.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            decrypted_archive = os.path.join(temp_dir, 'decrypted.tar.gz')
            openssl_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -d -in "{encrypted_file_path}" -out "{decrypted_archive}" -pass pass:{password}'
            result = self.run_command(openssl_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                
            # Extract archive
            os.makedirs(output_dir, exist_ok=True)
            tar_cmd = f'tar -xzf "{decrypted_archive}" -C "{output_dir}"'
            result = self.run_command(tar_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Archive extraction failed: {result.stderr}")
                
            return True
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True) 