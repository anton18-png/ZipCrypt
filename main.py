import ttkbootstrap as ttk
from ttkbootstrap import Style
import json
import logging
import os
import tempfile
import shutil
import subprocess
import csv
from datetime import datetime
import threading
import argparse
from tkinter import simpledialog, messagebox

from settings import SettingsTab
from files_tab import FilesTab
from password_manager import PasswordManagerTab
from crypto_engines import CryptoEngine
from utils import setup_logging, cleanup_all_temp_directories, test_encryption_functionality

class ZipCryptApp:
    def __init__(self, root, password_file=None):
        self.root = root
        self.root.title("ZipCrypt - Крипто архиватор и менеджер паролей")
        self.root.geometry("1000x600")
        
        self.default_settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'zstd_version': '1.5.7',  # New setting
            'openssl_version': '3.5.1',
            'aes_algorithm': 'aes-256-cbc',  # New setting
            'use_salt': True,  # New setting
            'use_pbkdf2': True,  # New setting
            'theme': 'boosterxvapor',
            'telegram_token': '',
            'telegram_chat_id': '',
            'logging_enabled': False,
            'disable_encryption_test': True,
            'delete_temp_files': True
        }
        self.settings = self.default_settings.copy()
        
        self.load_settings()
        
        self.configure_logging()
        
        self.crypto_engine = CryptoEngine()
        self.crypto_engine.update_settings(self.settings)
        
        cleanup_all_temp_directories()
        
        if not self.settings.get('disable_encryption_test', False):
            if not test_encryption_functionality():
                messagebox.showwarning("Предупреждение", 
                    "Тест шифрования не прошел. Приложение может работать некорректно.")
                logging.error("Startup encryption test failed")
        
        self.settings['master_password'] = self.prompt_and_verify_master_password()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.files_tab = FilesTab(self.notebook, self.crypto_engine)
        self.password_tab = PasswordManagerTab(self.notebook, self.crypto_engine)
        self.settings_tab = SettingsTab(self.notebook)
        
        self.notebook.add(self.files_tab, text="Файлы")
        self.notebook.add(self.password_tab, text="Пароли")
        self.notebook.add(self.settings_tab, text="Настройки")
        
        self.update_all_components()
        
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
        
        self.settings_tab.set_crypto_engine(self.crypto_engine)
        
        self.set_master_password()
        
        if password_file:
            self.handle_password_file(password_file)
        
        self.settings_tab.apply_theme()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def configure_logging(self):
        """Настройка логирования на основе настроек"""
        if not self.settings.get('logging_enabled', True):
            logging.disable(logging.CRITICAL)
            return
            
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('zipcrypt.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

    def load_settings(self):
        """Загрузка настроек с улучшенной обработкой ошибок"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    self.settings = {**self.default_settings, **loaded_settings}
        except Exception as e:
            logging.error(f"Ошибка загрузки настроек: {e}")
            self.settings = self.default_settings.copy()

    def update_all_components(self):
        """Обновление всех компонентов приложения с текущими настройками"""
        self.crypto_engine.update_settings(self.settings)
        if hasattr(self, 'settings_tab'):
            self.settings_tab.update_settings(self.settings)
        if hasattr(self, 'files_tab'):
            self.files_tab.set_master_password(self.settings.get('master_password', ''))
        if hasattr(self, 'password_tab'):
            self.password_tab.set_master_password(self.settings.get('master_password', ''))

    def save_settings(self):
        """Сохранение настроек с проверкой"""
        try:
            if not self.check_settings_permissions():
                return False
                
            current_settings = {
                'file_methods': self.settings_tab.file_methods_var.get(),
                'compression_method': self.settings_tab.compression_method_var.get(),
                '7zip_version': self.settings_tab.sevenzip_version_var.get(),
                'zstd_version': self.settings_tab.zstd_version_var.get(),  # Save Zstandard version
                'openssl_version': self.settings_tab.openssl_version_var.get(),
                'aes_algorithm': self.settings_tab.aes_algorithm_var.get(),  # Save AES algorithm
                'use_salt': self.settings_tab.use_salt_var.get(),  # Save salt setting
                'use_pbkdf2': self.settings_tab.use_pbkdf2_var.get(),  # Save PBKDF2 setting
                'theme': self.settings_tab.theme_var.get(),
                'telegram_token': self.settings_tab.telegram_token_var.get(),
                'telegram_chat_id': self.settings_tab.telegram_chat_id_var.get(),
                'logging_enabled': self.settings_tab.logging_enabled_var.get(),
                'disable_encryption_test': self.settings_tab.disable_encryption_test_var.get(),
                'delete_temp_files': self.settings_tab.delete_temp_files_var.get()
            }
            
            self.settings.update(current_settings)
            
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(current_settings, f, indent=2, ensure_ascii=False)
                
            self.update_all_components()
            
            logging.info("Настройки успешно сохранены")
            return True
            
        except Exception as e:
            logging.error(f"Ошибка сохранения настроек: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {str(e)}")
            return False

    def check_settings_permissions(self):
        """Проверка прав доступа к файлу настроек"""
        try:
            with open('settings.json', 'a'):
                pass
            return True
        except PermissionError:
            messagebox.showerror("Ошибка", "Нет прав на запись в файл настроек")
            return False
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка доступа к файлу: {str(e)}")
            return False

    def prompt_and_verify_master_password(self):
        """Запрос и проверка мастер-пароля при запуске (опционально)"""
        if os.path.exists('master_password.enc'):
            while True:
                password = simpledialog.askstring(
                    "Мастер-пароль", 
                    "Введите мастер-пароль (или оставьте пустым для пропуска):", 
                    show='*', 
                    parent=self.root
                )
                if password is None:
                    logging.info("Master password prompt canceled")
                    return None
                if not password:
                    logging.info("Master password skipped")
                    return None
                try:
                    stored_password = self.decrypt_master_password(password)
                    if stored_password == password:
                        logging.info("Master password verified successfully")
                        return password
                    else:
                        messagebox.showerror("Ошибка", "Неверный мастер-пароль. Попробуйте снова.")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка при проверке мастер-пароля: {str(e)}")
                    continue
        else:
            password = simpledialog.askstring(
                "Мастер-пароль", 
                "Мастер-пароль не найден. Введите новый мастер-пароль (или оставьте пустым для пропуска):", 
                show='*', 
                parent=self.root
            )
            if password is None:
                logging.info("Master password creation canceled")
                return None
            if not password:
                logging.info("Master password creation skipped")
                return None
            try:
                self.save_master_password(password)
                logging.info("New master password created and saved")
                return password
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить мастер-пароль: {str(e)}")
                return self.prompt_and_verify_master_password()
        
    def save_master_password(self, password):
        """Сохранение мастер-пароля в зашифрованном виде"""
        temp_dir = create_temp_directory()
        try:
            temp_file = os.path.join(temp_dir, 'master_password.txt')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(password)
                
            openssl_path = self.crypto_engine.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            encrypt_cmd = f'"{openssl_path}" {self.settings["aes_algorithm"]} -a'
            encrypt_cmd = self.crypto_engine.build_openssl_cmd(encrypt_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            encrypt_cmd += f' -in "{temp_file}" -out "master_password.enc" -pass pass:{password}'
            result = self.crypto_engine.run_command(encrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Master password encryption failed: {result.stderr}")
                
            logging.info("Master password saved successfully")
        except Exception as e:
            logging.error(f"Error saving master password: {e}")
            raise
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def decrypt_master_password(self, password):
        """Расшифровка мастер-пароля"""
        temp_dir = create_temp_directory()
        try:
            openssl_path = self.crypto_engine.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            temp_output = os.path.join(temp_dir, 'master_password_dec.txt')
            decrypt_cmd = f'"{openssl_path}" {self.settings["aes_algorithm"]} -a -d'
            decrypt_cmd = self.crypto_engine.build_openssl_cmd(decrypt_cmd, self.settings['use_salt'], self.settings['use_pbkdf2'])
            decrypt_cmd += f' -in "master_password.enc" -out "{temp_output}" -pass pass:{password}'
            result = self.crypto_engine.run_command(decrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"Master password decryption failed: {result.stderr}")
                
            with open(temp_output, 'r', encoding='utf-8') as f:
                decrypted_password = f.read().strip()
            return decrypted_password
        finally:
            if self.settings.get('delete_temp_files', True):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
    def set_master_password(self):
        """Установка мастер-пароля из настроек"""
        master_password = self.settings.get('master_password', '')
        if master_password:
            if hasattr(self.files_tab, 'set_master_password'):
                self.files_tab.set_master_password(master_password)
            if hasattr(self.password_tab, 'set_master_password'):
                self.password_tab.set_master_password(master_password)
            logging.info("Master password set from settings")
        
    def on_tab_changed(self, event):
        """Обработчик смены вкладки"""
        current_tab = self.notebook.select()
        tab_name = self.notebook.tab(current_tab, "text")
        logging.info(f"Switched to tab: {tab_name}")

    def handle_password_file(self, password_file):
        """Обработка файла паролей"""
        if os.path.exists(password_file):
            if self.crypto_engine.decrypt_file(password_file):
                messagebox.showinfo("Успех", f"Файл {password_file} успешно расшифрован")
                logging.info(f"File {password_file} decrypted successfully")
                self.notebook.select(self.password_tab)
            else:
                messagebox.showerror("Ошибка", f"Не удалось расшифровать {password_file}")
                logging.error(f"Failed to decrypt {password_file}")
        else:
            messagebox.showerror("Ошибка", f"Файл {password_file} не найден")
            logging.error(f"Password file {password_file} not found")

    def on_closing(self):
        """Обработчик закрытия приложения"""
        self.save_settings()
        if self.settings.get('master_password'):
            self.save_master_password(self.settings['master_password'])
        cleanup_all_temp_directories()
        self.root.destroy()

def create_temp_directory():
    """Create a unique temporary directory and return its path"""
    temp_dir = tempfile.mkdtemp(prefix="zipcrypt_")
    return temp_dir

def main():
    parser = argparse.ArgumentParser(description="ZipCrypt - Password Manager and Encryption Tool")
    parser.add_argument('-p', '--password-file', help="Path to password file to decrypt (e.g., pass.dll)")
    args = parser.parse_args()

    root = ttk.Window()
    app = ZipCryptApp(root, args.password_file)
    root.mainloop()

if __name__ == "__main__":
    main()