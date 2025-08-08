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
import argparse
from tkinter import simpledialog, messagebox

from settings import SettingsTab
from files_tab import FilesTab
from password_manager import PasswordManagerTab
from crypto_engines import CryptoEngine
from utils import setup_logging, cleanup_all_temp_directories, test_encryption_functionality
from master_password_manager import MasterPasswordManager

class ZipCryptApp:
    def __init__(self, root, password_file=None):
        self.root = root
        self.root.title("ZipCrypt - Крипто архиватор и менеджер паролей")
        self.root.geometry("1000x600")
        
        self.default_settings = {
            'file_methods': 'binary_openssl_7zip',  # Restored original default
            'compression_method': 'none',  # Restored original default
            '7zip_version': '24.08',
            'openssl_version': '3.5.1',
            'theme': 'litera',
            'telegram_token': '',
            'telegram_chat_id': '',
            'logging_enabled': False,
            'disable_encryption_test': True,
            'send_password_in_caption': False
        }
        self.settings = self.default_settings.copy()
        
        self.master_password_manager = MasterPasswordManager()
        
        self.load_settings()
        
        self.configure_logging()
        
        self.crypto_engine = CryptoEngine()
        self.crypto_engine.update_settings(self.settings)
        
        cleanup_all_temp_directories()
        
        if not self.verify_master_password():
            self.root.destroy()
            return
        
        if not self.settings.get('disable_encryption_test', False):
            if not test_encryption_functionality():
                messagebox.showwarning("Предупреждение", 
                    "Тест шифрования не прошел. Приложение может работать некорректно.")
                logging.error("Startup encryption test failed")
        
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
        self.settings_tab.set_master_password_manager(self.master_password_manager)
        
        self.set_master_password()
        
        if password_file:
            self.handle_password_file(password_file)
        
        self.settings_tab.apply_theme()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def configure_logging(self):
        """Configure logging based on settings"""
        if not self.settings.get('logging_enabled', True):
            logging.getLogger().setLevel(logging.CRITICAL)
        else:
            setup_logging()

    def load_settings(self):
        """Load settings from file"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    # Ensure new settings are included with defaults
                    for key, value in self.default_settings.items():
                        if key not in loaded_settings:
                            loaded_settings[key] = value
                    self.settings.update(loaded_settings)
                    logging.info("Settings loaded from settings.json")
            else:
                logging.info("No settings.json found, using defaults")
        except Exception as e:
            logging.error(f"Error loading settings: {e}")
            messagebox.showerror("Ошибка", f"Не удалось загрузить настройки: {str(e)}")

    def save_settings(self):
        """Save settings to file"""
        try:
            settings_file = 'settings.json'
            settings_dir = os.path.dirname(settings_file) or '.'
            if not os.access(settings_dir, os.W_OK):
                logging.error(f"No write permission for directory: {settings_dir}")
                raise PermissionError(f"No write permission for {settings_dir}")
                
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
                logging.info("Settings saved to settings.json")
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {str(e)}")

    def update_all_components(self):
        """Update all components with current settings"""
        self.settings_tab.update_settings(self.settings)
        self.crypto_engine.update_settings(self.settings)
        self.set_master_password()

    def verify_master_password(self):
        """Verify master password at startup"""
        if not os.path.exists('master_password.enc'):
            return True
            
        password = simpledialog.askstring(
            "Мастер-пароль", 
            "Введите мастер-пароль:", 
            show='*', 
            parent=self.root
        )
        
        if not password:
            messagebox.showerror("Ошибка", "Мастер-пароль обязателен для доступа")
            return False
            
        try:
            stored_password = self.master_password_manager.decrypt_master_password(password)
            if stored_password is None:
                messagebox.showerror("Ошибка", "Неверный мастер-пароль")
                return False
            self.master_password_manager.set_stored_password(stored_password)
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке мастер-пароля: {str(e)}")
            return False

    def set_master_password(self):
        """Set master password from stored value"""
        master_password = self.master_password_manager.get_stored_password() or ''
        if master_password:
            if hasattr(self.files_tab, 'set_master_password'):
                self.files_tab.set_master_password(master_password)
            if hasattr(self.password_tab, 'set_master_password'):
                self.password_tab.set_master_password(master_password)
            logging.info("Master password set from stored value")

    def on_tab_changed(self, event):
        """Handle tab change event"""
        current_tab = self.notebook.select()
        tab_name = self.notebook.tab(current_tab, "text")
        logging.info(f"Switched to tab: {tab_name}")

    def handle_password_file(self, password_file):
        """Handle password file decryption"""
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
        """Handle application closing"""
        self.save_settings()
        cleanup_all_temp_directories()
        self.root.destroy()

def main():
    parser = argparse.ArgumentParser(description="ZipCrypt - Password Manager and Encryption Tool")
    parser.add_argument('-p', '--password-file', help="Path to password file to decrypt (e.g., pass.dll)")
    args = parser.parse_args()

    root = ttk.Window()
    app = ZipCryptApp(root, args.password_file)
    root.mainloop()

if __name__ == "__main__":
    main()