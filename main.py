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

# Import custom modules
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
        
        # Initialize default settings
        self.default_settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'openssl_version': '3.5.1',
            'theme': 'boosterxvapor',
            'telegram_token': '',
            'telegram_chat_id': '',
            'logging_enabled': False,
            'disable_encryption_test': True
        }
        self.settings = self.default_settings.copy()
        
        # Initialize master password manager
        self.master_password_manager = MasterPasswordManager()
        
        # Load settings
        self.load_settings()
        
        # Configure logging
        self.configure_logging()
        
        # Initialize crypto engine
        self.crypto_engine = CryptoEngine()
        self.crypto_engine.update_settings(self.settings)
        
        # Clean up old temporary directories
        cleanup_all_temp_directories()
        
        # Prompt for master password and verify
        if not self.verify_master_password():
            self.root.destroy()
            return
        
        # Test encryption functionality on startup if not disabled
        if not self.settings.get('disable_encryption_test', False):
            if not test_encryption_functionality():
                messagebox.showwarning("Предупреждение", 
                    "Тест шифрования не прошел. Приложение может работать некорректно.")
                logging.error("Startup encryption test failed")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs
        self.files_tab = FilesTab(self.notebook, self.crypto_engine)
        self.password_tab = PasswordManagerTab(self.notebook, self.crypto_engine)
        self.settings_tab = SettingsTab(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.files_tab, text="Файлы")
        self.notebook.add(self.password_tab, text="Пароли")
        self.notebook.add(self.settings_tab, text="Настройки")
        
        # Update all components
        self.update_all_components()
        
        # Bind tab change event
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
        
        # Connect settings tab to crypto engine and master password manager
        self.settings_tab.set_crypto_engine(self.crypto_engine)
        self.settings_tab.set_master_password_manager(self.master_password_manager)
        
        # Set master password if available
        self.set_master_password()
        
        # Handle password file decryption if specified
        if password_file:
            self.handle_password_file(password_file)
        
        # Apply theme after tabs are created
        self.settings_tab.apply_theme()
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def configure_logging(self):
        """Configure logging based on settings"""
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
        """Load settings with improved error handling"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    # Merge with default settings
                    self.settings = {**self.default_settings, **loaded_settings}
                logging.info("Settings loaded successfully from settings.json")
            else:
                logging.info("No settings.json found, using default settings")
        except Exception as e:
            logging.error(f"Error loading settings: {e}")
            self.settings = self.default_settings.copy()

    def update_all_components(self):
        """Update all application components with current settings"""
        self.crypto_engine.update_settings(self.settings)
        
        if hasattr(self, 'settings_tab'):
            self.settings_tab.update_settings(self.settings)
        if hasattr(self, 'files_tab'):
            self.files_tab.set_master_password(self.master_password_manager.get_stored_password() or '')
        if hasattr(self, 'password_tab'):
            self.password_tab.set_master_password(self.master_password_manager.get_stored_password() or '')

    def save_settings(self):
        """Save settings with validation"""
        try:
            if not self.check_settings_permissions():
                return False
                
            current_settings = {
                'file_methods': self.settings_tab.file_methods_var.get(),
                'compression_method': self.settings_tab.compression_method_var.get(),
                '7zip_version': self.settings_tab.sevenzip_version_var.get(),
                'openssl_version': self.settings_tab.openssl_version_var.get(),
                'theme': self.settings_tab.theme_var.get(),
                'telegram_token': self.settings_tab.telegram_token_var.get(),
                'telegram_chat_id': self.settings_tab.telegram_chat_id_var.get(),
                'logging_enabled': self.settings_tab.logging_enabled_var.get(),
                'disable_encryption_test': self.settings_tab.disable_encryption_test_var.get()
            }
            
            self.settings.update(current_settings)
            
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(current_settings, f, indent=2, ensure_ascii=False)
                
            # Save master password separately
            self.master_password_manager.set_stored_password(self.settings_tab.master_password_var.get())
            self.master_password_manager.encrypt_master_password()
            
            self.update_all_components()
            
            logging.info("Settings successfully saved")
            return True
            
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {str(e)}")
            return False

    def check_settings_permissions(self):
        """Check permissions for settings file"""
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

    def verify_master_password(self):
        """Verify master password at startup"""
        if not os.path.exists('master_password.enc'):
            return True  # No master password set
            
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