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

# Import custom modules
from settings import SettingsTab
from files_tab import FilesTab
from password_manager import PasswordManagerTab
from crypto_engines import CryptoEngine
from utils import setup_logging, cleanup_all_temp_directories, test_encryption_functionality

class ZipCryptApp:
    def __init__(self, root, password_file=None):
        self.root = root
        self.root.title("ZipCrypt - Крипто архиватор и менеджер паролей")
        self.root.geometry("900x400")
        
        # Инициализация настроек по умолчанию
        self.default_settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'openssl_version': '3.5.1',
            'theme': 'darkly',
            'telegram_token': '',
            'telegram_chat_id': '',
            'master_password': '',
            'logging_enabled': False,
            'disable_encryption_test': True
        }
        self.settings = self.default_settings.copy()
        
        # Загрузка настроек
        self.load_settings()
        
        # Настройка логирования
        self.configure_logging()
        
        # Инициализация crypto engine
        self.crypto_engine = CryptoEngine()
        self.crypto_engine.update_settings(self.settings)
        
        # Clean up old temporary directories
        cleanup_all_temp_directories()
        
        # Test encryption functionality on startup if not disabled
        if not self.settings.get('disable_encryption_test', False):
            if not test_encryption_functionality():
                messagebox.showwarning("Предупреждение", 
                    "Тест шифрования не прошел. Приложение может работать некорректно.")
                logging.error("Startup encryption test failed")
        
        # Prompt for master password
        if not self.prompt_master_password():
            self.root.destroy()
            return
        
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
        
        # Обновляем настройки во всех компонентах
        self.update_all_components()
        
        # Bind tab change event
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
        
        # Connect settings tab to crypto engine
        self.settings_tab.set_crypto_engine(self.crypto_engine)
        
        # Set master password if available
        self.set_master_password()
        
        # Handle password file decryption if specified
        if password_file:
            self.handle_password_file(password_file)
        
        # Apply theme after tabs are created
        self.settings_tab.apply_theme()
        
        # Обработчик закрытия окна
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
                    # Объединяем с настройками по умолчанию
                    self.settings = {**self.default_settings, **loaded_settings}
        except Exception as e:
            logging.error(f"Ошибка загрузки настроек: {e}")
            self.settings = self.default_settings.copy()

    def update_all_components(self):
        """Обновление всех компонентов приложения с текущими настройками"""
        # Обновляем настройки в движке
        self.crypto_engine.update_settings(self.settings)
        
        # Обновляем настройки в табах
        if hasattr(self, 'settings_tab'):
            self.settings_tab.update_settings(self.settings)
        if hasattr(self, 'files_tab'):
            self.files_tab.set_master_password(self.settings.get('master_password', ''))
        if hasattr(self, 'password_tab'):
            self.password_tab.set_master_password(self.settings.get('master_password', ''))

    def save_settings(self):
        """Сохранение настроек с проверкой"""
        try:
            # Проверяем доступ к файлу настроек
            if not self.check_settings_permissions():
                return False
                
            # Собираем актуальные настройки из всех компонентов
            current_settings = {
                'file_methods': self.settings_tab.file_methods_var.get(),
                'compression_method': self.settings_tab.compression_method_var.get(),
                '7zip_version': self.settings_tab.sevenzip_version_var.get(),
                'openssl_version': self.settings_tab.openssl_version_var.get(),
                'theme': self.settings_tab.theme_var.get(),
                'telegram_token': self.settings_tab.telegram_token_var.get(),
                'telegram_chat_id': self.settings_tab.telegram_chat_id_var.get(),
                'master_password': self.settings_tab.master_password_var.get(),
                'logging_enabled': self.settings_tab.logging_enabled_var.get(),
                'disable_encryption_test': self.settings_tab.disable_encryption_test_var.get()
            }
            
            # Обновляем внутренние настройки
            self.settings.update(current_settings)
            
            # Сохраняем в файл
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(current_settings, f, indent=2, ensure_ascii=False)
                
            # Обновляем все компоненты
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

    def prompt_master_password(self):
        """Запрос мастер-пароля при запуске"""
        stored_password = self.settings.get('master_password', '')
        if not stored_password:
            return True
            
        password = simpledialog.askstring(
            "Мастер-пароль", 
            "Введите мастер-пароль:", 
            show='*', 
            parent=self.root
        )
        
        if password != stored_password:
            messagebox.showerror("Ошибка", "Неверный мастер-пароль. Приложение будет закрыто.")
            return False
            
        return True
        
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
        cleanup_all_temp_directories()
        self.root.destroy()

def main():
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="ZipCrypt - Password Manager and Encryption Tool")
    parser.add_argument('-p', '--password-file', help="Path to password file to decrypt (e.g., pass.dll)")
    args = parser.parse_args()

    root = ttk.Window()
    app = ZipCryptApp(root, args.password_file)
    root.mainloop()

if __name__ == "__main__":
    main()