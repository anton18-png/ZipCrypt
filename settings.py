import ttkbootstrap as ttk
from ttkbootstrap import Style
from tkinter import messagebox
import os
import json
import logging
import re
import tempfile
import shutil
from master_password_manager import MasterPasswordManager
from utils import get_openssl_ciphers

class SettingsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.root = parent.winfo_toplevel()
        self.crypto_engine = None
        self.master_password_manager = None
        self.ciphers = get_openssl_ciphers()  # Fetch available ciphers
        self.settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'zstd_version': '1.5.7',
            'openssl_version': '3.5.1',
            'cipher_algorithm': 'aes-256-cbc',
            'use_salt': True,
            'use_pbkdf2': True,
            'use_pbkdf2_iterations': True,
            'pbkdf2_iterations': 200000,
            'theme': 'litera',
            'telegram_token': '',
            'telegram_chat_id': '',
            'show_passwords': False,
            'logging_enabled': False,
            'disable_encryption_test': False,
            'send_password_in_caption': False,
            'delete_temp_files': True
        }
        self.setup_ui()
        self.apply_theme()
        self.configure_logging()

    def set_crypto_engine(self, crypto_engine):
        """Set the crypto engine reference"""
        self.crypto_engine = crypto_engine

    def set_master_password_manager(self, master_password_manager):
        """Set the master password manager reference"""
        self.master_password_manager = master_password_manager
        if self.master_password_manager:
            self.master_password_var.set(self.master_password_manager.get_stored_password() or '')

    def setup_ui(self):
        """Setup the user interface with three columns"""
        main_frame = ttk.Frame(self)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        canvas = ttk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        column_frame = ttk.Frame(scrollable_frame)
        column_frame.grid(row=0, column=0, sticky="nsew")

        # Column 1
        col1 = ttk.Frame(column_frame)
        col1.grid(row=0, column=0, padx=5, pady=5, sticky="ns")
        self.create_encryption_section(col1)
        self.create_compression_section(col1)

        # Column 2
        col2 = ttk.Frame(column_frame)
        col2.grid(row=0, column=1, padx=5, pady=5, sticky="ns")
        self.create_version_section(col2)
        self.create_theme_section(col2)

        # Column 3
        col3 = ttk.Frame(column_frame)
        col3.grid(row=0, column=2, padx=5, pady=5, sticky="ns")
        self.create_telegram_section(col3)
        self.create_master_password_section(col3)
        self.create_logging_section(col3)
        self.create_advanced_section(col3)
        self.create_buttons(col3)

        column_frame.columnconfigure(0, weight=1)
        column_frame.columnconfigure(1, weight=1)
        column_frame.columnconfigure(2, weight=1)

    def create_encryption_section(self, parent):
        """Create encryption method selection section"""
        section_frame = ttk.Labelframe(parent, text="Метод шифрования", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.file_methods_var = ttk.StringVar(value=self.settings['file_methods'])
        methods = [
            ('binary_openssl_7zip', 'Двоичный код -> OpenSSL -> 7zip (по умолчанию)'),
            ('openssl_only', 'Только OpenSSL'),
            ('openssl_7zip', 'OpenSSL -> 7zip')
        ]
        for value, text in methods:
            ttk.Radiobutton(section_frame, text=text, variable=self.file_methods_var, value=value).pack(anchor='w', pady=2)
        
        ttk.Label(section_frame, text="Алгоритм шифрования:").pack(anchor='w', pady=2)
        self.cipher_algorithm_var = ttk.StringVar(value=self.settings['cipher_algorithm'])

        # # 🔒 Только те AES-алгоритмы, которые точно есть в текущей сборке OpenSSL
        # available_aes_algorithms = [
        #     'aes-128-cbc',
        #     'aes-192-cbc',
        #     'aes-256-cbc',
        #     'aes-128-ecb',
        #     'aes-192-ecb',
        #     'aes-256-ecb'
        # ]
        # available_aes_algorithms = ['aes-256-cbc']  # один безопасный режим по умолчанию
        available_aes_algorithms = [
            'aes-128-cbc',
            'aes-192-cbc',
            'aes-256-cbc'
        ]

        # Фильтруем: оставляем только те, что есть и в self.ciphers (на случай, если пользователь подменил)
        filtered_aes_algorithms = [algo for algo in available_aes_algorithms if algo in self.ciphers]

        # Если ни один AES не найден — используем fallback
        if not filtered_aes_algorithms:
            filtered_aes_algorithms = ['aes-256-cbc']  # аварийный вариант

        # Если текущий алгоритм из настроек не в списке — выбираем дефолтный
        if self.settings['cipher_algorithm'] not in filtered_aes_algorithms:
            default_algo = 'aes-256-cbc'
            if default_algo in filtered_aes_algorithms:
                self.cipher_algorithm_var.set(default_algo)
            elif filtered_aes_algorithms:
                self.cipher_algorithm_var.set(filtered_aes_algorithms[0])
            else:
                self.cipher_algorithm_var.set('')

        # Создаём Combobox
        ttk.Combobox(section_frame, textvariable=self.cipher_algorithm_var, 
                    values=filtered_aes_algorithms).pack(fill='x', pady=2)
        
        self.use_salt_var = ttk.BooleanVar(value=self.settings['use_salt'])
        ttk.Checkbutton(section_frame, text="Использовать соль", 
                        variable=self.use_salt_var).pack(anchor='w', pady=2)
        
        self.use_pbkdf2_var = ttk.BooleanVar(value=self.settings['use_pbkdf2'])
        ttk.Checkbutton(section_frame, text="Использовать PBKDF2", 
                        variable=self.use_pbkdf2_var).pack(anchor='w', pady=2)
        
        self.use_pbkdf2_iterations_var = ttk.BooleanVar(value=self.settings['use_pbkdf2_iterations'])
        ttk.Checkbutton(section_frame, text="Использовать PBKDF2 итерации", 
                        variable=self.use_pbkdf2_iterations_var).pack(anchor='w', pady=2)
        
        ttk.Label(section_frame, text="PBKDF2 итерации:").pack(anchor='w', pady=2)
        self.pbkdf2_iterations_var = ttk.StringVar(value=str(self.settings['pbkdf2_iterations']))
        ttk.Entry(section_frame, textvariable=self.pbkdf2_iterations_var).pack(fill='x', pady=2)

    def create_compression_section(self, parent):
        """Create compression settings section"""
        section_frame = ttk.Labelframe(parent, text="Настройки сжатия", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.compression_method_var = ttk.StringVar(value=self.settings['compression_method'])
        ttk.Label(section_frame, text="Степень сжатия:").pack(anchor='w')
        compression_methods = [
            ('none', 'Без сжатия'),
            ('fast', 'Быстрое сжатие'),
            ('medium', 'Среднее сжатие'),
            ('normal', 'Обычное сжатие'),
            ('high', 'Высокое сжатие'),
            ('ultra', 'Максимальное сжатие'),
            ('custom', 'Пользовательское сжатие')
        ]
        for value, text in compression_methods:
            ttk.Radiobutton(section_frame, text=text, variable=self.compression_method_var, value=value).pack(anchor='w', pady=2)

    def create_version_section(self, parent):
        """Create version selection section"""
        section_frame = ttk.Labelframe(parent, text="Версии программ", padding=10)
        section_frame.pack(fill='x', pady=5)
        
        ttk.Label(section_frame, text="7zip версия:").pack(anchor='w')
        self.sevenzip_version_var = ttk.StringVar(value=self.settings['7zip_version'])
        ttk.Combobox(section_frame, textvariable=self.sevenzip_version_var, 
                     values=['24.08', '920', '2501_extra', '24.09_zstandard']).pack(fill='x', pady=2)
        
        ttk.Label(section_frame, text="Zstandard версия:").pack(anchor='w')
        self.zstd_version_var = ttk.StringVar(value=self.settings['zstd_version'])
        ttk.Combobox(section_frame, textvariable=self.zstd_version_var, 
                     values=['1.5.7']).pack(fill='x', pady=2)
        
        ttk.Label(section_frame, text="OpenSSL версия:").pack(anchor='w')
        self.openssl_version_var = ttk.StringVar(value=self.settings['openssl_version'])
        ttk.Combobox(section_frame, textvariable=self.openssl_version_var, 
                     values=['3.5.1', '3.5.1_Light', '3.2.4', '4.1.0_LibreSSL']).pack(fill='x', pady=2)

    def create_theme_section(self, parent):
        """Create theme selection section"""
        section_frame = ttk.Labelframe(parent, text="Тема интерфейса", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.theme_var = ttk.StringVar(value=self.settings['theme'])
        themes = sorted(self.root.style.theme_names())
        ttk.Combobox(section_frame, textvariable=self.theme_var, values=themes).pack(fill='x')

    def create_telegram_section(self, parent):
        """Create Telegram HRU"""
        section_frame = ttk.Labelframe(parent, text="Настройки Telegram", padding=10)
        section_frame.pack(fill='x', pady=5)
        ttk.Label(section_frame, text="Токен:").pack(anchor='w')
        self.telegram_token_var = ttk.StringVar(value=self.settings['telegram_token'])
        ttk.Entry(section_frame, textvariable=self.telegram_token_var, width=40).pack(fill='x', pady=2)
        ttk.Label(section_frame, text="Chat ID:").pack(anchor='w')
        self.telegram_chat_id_var = ttk.StringVar(value=self.settings['telegram_chat_id'])
        ttk.Entry(section_frame, textvariable=self.telegram_chat_id_var, width=40).pack(fill='x', pady=2)
        self.send_password_in_caption_var = ttk.BooleanVar(value=self.settings['send_password_in_caption'])
        ttk.Checkbutton(section_frame, text="Отправлять пароль в подписи Telegram", 
                        variable=self.send_password_in_caption_var).pack(anchor='w', pady=5)
        ttk.Button(section_frame, text="Тестировать подключение", command=self.test_telegram_connection, 
                   bootstyle="info-outline").pack(anchor='w', pady=5)

    def create_master_password_section(self, parent):
        """Create master password section"""
        section_frame = ttk.Labelframe(parent, text="Мастер-пароль", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.master_password_var = ttk.StringVar()
        ttk.Label(section_frame, text="Новый мастер-пароль:").pack(anchor='w')
        ttk.Entry(section_frame, textvariable=self.master_password_var, show='*').pack(fill='x', pady=2)

    def create_logging_section(self, parent):
        """Create logging settings section"""
        section_frame = ttk.Labelframe(parent, text="Логирование", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.logging_enabled_var = ttk.BooleanVar(value=self.settings['logging_enabled'])
        ttk.Checkbutton(section_frame, text="Включить логирование", 
                        variable=self.logging_enabled_var, command=self.toggle_logging).pack(anchor='w')
        self.disable_encryption_test_var = ttk.BooleanVar(value=self.settings['disable_encryption_test'])
        ttk.Checkbutton(section_frame, text="Отключить тест шифрования при запуске", 
                        variable=self.disable_encryption_test_var).pack(anchor='w')
        self.delete_temp_files_var = ttk.BooleanVar(value=self.settings['delete_temp_files'])
        ttk.Checkbutton(section_frame, text="Удалять временные файлы", 
                        variable=self.delete_temp_files_var).pack(anchor='w')

    def create_advanced_section(self, parent):
        """Create advanced settings section"""
        section_frame = ttk.Labelframe(parent, text="Дополнительно", padding=10)
        section_frame.pack(fill='x', pady=5)
        ttk.Button(section_frame, text="Проверить пути", command=self.check_paths, 
                   bootstyle="secondary-outline").pack(anchor='w', pady=2)

    def create_buttons(self, parent):
        """Create save and reset buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', pady=10)
        ttk.Button(button_frame, text="Сохранить", command=self.save_settings, 
                   bootstyle="primary-outline").pack(side='left', padx=5)
        ttk.Button(button_frame, text="Сбросить", command=self.reset_settings, 
                   bootstyle="secondary-outline").pack(side='left', padx=5)

    def apply_theme(self):
        """Apply selected theme"""
        try:
            theme = self.settings['theme']
            self.root.style.theme_use(theme)
            logging.info(f"Applied theme: {theme}")
        except Exception as e:
            logging.error(f"Error applying theme: {e}")
            messagebox.showerror("Ошибка", f"Не удалось применить тему: {str(e)}")

    def configure_logging(self):
        """Configure logging based on settings"""
        if self.settings['logging_enabled']:
            logging.getLogger().setLevel(logging.INFO)
        else:
            logging.getLogger().setLevel(logging.CRITICAL)

    def save_settings(self):
        """Save settings to file"""
        try:
            settings_file = 'settings.json'
            settings_dir = os.path.dirname(settings_file) or '.'
            logging.debug(f"Checking write permissions for {settings_dir}")
            
            if not os.access(settings_dir, os.W_OK):
                logging.error(f"No write permission for directory: {settings_dir}")
                messagebox.showerror("Ошибка", f"Нет прав на запись в директорию: {settings_dir}")
                return False

            token = self.telegram_token_var.get()
            if token and not re.match(r'^\d+:[A-Za-z0-9_-]+$', token):
                messagebox.showerror("Ошибка", "Неверный формат токена Telegram. Пример: 123456:ABC-DEF...")
                logging.error("Invalid Telegram token format")
                return False

            # Validate PBKDF2 iterations if enabled
            if self.use_pbkdf2_iterations_var.get():
                try:
                    iterations = int(self.pbkdf2_iterations_var.get())
                    if iterations <= 0:
                        raise ValueError("PBKDF2 iterations must be a positive integer")
                except ValueError:
                    messagebox.showerror("Ошибка", "PBKDF2 итерации должны быть положительным целым числом")
                    logging.error("Invalid PBKDF2 iterations value")
                    return False
            else:
                iterations = 200000  # Default value when iterations are disabled

            new_settings = {
                'file_methods': self.file_methods_var.get(),
                'compression_method': self.compression_method_var.get(),
                '7zip_version': self.sevenzip_version_var.get(),
                'zstd_version': self.zstd_version_var.get(),
                'openssl_version': self.openssl_version_var.get(),
                'cipher_algorithm': self.cipher_algorithm_var.get(),
                'use_salt': self.use_salt_var.get(),
                'use_pbkdf2': self.use_pbkdf2_var.get(),
                'use_pbkdf2_iterations': self.use_pbkdf2_iterations_var.get(),
                'pbkdf2_iterations': iterations,
                'theme': self.theme_var.get(),
                'telegram_token': self.telegram_token_var.get(),
                'telegram_chat_id': self.telegram_chat_id_var.get(),
                'logging_enabled': self.logging_enabled_var.get(),
                'disable_encryption_test': self.disable_encryption_test_var.get(),
                'send_password_in_caption': self.send_password_in_caption_var.get(),
                'delete_temp_files': self.delete_temp_files_var.get()
            }
            
            try:
                with open(settings_file, 'w', encoding='utf-8') as f:
                    json.dump(new_settings, f, indent=4, ensure_ascii=False)
                    logging.info(f"Settings saved to {settings_file}")
            except PermissionError:
                temp_fd, temp_path = tempfile.mkstemp(suffix='.json', prefix='settings_')
                try:
                    with os.fdopen(temp_fd, 'w', encoding='utf-8') as temp_f:
                        json.dump(new_settings, temp_f, indent=4, ensure_ascii=False)
                    shutil.move(temp_path, settings_file)
                    logging.info(f"Settings saved via temp file to {settings_file}")
                except Exception as e:
                    logging.error(f"Failed to save settings via temp file: {e}")
                    os.remove(temp_path) if os.path.exists(temp_path) else None
                    raise
                
            self.settings.update(new_settings)
            
            if self.crypto_engine:
                self.crypto_engine.update_settings(self.settings)
                
            if self.master_password_manager:
                self.master_password_manager.set_stored_password(self.master_password_var.get())
                self.master_password_manager.encrypt_master_password()
                
            self.apply_theme()
            self.configure_logging()
            
            messagebox.showinfo("Успех", "Настройки успешно сохранены")
            return True
            
        except Exception as e:
            logging.error(f"Error saving settings: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить настройки: {str(e)}")
            return False

    def reset_settings(self):
        """Reset settings to default"""
        self.settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'zstd_version': '1.5.7',
            'openssl_version': '3.5.1',
            'cipher_algorithm': 'aes-256-cbc',
            'use_salt': True,
            'use_pbkdf2': True,
            'use_pbkdf2_iterations': True,
            'pbkdf2_iterations': 200000,
            'theme': 'litera',
            'telegram_token': '',
            'telegram_chat_id': '',
            'show_passwords': False,
            'logging_enabled': False,
            'disable_encryption_test': False,
            'send_password_in_caption': False,
            'delete_temp_files': True
        }
        self.file_methods_var.set(self.settings['file_methods'])
        self.compression_method_var.set(self.settings['compression_method'])
        self.sevenzip_version_var.set(self.settings['7zip_version'])
        self.zstd_version_var.set(self.settings['zstd_version'])
        self.openssl_version_var.set(self.settings['openssl_version'])
        self.cipher_algorithm_var.set(self.settings['cipher_algorithm'])
        self.use_salt_var.set(self.settings['use_salt'])
        self.use_pbkdf2_var.set(self.settings['use_pbkdf2'])
        self.use_pbkdf2_iterations_var.set(self.settings['use_pbkdf2_iterations'])
        self.pbkdf2_iterations_var.set(str(self.settings['pbkdf2_iterations']))
        self.theme_var.set(self.settings['theme'])
        self.telegram_token_var.set(self.settings['telegram_token'])
        self.telegram_chat_id_var.set(self.settings['telegram_chat_id'])
        self.logging_enabled_var.set(self.settings['logging_enabled'])
        self.disable_encryption_test_var.set(self.settings['disable_encryption_test'])
        self.send_password_in_caption_var.set(self.settings['send_password_in_caption'])
        self.delete_temp_files_var.set(self.settings['delete_temp_files'])
        if self.crypto_engine:
            self.crypto_engine.update_settings(self.settings)
        if self.master_password_manager:
            self.master_password_manager.set_stored_password('')
            self.master_password_manager.encrypt_master_password()
        self.apply_theme()
        self.configure_logging()
        messagebox.showinfo("Успех", "Настройки сброшены к значениям по умолчанию")

    def check_paths(self):
        """Check if required executables are available"""
        try:
            results = []
            
            if not os.path.exists('7zip'):
                results.append("✗ Папка '7zip' не найдена")
            else:
                sevenzip_versions = self.get_available_7zip_versions()
                for version in sevenzip_versions:
                    path = os.path.join('7zip', f'7zip_{version}', '7za.exe')
                    if os.path.exists(path):
                        results.append(f"✓ 7zip {version}: {path}")
                    else:
                        results.append(f"✗ 7zip {version}: не найден")
            
            if not os.path.exists('zstd'):
                results.append("✗ Папка 'zstd' не найдена")
            else:
                zstd_versions = self.get_available_zstd_versions()
                for version in zstd_versions:
                    path = os.path.join('zstd', f'zstd_{version}', 'zstd.exe')
                    if os.path.exists(path):
                        results.append(f"✓ Zstandard {version}: {path}")
                    else:
                        results.append(f"✗ Zstandard {version}: не найден")
            
            if not os.path.exists('OpenSSL'):
                results.append("✗ Папка 'OpenSSL' не найдена")
            else:
                openssl_versions = self.get_available_openssl_versions()
                for version in openssl_versions:
                    path = os.path.join('OpenSSL', f'OpenSSL_{version}', 'openssl.exe')
                    if os.path.exists(path):
                        results.append(f"✓ OpenSSL {version}: {path}")
                    else:
                        results.append(f"✗ OpenSSL {version}: не найден")
            
            result_text = "\n".join(results)
            messagebox.showinfo("Проверка путей", f"Результаты проверки:\n\n{result_text}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке путей: {e}")
            logging.error(f"Path check error: {e}")

    def get_available_7zip_versions(self):
        """Get available 7zip versions"""
        return ['24.08', '920', '2501_extra', '24.09_zstandard']

    def get_available_zstd_versions(self):
        """Get available Zstandard versions"""
        return ['1.5.7']

    def get_available_openssl_versions(self):
        """Get available OpenSSL versions"""
        return ['3.5.1', '3.5.1_Light', '3.2.4']

    def test_telegram_connection(self):
        """Test Telegram connection"""
        from telegram_utils import TelegramUtils
        telegram_token = self.telegram_token_var.get()
        telegram_chat_id = self.telegram_chat_id_var.get()
        if not telegram_token or not telegram_chat_id:
            messagebox.showerror("Ошибка", "Укажите токен и Chat ID")
            return
        telegram_utils = TelegramUtils(telegram_token, telegram_chat_id)
        success, message = telegram_utils.test_connection()
        if success:
            messagebox.showinfo("Успех", "Подключение к Telegram успешно")
        else:
            messagebox.showerror("Ошибка", f"Ошибка подключения: {message}\nПроверьте токен у @BotFather и Chat ID у @GetIDsBot.")

    def get_settings(self):
        """Get current settings"""
        return self.settings.copy()

    def update_settings(self, settings):
        """Update settings from external source"""
        self.settings.update(settings)
        if hasattr(self, 'file_methods_var'):
            self.file_methods_var.set(self.settings.get('file_methods', 'binary_openssl_7zip'))
            self.compression_method_var.set(self.settings.get('compression_method', 'none'))
            self.sevenzip_version_var.set(self.settings.get('7zip_version', '24.08'))
            self.zstd_version_var.set(self.settings.get('zstd_version', '1.5.7'))
            self.openssl_version_var.set(self.settings.get('openssl_version', '3.5.1'))
            self.cipher_algorithm_var.set(self.settings.get('cipher_algorithm', 'aes-256-cbc'))
            self.use_salt_var.set(self.settings.get('use_salt', True))
            self.use_pbkdf2_var.set(self.settings.get('use_pbkdf2', True))
            self.use_pbkdf2_iterations_var.set(self.settings.get('use_pbkdf2_iterations', True))
            self.pbkdf2_iterations_var.set(str(self.settings.get('pbkdf2_iterations', 200000)))
            self.theme_var.set(self.settings.get('theme', 'litera'))
            self.telegram_token_var.set(self.settings.get('telegram_token', ''))
            self.telegram_chat_id_var.set(self.settings.get('telegram_chat_id', ''))
            self.logging_enabled_var.set(self.settings.get('logging_enabled', False))
            self.disable_encryption_test_var.set(self.settings.get('disable_encryption_test', False))
            self.send_password_in_caption_var.set(self.settings.get('send_password_in_caption', False))
            self.delete_temp_files_var.set(self.settings.get('delete_temp_files', True))
            self.apply_theme()
            self.configure_logging()

    def toggle_logging(self):
        """Toggle logging state and reconfigure"""
        self.settings['logging_enabled'] = self.logging_enabled_var.get()
        self.configure_logging()