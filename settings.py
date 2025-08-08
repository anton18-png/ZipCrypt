import ttkbootstrap as ttk
from ttkbootstrap import Style
from tkinter import messagebox, filedialog
import os
import json
import logging
import re
from master_password_manager import MasterPasswordManager

class SettingsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.root = parent.winfo_toplevel()
        self.crypto_engine = None
        self.master_password_manager = None
        self.settings = {
            'file_methods': 'binary_openssl_7zip',
            'compression_method': 'none',
            '7zip_version': '24.08',
            'openssl_version': '3.5.1',
            'theme': 'boosterxvapor',
            'telegram_token': '',
            'telegram_chat_id': '',
            'show_passwords': False,
            'logging_enabled': False,
            'disable_encryption_test': False
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
        # Initialize master password field with stored password if available
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
        ttk.Label(section_frame, text="Версия 7zip:").pack(anchor='w')
        self.sevenzip_version_var = ttk.StringVar(value=self.settings['7zip_version'])
        sevenzip_versions = self.get_available_7zip_versions()
        sevenzip_combo = ttk.Combobox(section_frame, textvariable=self.sevenzip_version_var, values=sevenzip_versions, state='readonly')
        sevenzip_combo.pack(fill='x', pady=2)
        ttk.Label(section_frame, text="Версия OpenSSL:").pack(anchor='w')
        self.openssl_version_var = ttk.StringVar(value=self.settings['openssl_version'])
        openssl_versions = self.get_available_openssl_versions()
        openssl_combo = ttk.Combobox(section_frame, textvariable=self.openssl_version_var, values=openssl_versions, state='readonly')
        openssl_combo.pack(fill='x', pady=2)

    def create_theme_section(self, parent):
        """Create theme selection section"""
        section_frame = ttk.Labelframe(parent, text="Тема интерфейса", padding=10)
        section_frame.pack(fill='x', pady=5)
        
        themes = sorted(self.root.style.theme_names())
        
        self.theme_var = ttk.StringVar(value=self.settings['theme'])
        ttk.Label(section_frame, text="Выберите тему:").pack(anchor='w')
        
        theme_combo = ttk.Combobox(
            section_frame, 
            textvariable=self.theme_var, 
            values=themes,
            state='readonly'
        )
        theme_combo.pack(fill='x', pady=2)
        theme_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_theme())

    def configure_logging(self):
        """Configure logging based on settings"""
        logger = logging.getLogger()
        
        if not self.settings['logging_enabled']:
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
            logger.setLevel(logging.CRITICAL + 1)
        else:
            if not logger.handlers:
                logging.basicConfig(
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('zipcrypt.log', encoding='utf-8'),
                        logging.StreamHandler()
                    ]
                )
            else:
                logger.setLevel(logging.INFO)

    def create_advanced_section(self, parent):
        """Create advanced settings section"""
        section_frame = ttk.Labelframe(parent, text="Дополнительно", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.disable_encryption_test_var = ttk.BooleanVar(value=self.settings['disable_encryption_test'])
        ttk.Checkbutton(section_frame, text="Отключить проверку шифрования при запуске", variable=self.disable_encryption_test_var).pack(anchor='w', pady=2)

    def apply_theme(self):
        """Apply selected theme to all tabs and root"""
        theme = self.theme_var.get()
        self.root.style.theme_use(theme)
        for widget in self.root.winfo_children():
            self._apply_theme_to_widget(widget)
        self.root.update_idletasks()

    def _apply_theme_to_widget(self, widget):
        """Apply theme to widget and its children"""
        try:
            widget_type = widget.winfo_class()
            if widget_type in ['TFrame', 'Frame', 'Labelframe']:
                widget.configure(style='TFrame')
            elif widget_type in ['TLabel', 'Label']:
                widget.configure(style='TLabel')
            elif widget_type in ['TButton', 'Button']:
                widget.configure(style='TButton')
            elif widget_type in ['TEntry', 'Entry']:
                widget.configure(style='TEntry')
            elif widget_type in ['TCheckbutton', 'Checkbutton']:
                widget.configure(style='TCheckbutton')
            elif widget_type in ['TRadiobutton', 'Radiobutton']:
                widget.configure(style='TRadiobutton')
            elif widget_type in ['TNotebook', 'Notebook']:
                widget.configure(style='TNotebook')
            elif widget_type in ['Treeview']:
                widget.configure(style='Treeview')
            elif widget_type in ['TCombobox', 'Combobox']:
                widget.configure(style='TCombobox')
            widget.update_idletasks()
        except Exception:
            pass
        for child in widget.winfo_children():
            self._apply_theme_to_widget(child)

    def create_telegram_section(self, parent):
        """Create Telegram settings section"""
        section_frame = ttk.Labelframe(parent, text="Настройки Telegram", padding=10)
        section_frame.pack(fill='x', pady=5)
        ttk.Label(section_frame, text="Токен Telegram:").pack(anchor='w')
        self.telegram_token_var = ttk.StringVar(value=self.settings['telegram_token'])
        telegram_token_entry = ttk.Entry(section_frame, textvariable=self.telegram_token_var, show='*', width=50)
        telegram_token_entry.pack(fill='x', pady=2)
        ttk.Label(section_frame, text="Chat ID:").pack(anchor='w')
        self.telegram_chat_id_var = ttk.StringVar(value=self.settings['telegram_chat_id'])
        chat_id_entry = ttk.Entry(section_frame, textvariable=self.telegram_chat_id_var, width=50)
        chat_id_entry.pack(fill='x', pady=2)
        instructions_text = """Инструкции по настройке Telegram:
1. Создайте бота через @BotFather: отправьте /newbot, следуйте инструкциям, скопируйте токен
2. Получите Chat ID: отправьте сообщение боту, перейдите по https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates, найдите "chat":{"id": число}, скопируйте в поле Chat ID"""
        ttk.Label(section_frame, text=instructions_text, wraplength=500).pack(anchor='w', pady=5)

    def create_master_password_section(self, parent):
        """Create master password section"""
        section_frame = ttk.Labelframe(parent, text="Мастер-пароль", padding=10)
        section_frame.pack(fill='x', pady=5)
        ttk.Label(section_frame, text="Мастер-пароль:").pack(anchor='w')
        self.master_password_var = ttk.StringVar(value='')
        master_password_entry = ttk.Entry(section_frame, textvariable=self.master_password_var, show='*', width=50)
        master_password_entry.pack(fill='x', pady=2)

    def create_logging_section(self, parent):
        """Create logging control section"""
        section_frame = ttk.Labelframe(parent, text="Логирование", padding=10)
        section_frame.pack(fill='x', pady=5)
        self.logging_enabled_var = ttk.BooleanVar(value=self.settings['logging_enabled'])
        ttk.Checkbutton(section_frame, text="Включить логирование", variable=self.logging_enabled_var, command=self.toggle_logging).pack(anchor='w', pady=2)

    def create_buttons(self, parent):
        """Create action buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', pady=10)
        ttk.Button(button_frame, text="Сохранить настройки", command=self.save_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Сбросить к умолчаниям", command=self.reset_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Проверить пути", command=self.check_paths).pack(side='left', padx=5)

    def get_available_7zip_versions(self):
        """Get available 7zip versions"""
        return ['24.08', '9.20', '25.01_extra']

    def get_available_openssl_versions(self):
        """Get available OpenSSL versions"""
        versions = []
        if os.path.exists('OpenSSL'):
            for item in os.listdir('OpenSSL'):
                if item.startswith('OpenSSL_'):
                    version = item.replace('OpenSSL_', '')
                    versions.append(version)
        return versions if versions else ['3.5.1', '3.5.1_Light', '3.2.4']

    def save_settings(self):
        """Save current settings"""
        try:
            self.settings.update({
                'file_methods': self.file_methods_var.get(),
                'compression_method': self.compression_method_var.get(),
                '7zip_version': self.sevenzip_version_var.get(),
                'openssl_version': self.openssl_version_var.get(),
                'theme': self.theme_var.get(),
                'telegram_token': self.telegram_token_var.get(),
                'telegram_chat_id': self.telegram_chat_id_var.get(),
                'logging_enabled': self.logging_enabled_var.get(),
                'disable_encryption_test': self.disable_encryption_test_var.get()
            })
            if self.crypto_engine:
                self.crypto_engine.update_settings(self.settings)
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
            if self.master_password_manager:
                self.master_password_manager.set_stored_password(self.master_password_var.get())
                self.master_password_manager.encrypt_master_password()
            messagebox.showinfo("Успех", "Настройки сохранены")
            self.configure_logging()
            log_settings = self.settings.copy()
            log_settings['telegram_token'] = '****' if log_settings['telegram_token'] else ''
            if self.settings['logging_enabled']:
                logging.info(f"Settings saved successfully: {log_settings}")
            self.apply_theme()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при сохранении настроек: {e}")
            if self.settings['logging_enabled']:
                logging.error(f"Error saving settings: {e}")

    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Подтверждение", "Сбросить все настройки к значениям по умолчанию?"):
            self.settings = {
                'file_methods': 'binary_openssl_7zip',
                'compression_method': 'normal',
                '7zip_version': '24.08',
                'openssl_version': '3.5.1',
                'theme': 'darkly',
                'telegram_token': '',
                'telegram_chat_id': '',
                'show_passwords': False,
                'logging_enabled': True,
                'disable_encryption_test': False
            }
            self.file_methods_var.set(self.settings['file_methods'])
            self.compression_method_var.set(self.settings['compression_method'])
            self.sevenzip_version_var.set(self.settings['7zip_version'])
            self.openssl_version_var.set(self.settings['openssl_version'])
            self.theme_var.set(self.settings['theme'])
            self.telegram_token_var.set(self.settings['telegram_token'])
            self.telegram_chat_id_var.set(self.settings['telegram_chat_id'])
            self.master_password_var.set('')
            self.logging_enabled_var.set(self.settings['logging_enabled'])
            self.disable_encryption_test_var.set(self.settings['disable_encryption_test'])
            if self.crypto_engine:
                self.crypto_engine.update_settings(self.settings)
            if self.master_password_manager:
                self.master_password_manager.set_stored_password('')
                self.master_password_manager.encrypt_master_password()
            self.apply_theme()
            self.configure_logging()
            if self.settings['logging_enabled']:
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

    def get_settings(self):
        """Get current settings"""
        return self.settings.copy()

    def update_settings(self, settings):
        """Update settings from external source"""
        self.settings.update(settings)
        if hasattr(self, 'file_methods_var'):
            self.file_methods_var.set(self.settings.get('file_methods', 'binary_openssl_7zip'))
            self.compression_method_var.set(self.settings.get('compression_method', 'normal'))
            self.sevenzip_version_var.set(self.settings.get('7zip_version', '24.08'))
            self.openssl_version_var.set(self.settings.get('openssl_version', '3.5.1'))
            self.theme_var.set(self.settings.get('theme', 'darkly'))
            self.telegram_token_var.set(self.settings.get('telegram_token', ''))
            self.telegram_chat_id_var.set(self.settings.get('telegram_chat_id', ''))
            self.logging_enabled_var.set(self.settings.get('logging_enabled', True))
            self.disable_encryption_test_var.set(self.settings.get('disable_encryption_test', False))
            self.apply_theme()
            self.configure_logging()

    def toggle_logging(self):
        """Toggle logging state and reconfigure"""
        self.settings['logging_enabled'] = self.logging_enabled_var.get()
        self.configure_logging()