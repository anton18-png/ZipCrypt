import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import json
import logging
import os
import tempfile
import shutil
import csv
import threading
from datetime import datetime
from utils import create_temp_directory

class PasswordManagerTab(tk.Frame):
    def __init__(self, parent, crypto_engine):
        super().__init__(parent)
        self.crypto_engine = crypto_engine
        self.db_path = tk.StringVar()
        self.master_password = tk.StringVar()
        self.status = tk.StringVar()
        self.passwords = []  # Список словарей
        self.tree = None
        self.show_passwords = tk.BooleanVar(value=False)
        self.master_password_from_settings = ""  # Master password from settings
        self.setup_ui()
        
    def set_master_password(self, password):
        """Set master password for automatic use"""
        self.master_password_from_settings = password
        if password:
            self.master_password.set(password)
            logging.info("Master password set for password manager")
            
    def setup_ui(self):
        """Setup the user interface"""
        # Top frame
        top_frame = tk.Frame(self)
        top_frame.pack(fill='x', pady=5)
        
        tk.Button(top_frame, text="Открыть базу", command=self.open_db).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Создать новую базу", command=self.create_db).pack(side=tk.LEFT, padx=5)
        tk.Label(top_frame, text="Мастер-пароль:").pack(side=tk.LEFT, padx=5)
        tk.Entry(top_frame, textvariable=self.master_password, show='*', width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Сохранить", command=self.save_db).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(top_frame, text="Показать пароли", variable=self.show_passwords, command=self.refresh_tree).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Экспорт в CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Импорт из CSV", command=self.import_csv).pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = tk.Label(self, textvariable=self.status, fg='blue')
        self.status_label.pack(anchor='w', padx=5)

        # Tree frame
        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(fill='both', expand=True)
        self.init_tree()

        # Bottom buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill='x', pady=5)
        tk.Button(btn_frame, text="Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Редактировать", command=self.edit_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Удалить", command=self.delete_entry).pack(side=tk.LEFT, padx=5)

    def set_status(self, text, success=True):
        """Set status message"""
        self.status.set(text)
        color = 'green' if success else 'red'
        self.status_label.config(fg=color)

    def init_tree(self):
        """Initialize the treeview"""
        if self.tree:
            self.tree.destroy()
        columns = ('site', 'login', 'password', 'comment')
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show='headings')
        self.tree.heading('site', text='Сайт/Сервис')
        self.tree.heading('login', text='Логин')
        self.tree.heading('password', text='Пароль')
        self.tree.heading('comment', text='Комментарий')
        
        # Set column widths
        self.tree.column('site', width=150)
        self.tree.column('login', width=150)
        self.tree.column('password', width=150)
        self.tree.column('comment', width=200)
        
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<Double-1>', self.on_tree_double_click)
        self.refresh_tree()

    def refresh_tree(self):
        """Refresh the treeview with current passwords"""
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in self.passwords:
            pwd = entry['password'] if self.show_passwords.get() else ('*' * len(entry['password']))
            self.tree.insert('', 'end', values=(entry['site'], entry['login'], pwd, entry['comment']))

    def on_tree_double_click(self, event):
        """Handle double click on tree item"""
        item = self.tree.identify_row(event.y)
        if not item:
            return
        idx = self.tree.index(item)
        if idx >= len(self.passwords):
            return
        password = self.passwords[idx]['password']
        
        # Copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(password)
            self.set_status("Пароль скопирован в буфер обмена", True)
        except ImportError:
            # Fallback for systems without pyperclip
            try:
                import subprocess
                process = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
                process.communicate(input=password.encode())
                self.set_status("Пароль скопирован в буфер обмена", True)
            except Exception:
                self.set_status("Не удалось скопировать пароль", False)

    def get_password(self):
        """Get password, using master password if available"""
        password = self.master_password.get()
        if not password and self.master_password_from_settings:
            password = self.master_password_from_settings
            self.master_password.set(password)
        return password

    def open_db(self):
        """Open password database"""
        path = filedialog.askopenfilename(
            title="Открыть базу паролей", 
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")]
        )
        if not path:
            return
        self.db_path.set(path)
        password = self.get_password()
        if not password:
            password = simpledialog.askstring(
                "Мастер-пароль", 
                "Введите мастер-пароль для базы:", 
                show='*', 
                parent=self
            )
            if not password:
                self.set_status("Открытие отменено: не введён мастер-пароль", False)
                return
            self.master_password.set(password)
            
        # Run decryption in separate thread
        thread = threading.Thread(target=self._open_db_thread, args=(path, password))
        thread.daemon = True
        thread.start()

    def _open_db_thread(self, path, password):
        """Open database in separate thread"""
        temp_dir = None
        try:
            temp_dir = create_temp_directory()
            
            # Extract from 7zip
            sevenzip_path = self.crypto_engine.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            extracted_dir = os.path.join(temp_dir, 'extracted')
            os.makedirs(extracted_dir)
            
            sevenzip_cmd = f'"{sevenzip_path}" x "{path}" -o"{extracted_dir}" -p{password}'
            result = self.crypto_engine.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip extraction failed: {result.stderr}")
                
            # Find the database file
            files = [os.path.join(extracted_dir, f) for f in os.listdir(extracted_dir) if os.path.isfile(os.path.join(extracted_dir, f))]
            if not files:
                raise Exception("No database file found in archive")
                
            work_path = files[0]
            
            # Decrypt with OpenSSL
            openssl_path = self.crypto_engine.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            temp_openssl = os.path.join(temp_dir, 'db.dec')
            decrypt_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -d -in "{work_path}" -out "{temp_openssl}" -pass pass:{password}'
            
            result = self.crypto_engine.run_command(decrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL decryption failed: {result.stderr}")
                
            # Read decrypted data
            with open(temp_openssl, 'rb') as f:
                data = f.read()
                
            self.passwords = json.loads(data.decode('utf-8'))
            self.refresh_tree()
            self.set_status(f"База успешно открыта: {path}", True)
            logging.info(f"База паролей расшифрована: {path}")
            
        except Exception as e:
            self.set_status(f"Ошибка при открытии: {e}", False)
            logging.error(f"Ошибка при открытии базы: {e}")
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    def create_db(self):
        """Create new password database"""
        path = filedialog.asksaveasfilename(
            title="Создать новую базу паролей", 
            defaultextension=".dll", 
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")]
        )
        if not path:
            return
        self.db_path.set(path)
        self.passwords = []
        self.refresh_tree()
        self.set_status("Новая база создана (сохраните её после добавления паролей)", True)

    def save_db(self):
        """Save password database"""
        if not self.db_path.get():
            self.set_status("Сначала создайте или откройте базу", False)
            return
        if not self.get_password():
            self.set_status("Введите мастер-пароль", False)
            return
            
        # Run encryption in separate thread
        thread = threading.Thread(target=self._save_db_thread)
        thread.daemon = True
        thread.start()

    def _save_db_thread(self):
        """Save database in separate thread"""
        temp_dir = None
        try:
            temp_dir = create_temp_directory()
            
            password = self.get_password()
            data = json.dumps(self.passwords, ensure_ascii=False).encode('utf-8')
            
            # Create temporary file with data
            work_path = os.path.join(temp_dir, 'db.txt')
            with open(work_path, 'wb') as f:
                f.write(data)
                
            # Encrypt with OpenSSL
            openssl_path = self.crypto_engine.find_openssl_executable()
            if not openssl_path:
                raise FileNotFoundError("OpenSSL executable not found")
                
            temp_openssl = os.path.join(temp_dir, 'db.openssl')
            encrypt_cmd = f'"{openssl_path}" aes-256-cbc -a -salt -pbkdf2 -in "{work_path}" -out "{temp_openssl}" -pass pass:{password}'
            
            result = self.crypto_engine.run_command(encrypt_cmd)
            if result and result.returncode != 0:
                raise Exception(f"OpenSSL encryption failed: {result.stderr}")
                
            # Compress with 7zip
            sevenzip_path = self.crypto_engine.find_7zip_executable()
            if not sevenzip_path:
                raise FileNotFoundError("7zip executable not found")
                
            compression_level = {
                'normal': '5',
                'fast': '1',
                'ultra': '9'
            }.get(self.crypto_engine.settings.get('compression_method', 'normal'), '5')
            
            sevenzip_cmd = f'"{sevenzip_path}" a -t7z -m0=lzma2 -mx={compression_level} -p{password} "{self.db_path.get()}" "{temp_openssl}"'
            
            result = self.crypto_engine.run_command(sevenzip_cmd)
            if result and result.returncode != 0:
                raise Exception(f"7zip compression failed: {result.stderr}")
                
            self.set_status(f"База сохранена: {self.db_path.get()}", True)
            logging.info(f"База паролей зашифрована и сохранена: {self.db_path.get()}")
            
        except Exception as e:
            self.set_status(f"Ошибка при сохранении: {e}", False)
            logging.error(f"Ошибка при сохранении базы: {e}")
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    def add_entry(self):
        """Add new password entry"""
        entry = self.entry_dialog()
        if entry:
            self.passwords.append(entry)
            self.refresh_tree()

    def edit_entry(self):
        """Edit selected password entry"""
        selected = self.tree.selection()
        if not selected:
            return
        idx = self.tree.index(selected[0])
        entry = self.passwords[idx]
        new_entry = self.entry_dialog(entry)
        if new_entry:
            self.passwords[idx] = new_entry
            self.refresh_tree()

    def delete_entry(self):
        """Delete selected password entry"""
        selected = self.tree.selection()
        if not selected:
            return
        idx = self.tree.index(selected[0])
        del self.passwords[idx]
        self.refresh_tree()

    def entry_dialog(self, entry=None):
        """Show dialog for adding/editing password entry"""
        d = tk.Toplevel(self)
        d.title("Добавить/Редактировать запись")
        d.grab_set()
        d.transient(self)
        d.geometry("400x200")
        
        site = tk.StringVar(value=entry['site'] if entry else '')
        login = tk.StringVar(value=entry['login'] if entry else '')
        password = tk.StringVar(value=entry['password'] if entry else '')
        comment = tk.StringVar(value=entry['comment'] if entry else '')
        
        tk.Label(d, text="Сайт/Сервис:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        tk.Entry(d, textvariable=site, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(d, text="Логин:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        tk.Entry(d, textvariable=login, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(d, text="Пароль:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        tk.Entry(d, textvariable=password, show='*', width=30).grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(d, text="Комментарий:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        tk.Entry(d, textvariable=comment, width=30).grid(row=3, column=1, padx=5, pady=5)
        
        result = {}
        def on_ok():
            result['site'] = site.get()
            result['login'] = login.get()
            result['password'] = password.get()
            result['comment'] = comment.get()
            d.destroy()
            
        def on_cancel():
            d.destroy()
            
        button_frame = tk.Frame(d)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        tk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Отмена", command=on_cancel).pack(side=tk.LEFT, padx=5)
        
        d.wait_window()
        return result if result else None

    def export_csv(self):
        """Export passwords to CSV"""
        path = filedialog.asksaveasfilename(
            title="Экспорт в CSV", 
            defaultextension=".csv", 
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['site', 'login', 'password', 'comment'])
                writer.writeheader()
                for entry in self.passwords:
                    writer.writerow(entry)
            self.set_status(f"Экспортировано в {path}", True)
        except Exception as e:
            self.set_status(f"Ошибка экспорта: {e}", False)

    def import_csv(self):
        """Import passwords from CSV"""
        path = filedialog.askopenfilename(
            title="Импорт из CSV", 
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                # Поддержка альтернативных названий столбцов
                aliases = {
                    'site': ['site', 'name', 'url'],
                    'login': ['login', 'username'],
                    'password': ['password'],
                    'comment': ['comment', 'note']
                }
                field_map = {}
                for key, options in aliases.items():
                    for opt in options:
                        for field in reader.fieldnames:
                            if opt == field.lower():
                                field_map[key] = field
                                break
                        if key in field_map:
                            break
                            
                required = ['site', 'login', 'password', 'comment']
                missing = [r for r in required if r not in field_map]
                if missing:
                    self.set_status("Ошибка импорта: В CSV должны быть столбцы: site/name/url, login/username, password, comment/note", False)
                    return
                    
                def map_row(row):
                    return {
                        'site': row.get(field_map['site'], ''),
                        'login': row.get(field_map['login'], ''),
                        'password': row.get(field_map['password'], ''),
                        'comment': row.get(field_map['comment'], ''),
                    }
                    
                self.passwords = [map_row(row) for row in reader]
            self.refresh_tree()
            self.set_status(f"Импортировано из {path}", True)
        except Exception as e:
            self.set_status(f"Ошибка импорта: {e}", False) 