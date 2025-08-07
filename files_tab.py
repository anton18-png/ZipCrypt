import ttkbootstrap as ttk
from ttkbootstrap import Style
import os
import threading
import logging
from datetime import datetime
from tkinter import filedialog, messagebox
import tempfile
import shutil

class FilesTab(ttk.Frame):
    def __init__(self, parent, crypto_engine):
        super().__init__(parent)
        self.crypto_engine = crypto_engine
        self.selected_files = []
        self.status = ttk.StringVar()
        self.password_var = ttk.StringVar()
        self.master_password = ""
        self.setup_ui()
        
    def set_master_password(self, password):
        """Set master password for automatic use"""
        self.master_password = password
        if password:
            self.password_var.set(password)
            logging.info("Master password set for files tab")
            
    def setup_ui(self):
        """Setup the user interface"""
        # Top frame for file selection
        top_frame = ttk.Frame(self)
        top_frame.pack(fill='x', pady=5)
        
        ttk.Button(top_frame, text="Выбрать файл", command=self.select_file).pack(side='left', padx=5)
        ttk.Button(top_frame, text="Выбрать папку", command=self.select_folder).pack(side='left', padx=5)
        ttk.Button(top_frame, text="Очистить список", command=self.clear_files).pack(side='left', padx=5)
        
        # Password frame
        password_frame = ttk.Frame(self)
        password_frame.pack(fill='x', pady=5)
        
        ttk.Label(password_frame, text="Пароль:").pack(side='left', padx=5)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show='*', width=30)
        self.password_entry.pack(side='left', padx=5)
        
        self.show_password_var = ttk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Скрыть", variable=self.show_password_var, 
                       command=self.toggle_password_visibility).pack(side='left', padx=5)
        
        # Action buttons frame
        action_frame = ttk.Frame(self)
        action_frame.pack(fill='x', pady=5)
        
        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt_files, style='success.TButton').pack(side='left', padx=5)
        ttk.Button(action_frame, text="Расшифровать", command=self.decrypt_files, style='primary.TButton').pack(side='left', padx=5)
        ttk.Button(action_frame, text="Отправить в Telegram", command=self.send_to_telegram, style='info.TButton').pack(side='left', padx=5)
        
        # Progress
        self.progress_text = ttk.Text(self, height=5)
        self.progress_text.pack(fill='x', padx=5, pady=5)

        # Status
        self.status_label = ttk.Label(self, textvariable=self.status, foreground='green')
        self.status_label.pack(anchor='w', padx=5, pady=5)

        # Selected files list
        files_frame = ttk.Frame(self)
        files_frame.pack(fill='both', expand=True, pady=5)
        
        ttk.Label(files_frame, text="Выбранные файлы:").pack(anchor='w', padx=5)
        self.files_listbox = ttk.Treeview(files_frame, columns=("File"), show="headings")
        self.files_listbox.heading("File", text="Файл")
        self.files_listbox.pack(fill='both', expand=True, padx=5, pady=5)

    def select_file(self):
        """Select a single file"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_files.append(file_path)
            self.update_file_list()

    def select_folder(self):
        """Select a folder"""
        folder_path = filedialog.askdirectory()
        if folder_path:
            for file in os.listdir(folder_path):
                full_path = os.path.join(folder_path, file)
                if os.path.isfile(full_path):
                    self.selected_files.append(full_path)
            self.update_file_list()

    def clear_files(self):
        """Clear selected files"""
        self.selected_files.clear()
        self.update_file_list()

    def update_file_list(self):
        """Update the file list display"""
        self.files_listbox.delete(*self.files_listbox.get_children())
        for file in self.selected_files:
            self.files_listbox.insert('', 'end', values=(file,))

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        self.password_entry.configure(show='' if self.show_password_var.get() else '*')

    def encrypt_files(self):
        """Encrypt selected files"""
        password = self.password_var.get() or self.master_password
        if not password:
            self.set_status("Введите пароль", False)
            return
        
        threading.Thread(target=self._encrypt_files_thread, args=(password,), daemon=True).start()

    def _encrypt_files_thread(self, password):
        """Encrypt files in a separate thread"""
        try:
            self.set_status("Шифрование файлов...", True)
            temp_encrypted = os.path.join(tempfile.gettempdir(), "temp_encrypted.dll")
            
            def progress_callback(message):
                self.log_progress(message)
                
            result = self.crypto_engine.encrypt_files(
                self.selected_files, password, temp_encrypted, progress_callback
            )
            
            if result:
                self.set_status("Файлы успешно зашифрованы", True)
                if messagebox.askyesno("Сохранить", "Хотите сохранить зашифрованный файл?"):
                    save_path = filedialog.asksaveasfilename(defaultextension=".dll")
                    if save_path:
                        shutil.move(temp_encrypted, save_path)
                        self.set_status(f"Файл сохранен как {save_path}", True)
                    else:
                        os.remove(temp_encrypted)
            else:
                self.set_status("Ошибка при шифровании", False)
                if os.path.exists(temp_encrypted):
                    os.remove(temp_encrypted)
                    
        except Exception as e:
            self.set_status(f"Ошибка: {e}", False)
            logging.error(f"Encryption error: {e}")

    def decrypt_files(self):
        """Decrypt selected files"""
        password = self.password_var.get() or self.master_password
        if not password or not self.selected_files:
            self.set_status("Выберите файл и введите пароль", False)
            return
        
        threading.Thread(target=self._decrypt_files_thread, args=(password,), daemon=True).start()

    def _decrypt_files_thread(self, password):
        """Decrypt files in a separate thread"""
        try:
            self.set_status("Расшифровка файлов...", True)
            output_dir = filedialog.askdirectory(title="Выберите папку для сохранения")
            if not output_dir:
                return
                
            def progress_callback(message):
                self.log_progress(message)
                
            for file in self.selected_files:
                result = self.crypto_engine.decrypt_files(file, password, output_dir, progress_callback)
                if not result:
                    self.set_status(f"Ошибка расшифровки {file}", False)
                    return
            self.set_status("Файлы успешно расшифрованы", True)
            
        except Exception as e:
            self.set_status(f"Ошибка: {e}", False)
            logging.error(f"Decryption error: {e}")

    def send_to_telegram(self):
        """Send encrypted file to Telegram"""
        password = self.password_var.get() or self.master_password
        if not password or not self.selected_files:
            self.set_status("Выберите файл и введите пароль", False)
            return
        
        threading.Thread(target=self._send_to_telegram_thread, args=(password,), daemon=True).start()

    def _prepare_for_telegram(self, password):
        """Prepare file for Telegram sending"""
        try:
            self.set_status("Подготовка файла для Telegram...", True)
            temp_encrypted = os.path.join(tempfile.gettempdir(), "temp_telegram_encrypted.dll")
            
            def progress_callback(message):
                self.log_progress(message)
                
            result = self.crypto_engine.encrypt_files(
                self.selected_files, password, temp_encrypted, progress_callback
            )
            
            if result:
                return temp_encrypted
            else:
                self.set_status("Ошибка при шифровании для Telegram", False)
                return None
                
        except Exception as e:
            self.set_status(f"Ошибка при подготовке файла для Telegram: {e}", False)
            logging.error(f"Telegram preparation error: {e}")
            return None

    def _send_to_telegram_thread(self, password):
        """Send file to Telegram in separate thread"""
        try:
            import requests
            
            telegram_token = self.crypto_engine.settings.get('telegram_token', '')
            telegram_chat_id = self.crypto_engine.settings.get('telegram_chat_id', '')
            
            self.log_progress("Отправляем файл в Telegram...")
            
            temp_encrypted = self._prepare_for_telegram(password)
            if not temp_encrypted:
                return
                
            url = f"https://api.telegram.org/bot{telegram_token}/sendDocument"
            
            with open(temp_encrypted, 'rb') as f:
                files = {'document': f}
                data = {'chat_id': telegram_chat_id}
                response = requests.post(url, files=files, data=data, timeout=30)
                
            if response.status_code == 200:
                self.set_status("Файл успешно отправлен в Telegram", True)
                self.log_progress("Файл отправлен в Telegram!")
            else:
                self.set_status(f"Ошибка отправки в Telegram: {response.text}", False)
                self.log_progress(f"Ошибка отправки в Telegram: {response.text}")
                
        except Exception as e:
            self.set_status(f"Ошибка отправки в Telegram: {e}", False)
            self.log_progress(f"Ошибка отправки в Telegram: {e}")
            logging.error(f"Telegram send error: {e}")
        finally:
            if os.path.exists(temp_encrypted):
                os.remove(temp_encrypted)
                
    def set_status(self, text, success=True):
        """Set status message"""
        self.status.set(text)
        color = 'green' if success else 'red'
        self.status_label.configure(foreground=color)
        
    def log_progress(self, message):
        """Log progress message"""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.progress_text.insert('end', f"{timestamp} {message}\n")
        self.progress_text.see('end')
        self.progress_text.update_idletasks()