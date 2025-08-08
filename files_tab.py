import ttkbootstrap as ttk
from ttkbootstrap import Style
import os
import threading
import logging
from datetime import datetime
from tkinter import filedialog, messagebox
import tempfile
import shutil
from telegram_utils import TelegramUtils
import time

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
        top_frame = ttk.Frame(self)
        top_frame.pack(fill='x', pady=5)
        
        ttk.Button(top_frame, text="Выбрать файл", command=self.select_file, 
                  bootstyle="secondary-outline").pack(side='left', padx=5)
        ttk.Button(top_frame, text="Выбрать папку", command=self.select_folder, 
                  bootstyle="secondary-outline").pack(side='left', padx=5)
        ttk.Button(top_frame, text="Очистить список", command=self.clear_files, 
                  bootstyle="secondary-outline").pack(side='left', padx=5)
        
        password_frame = ttk.Frame(self)
        password_frame.pack(fill='x', pady=5)
        
        ttk.Label(password_frame, text="Пароль:").pack(side='left', padx=5)
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show='*', width=30)
        self.password_entry.pack(side='left', padx=5)
        
        self.show_password_var = ttk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Скрыть", variable=self.show_password_var, 
                       command=self.toggle_password_visibility).pack(side='left', padx=5)
        
        action_frame = ttk.Frame(self)
        action_frame.pack(fill='x', pady=5)
        
        ttk.Button(action_frame, text="Зашифровать", command=self.encrypt_files, 
                  bootstyle="success-outline").pack(side='left', padx=5)
        ttk.Button(action_frame, text="Расшифровать", command=self.decrypt_files, 
                  bootstyle="primary-outline").pack(side='left', padx=5)
        ttk.Button(action_frame, text="Отправить в Telegram", command=self.send_to_telegram, 
                  bootstyle="info-outline").pack(side='left', padx=5)
        
        self.progress_text = ttk.Text(self, height=5)
        self.progress_text.pack(fill='x', padx=5, pady=5)

        self.status_label = ttk.Label(self, textvariable=self.status, foreground='green')
        self.status_label.pack(anchor='w', padx=5, pady=5)

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
        """Clear selected files list"""
        self.selected_files = []
        self.update_file_list()

    def update_file_list(self):
        """Update the file list display"""
        for item in self.files_listbox.get_children():
            self.files_listbox.delete(item)
        for file in self.selected_files:
            self.files_listbox.insert("", "end", values=(file,))

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        show = '' if self.show_password_var.get() else '*'
        self.password_entry.configure(show=show)

    def encrypt_files(self):
        """Encrypt selected files"""
        password = self.password_var.get() or self.master_password
        if not password or not self.selected_files:
            self.set_status("Выберите файл и введите пароль", False)
            return

        output_path = filedialog.asksaveasfilename(
            title="Сохранить зашифрованный файл",
            defaultextension=".dll",
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")]
        )
        if not output_path:
            return

        threading.Thread(target=self._encrypt_files_thread, args=(password, output_path), daemon=True).start()

    def _encrypt_files_thread(self, password, output_path):
        """Encrypt files in a separate thread"""
        try:
            self.set_status("Шифрование начато...", True)
            def progress_callback(message):
                self.log_progress(message)

            result = self.crypto_engine.encrypt_files(self.selected_files, password, output_path, progress_callback)
            if result:
                self.set_status("Файлы успешно зашифрованы", True)
            else:
                self.set_status("Ошибка при шифровании", False)
                logging.error("Encryption failed: Unknown error")
        except Exception as e:
            self.set_status(f"Ошибка: {e}", False)
            logging.error(f"Encryption error: {e}")

    def decrypt_files(self):
        """Decrypt selected file"""
        password = self.password_var.get() or self.master_password
        if not password or not self.selected_files:
            self.set_status("Выберите файл и введите пароль", False)
            return

        output_dir = filedialog.askdirectory(title="Выберите папку для расшифровки")
        if not output_dir:
            return

        threading.Thread(target=self._decrypt_files_thread, args=(password, output_dir), daemon=True).start()

    def _decrypt_files_thread(self, password, output_dir):
        """Decrypt files in a separate thread"""
        try:
            self.set_status("Расшифровка начата...", True)
            def progress_callback(message):
                self.log_progress(message)

            for file in self.selected_files:
                result = self.crypto_engine.decrypt_files(file, password, output_dir, progress_callback)
                if not result:
                    self.set_status(f"Ошибка при расшифровке {file}", False)
                    logging.error(f"Decryption failed for file: {file}")
                    return
            self.set_status("Файлы успешно расшифрованы", True)
        except Exception as e:
            self.set_status(f"Ошибка: {e}", False)
            logging.error(f"Decryption error: {e}")

    def send_to_telegram(self):
        """Send file to Telegram (encrypt if not .dll, send directly if .dll)"""
        password = self.password_var.get() or self.master_password
        if not self.selected_files:
            self.set_status("Выберите файл", False)
            messagebox.showerror("Ошибка", "Пожалуйста, выберите файл для отправки.")
            return
        
        if len(self.selected_files) > 1:
            self.set_status("Выберите только один файл для отправки", False)
            messagebox.showerror("Ошибка", "Пожалуйста, выберите только один файл для отправки в Telegram.")
            return

        file_path = self.selected_files[0]
        is_encrypted = file_path.lower().endswith('.dll')
        
        if not is_encrypted and not password:
            self.set_status("Введите пароль для шифрования", False)
            messagebox.showerror("Ошибка", "Пожалуйста, введите пароль для шифрования файла.")
            return

        threading.Thread(target=self._send_to_telegram_thread, args=(password, file_path, is_encrypted), daemon=True).start()

    def _prepare_for_telegram(self, password, file_path):
        """Prepare file for Telegram sending (encrypt to temporary .dll)"""
        temp_encrypted = None
        try:
            self.set_status("Подготовка файла для Telegram...", True)
            self.log_progress("Encrypting file for Telegram...")
            temp_encrypted = os.path.join(tempfile.gettempdir(), f"temp_telegram_encrypted_{int(time.time())}.dll")
            
            def progress_callback(message):
                self.log_progress(message)
                
            result = self.crypto_engine.encrypt_files(
                [file_path], password, temp_encrypted, progress_callback
            )
            
            if result and os.path.exists(temp_encrypted):
                self.log_progress(f"Encrypted file created: {temp_encrypted}")
                return temp_encrypted
            else:
                self.set_status("Ошибка при шифровании для Telegram", False)
                logging.error(f"Telegram preparation failed: Encryption unsuccessful for {file_path}")
                return None
        except Exception as e:
            self.set_status(f"Ошибка при подготовке файла для Telegram: {e}", False)
            logging.error(f"Telegram preparation error: {e}")
            return None

    def _send_to_telegram_thread(self, password, file_path, is_encrypted):
        """Send file to Telegram in separate thread"""
        temp_encrypted = None
        try:
            telegram_token = self.crypto_engine.settings.get('telegram_token', '')
            telegram_chat_id = self.crypto_engine.settings.get('telegram_chat_id', '')
            
            if not telegram_token or not telegram_chat_id:
                self.set_status("Ошибка: Не указан токен Telegram или Chat ID", False)
                logging.error("Telegram send failed: Missing token or chat ID")
                messagebox.showerror(
                    "Ошибка Telegram",
                    "Пожалуйста, проверьте токен бота и Chat ID в настройках.\n"
                    "Получите токен у @BotFather и Chat ID у @GetIDsBot."
                )
                return

            telegram_utils = TelegramUtils(telegram_token, telegram_chat_id)
            
            success, message = telegram_utils.test_connection()
            if not success:
                self.set_status(f"Ошибка подключения к Telegram: {message}", False)
                logging.error(f"Telegram connection test failed: {message}")
                messagebox.showerror(
                    "Ошибка Telegram",
                    f"Не удалось подключиться к Telegram: {message}\n"
                    "1. Проверьте токен бота у @BotFather.\n"
                    "2. Проверьте Chat ID у @GetIDsBot.\n"
                    "3. Убедитесь, что бот добавлен в чат и имеет права отправки."
                )
                return
            
            self.log_progress("Отправляем файл в Telegram...")
            
            if is_encrypted:
                file_to_send = file_path
                self.log_progress(f"Sending encrypted file: {file_to_send}")
            else:
                temp_encrypted = self._prepare_for_telegram(password, file_path)
                if not temp_encrypted or not os.path.exists(temp_encrypted):
                    self.set_status("Ошибка: Не удалось подготовить файл для отправки", False)
                    logging.error(f"Telegram send failed: No encrypted file prepared for {file_path}")
                    return
                file_to_send = temp_encrypted

            file_size_mb = os.path.getsize(file_to_send) / (1024 * 1024)
            if file_size_mb > 50:
                self.set_status("Ошибка: Файл превышает лимит Telegram (50 МБ)", False)
                logging.error(f"Telegram send failed: File {file_to_send} is {file_size_mb:.2f} MB, exceeds 50 MB limit")
                messagebox.showerror("Ошибка", "Файл слишком большой для Telegram (макс. 50 МБ).")
                return

            send_password = self.crypto_engine.settings.get('send_password_in_caption', False)
            caption_password = password if send_password else "N/A"

            max_retries = 3
            for attempt in range(1, max_retries + 1):
                try:
                    success, message = telegram_utils.send_encrypted_file(
                        file_to_send, caption_password, "file"
                    )
                    if success:
                        self.set_status("Файл успешно отправлен в Telegram", True)
                        self.log_progress("Файл отправлен в Telegram!")
                        return
                    else:
                        error_message = message
                        if "401" in message:
                            error_message = "Неверный токен бота. Проверьте токен у @BotFather."
                        elif "403" in message:
                            error_message = "Бот не имеет прав отправки. Добавьте бота в чат/группу."
                        elif "404" in message:
                            error_message = "Chat ID не найден. Проверьте Chat ID у @GetIDsBot."
                        self.log_progress(f"Попытка {attempt} не удалась: {error_message}")
                        if attempt == max_retries:
                            self.set_status(f"Ошибка отправки в Telegram: {error_message}", False)
                            logging.error(f"Telegram send error after {max_retries} attempts: {message}")
                            messagebox.showerror(
                                "Ошибка Telegram",
                                f"Не удалось отправить файл: {error_message}\n"
                                "1. Проверьте токен бота у @BotFather.\n"
                                "2. Проверьте Chat ID у @GetIDsBot.\n"
                                "3. Убедитесь, что бот добавлен в чат и имеет права отправки."
                            )
                            return
                        time.sleep(2)
                except Exception as e:
                    self.log_progress(f"Попытка {attempt} не удалась: {str(e)}")
                    if attempt == max_retries:
                        self.set_status(f"Ошибка отправки в Telegram: {str(e)}", False)
                        logging.error(f"Telegram send error after {max_retries} attempts: {str(e)}")
                        messagebox.showerror(
                            "Ошибка Telegram",
                            f"Произошла ошибка: {str(e)}\n"
                            "1. Проверьте токен бота у @BotFather.\n"
                            "2. Проверьте Chat ID у @GetIDsBot.\n"
                            "3. Убедитесь, что бот добавлен в чат и имеет права отправки."
                        )
                        return
                    time.sleep(2)
                
        finally:
            if temp_encrypted and os.path.exists(temp_encrypted):
                try:
                    os.remove(temp_encrypted)
                    self.log_progress(f"Очищен временный файл: {temp_encrypted}")
                    logging.info(f"Cleaned up temporary file: {temp_encrypted}")
                except Exception as e:
                    logging.error(f"Error cleaning up temp file {temp_encrypted}: {e}")

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