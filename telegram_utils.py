import requests
import os
import logging

class TelegramUtils:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{self.token}"
    
    def test_connection(self):
        """Test Telegram connection"""
        try:
            response = requests.get(f"{self.base_url}/getMe", timeout=10)
            logging.debug(f"Telegram test connection response: {response.json()}")
            if response.status_code == 200:
                return True, "Connection successful"
            return False, f"Connection failed: {response.json().get('description', 'Unknown error')}"
        except Exception as e:
            logging.error(f"Telegram connection test error: {str(e)}")
            return False, f"Connection error: {str(e)}"
    
    def send_message(self, message):
        """Send a message to Telegram"""
        try:
            response = requests.post(
                f"{self.base_url}/sendMessage",
                data={"chat_id": self.chat_id, "text": message},
                timeout=10
            )
            logging.debug(f"Telegram send message response: {response.json()}")
            if response.status_code == 200:
                return True, "Message sent"
            return False, f"Failed to send message: {response.json().get('description', 'Unknown error')}"
        except Exception as e:
            logging.error(f"Telegram send message error: {str(e)}")
            return False, f"Error sending message: {str(e)}"
    
    def send_encrypted_file(self, file_path, password, file_type):
        """Send encrypted file to Telegram"""
        try:
            with open(file_path, 'rb') as f:
                caption = f"Encrypted {file_type}: {os.path.basename(file_path)}\nPassword: {password}"
                response = requests.post(
                    f"{self.base_url}/sendDocument",
                    data={"chat_id": self.chat_id, "caption": caption},
                    files={"document": f},
                    timeout=10
                )
                logging.debug(f"Telegram send file response: {response.json()}")
                if response.status_code == 200:
                    return True, "File sent"
                return False, f"Failed to send file: {response.json().get('description', 'Unknown error')}"
        except Exception as e:
            logging.error(f"Telegram send file error: {str(e)}")
            return False, f"Error sending file: {str(e)}"
    
    def send_password_backup(self, file_path, password):
        """Send password backup to Telegram"""
        return self.send_encrypted_file(file_path, password, "passwords")