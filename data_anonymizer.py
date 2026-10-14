import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import pandas as pd
import json
import os
import hashlib
import base64
import logging
import secrets
import sqlite3
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('data_anonymizer.log', encoding='utf-8')]
)
logger = logging.getLogger(__name__)

class AuditLogger:
    def __init__(self, db_path="audit.db"):
        self.db_path = db_path
        self.current_user = None
        self.user_role = None
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                username TEXT,
                action_type TEXT NOT NULL,
                action_details TEXT,
                file_name TEXT,
                columns_involved TEXT,
                success BOOLEAN,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", admin_hash, "admin")
            )
            user_hash = hashlib.sha256("user123".encode()).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("user", user_hash, "user")
            )
        conn.commit()
        conn.close()
    
    def login(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
            (username, password_hash)
        )
        result = cursor.fetchone()
        conn.close()
        if result:
            self.current_user = {
                'id': result[0],
                'username': result[1],
                'role': result[2]
            }
            self.user_role = result[2]
            self.log_action("LOGIN", f"Успешный вход пользователя {username}", success=True)
            return True
        else:
            self.log_action("LOGIN_FAILED", f"Неудачная попытка входа пользователя {username}", success=False)
            return False
    
    def logout(self):
        if self.current_user:
            self.log_action("LOGOUT", f"Выход пользователя {self.current_user['username']}", success=True)
            self.current_user = None
            self.user_role = None
    
    def log_action(self, action_type, details="", file_name=None, columns=None, success=True):
        if not self.current_user:
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        columns_str = json.dumps(columns) if columns else None
        cursor.execute('''
            INSERT INTO audit_log
            (user_id, username, action_type, action_details, file_name, columns_involved, success)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.current_user['id'],
            self.current_user['username'],
            action_type,
            details,
            file_name,
            columns_str,
            success
        ))
        conn.commit()
        conn.close()
        logger.info(f"AUDIT: {self.current_user['username']} - {action_type} - {details}")
    
    def get_audit_logs(self, limit=1000):
        if self.user_role != 'admin':
            return []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, username, action_type, action_details,
            file_name, columns_involved, success
            FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        logs = cursor.fetchall()
        conn.close()
        return logs
    
    def get_user_stats(self):
        if self.user_role != 'admin':
            return []
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
            u.username,
            u.role,
            COUNT(al.id) as total_actions,
            SUM(CASE WHEN al.success = 1 THEN 1 ELSE 0 END) as successful_actions,
            MIN(al.timestamp) as first_action,
            MAX(al.timestamp) as last_action
            FROM users u
            LEFT JOIN audit_log al ON u.id = al.user_id
            GROUP BY u.id, u.username, u.role
            ORDER BY total_actions DESC
        ''')
        stats = cursor.fetchall()
        conn.close()
        return stats

class LoginWindow:
    def __init__(self, parent, audit_logger):
        self.parent = parent
        self.audit_logger = audit_logger
        self.window = tk.Toplevel(parent)
        self.window.title("Авторизация")
        self.window.geometry("400x300")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        self.result = None
        self._create_widgets()
    
    def _create_widgets(self):
        ttk.Label(self.window, text="АВТОРИЗАЦИЯ", font=("Arial", 16, "bold")).pack(pady=20)
        login_frame = ttk.Frame(self.window)
        login_frame.pack(pady=10, padx=20, fill=tk.X)
        ttk.Label(login_frame, text="Имя пользователя:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=5)
        ttk.Label(login_frame, text="Пароль:").pack(anchor=tk.W, pady=(10, 0))
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=30).pack(fill=tk.X, pady=5)
        button_frame = ttk.Frame(self.window)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Войти", command=self._login, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Отмена", command=self._cancel, width=15).pack(side=tk.LEFT, padx=5)
        self.window.bind('<Return>', lambda e: self._login())
    
    def _login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            messagebox.showerror("Ошибка", "Введите имя пользователя и пароль")
            return
        if self.audit_logger.login(username, password):
            self.result = {'username': username, 'role': self.audit_logger.user_role}
            self.window.destroy()
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль")
    
    def _cancel(self):
        self.window.destroy()
    
    def show(self):
        self.window.wait_window()
        return self.result

class AnonymizationInfo:
    def __init__(self, column_name: str, salt: bytes, method: str, layer: int = 1, encrypted_mapping: str = None):
        self.column_name = column_name
        self.salt = salt
        self.method = method
        self.layer = layer
        self.is_reversible = method in ['encryption', 'pseudo']
        self.encrypted_mapping = encrypted_mapping

class DataModel:
    def __init__(self, audit_logger):
        self.data = None
        self.columns = []
        self.selected_columns = []
        self.anonymization_info = {}
        self.encryption_key = None
        self.current_file_path = None
        self.audit_logger = audit_logger
    
    def load_excel(self, file_path: str):
        try:
            self.data = pd.read_excel(file_path)
            self.columns = list(self.data.columns)
            self.current_file_path = file_path
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "FILE_LOAD",
                    f"Загрузка Excel файла: {os.path.basename(file_path)}",
                    file_name=os.path.basename(file_path),
                    columns=self.columns,
                    success=True
                )
            file_without_ext = os.path.splitext(file_path)[0]
            meta_file = f"{file_without_ext}_meta.json"
            if os.path.exists(meta_file):
                with open(meta_file, 'r', encoding='utf-8') as f:
                    meta_data = json.load(f)
                    self.anonymization_info = {}
                    for col_info in meta_data.get('anonymized_columns', []):
                        col_name = col_info['column_name']
                        self.anonymization_info[col_name] = AnonymizationInfo(
                            column_name=col_name,
                            salt=base64.b64decode(col_info['salt']),
                            method=col_info.get('method', 'encryption'),
                            layer=col_info.get('layer', 1),
                            encrypted_mapping=col_info.get('encrypted_mapping')
                        )
            return True
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "FILE_LOAD_ERROR",
                    f"Ошибка загрузки Excel: {str(e)}",
                    file_name=os.path.basename(file_path) if file_path else None,
                    success=False
                )
            raise
    
    def load_json(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            if isinstance(json_data, list):
                self.data = pd.DataFrame(json_data)
            elif isinstance(json_data, dict) and 'data' in json_data:
                self.data = pd.DataFrame(json_data['data'])
                if 'metadata' in json_data and 'anonymized_columns' in json_data['metadata']:
                    self.anonymization_info = {}
                    for col_info in json_data['metadata']['anonymized_columns']:
                        col_name = col_info['column_name']
                        self.anonymization_info[col_name] = AnonymizationInfo(
                            column_name=col_name,
                            salt=base64.b64decode(col_info['salt']),
                            method=col_info.get('method', 'encryption'),
                            layer=col_info.get('layer', 1),
                            encrypted_mapping=col_info.get('encrypted_mapping')
                        )
            else:
                self.data = pd.DataFrame([json_data])
            self.columns = list(self.data.columns)
            self.current_file_path = file_path
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "FILE_LOAD",
                    f"Загрузка JSON файла: {os.path.basename(file_path)}",
                    file_name=os.path.basename(file_path),
                    columns=self.columns,
                    success=True
                )
            return True
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "FILE_LOAD_ERROR",
                    f"Ошибка загрузки JSON: {str(e)}",
                    file_name=os.path.basename(file_path) if file_path else None,
                    success=False
                )
            raise
    
    def save_excel(self, file_path: str):
        if self.data is None:
            raise ValueError("Нет данных для сохранения")
        self.data.to_excel(file_path, index=False)
        file_without_ext = os.path.splitext(file_path)[0]
        meta_file = f"{file_without_ext}_meta.json"
        meta_data = {
            'anonymized_columns': [
                {
                    'column_name': col,
                    'salt': base64.b64encode(info.salt).decode('utf-8'),
                    'method': info.method,
                    'layer': info.layer,
                    'encrypted_mapping': info.encrypted_mapping
                }
                for col, info in self.anonymization_info.items()
            ]
        }
        with open(meta_file, 'w', encoding='utf-8') as f:
            json.dump(meta_data, f, indent=2, ensure_ascii=False)
        if self.audit_logger.current_user:
            anonymized_cols = list(self.anonymization_info.keys())
            self.audit_logger.log_action(
                "FILE_SAVE",
                f"Сохранение Excel файла: {os.path.basename(file_path)}",
                file_name=os.path.basename(file_path),
                columns=anonymized_cols if anonymized_cols else None,
                success=True
            )
        return True
    
    def save_json(self, file_path: str):
        if self.data is None:
            raise ValueError("Нет данных для сохранения")
        output_data = {
            'metadata': {
                'anonymized_columns': [
                    {
                        'column_name': col,
                        'salt': base64.b64encode(info.salt).decode('utf-8'),
                        'method': info.method,
                        'layer': info.layer,
                        'encrypted_mapping': info.encrypted_mapping
                    }
                    for col, info in self.anonymization_info.items()
                ]
            },
            'data': self.data.to_dict(orient='records')
        }
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        if self.audit_logger.current_user:
            anonymized_cols = list(self.anonymization_info.keys())
            self.audit_logger.log_action(
                "FILE_SAVE",
                f"Сохранение JSON файла: {os.path.basename(file_path)}",
                file_name=os.path.basename(file_path),
                columns=anonymized_cols if anonymized_cols else None,
                success=True
            )
        return True
    
    def clear(self):
        self.data = None
        self.columns = []
        self.selected_columns = []
        self.anonymization_info = {}
        self.encryption_key = None
        self.current_file_path = None
    
    def generate_key(self, password: str, salt: bytes = None):
        if salt is None:
            salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def anonymize_columns(self, password: str, check_double: bool = True):
        if not self.selected_columns:
            raise ValueError("Не выбраны столбцы для обезличивания")
        already_anonymized = []
        for col in self.selected_columns:
            if col in self.anonymization_info:
                already_anonymized.append(col)
        if check_double and already_anonymized:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_ATTEMPT",
                    f"Попытка повторного обезличивания: {', '.join(already_anonymized)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            return False, already_anonymized
        key, salt = self.generate_key(password)
        cipher = Fernet(key)
        for col in self.selected_columns:
            if col not in self.data.columns:
                continue
            values = []
            for val in self.data[col]:
                if pd.isna(val) or val == "":
                    values.append("")
                else:
                    encrypted = cipher.encrypt(str(val).encode())
                    values.append(encrypted.decode())
            self.data[col] = values
            self.anonymization_info[col] = AnonymizationInfo(col, salt, 'encryption', 1)
        self.encryption_key = key
        if self.audit_logger.current_user:
            self.audit_logger.log_action(
                "ANONYMIZE",
                f"Обезличивание (шифрование) {len(self.selected_columns)} столбцов",
                file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                columns=self.selected_columns,
                success=True
            )
        return True, []
    
    def deanonymize_columns(self, password: str):
        if not self.anonymization_info:
            raise ValueError("Нет обезличенных данных")
        reversible_cols = {col: info for col, info in self.anonymization_info.items() if info.is_reversible}
        if not reversible_cols:
            raise ValueError("Нет обратимых методов обезличивания")
        successful_deanonymization = False
        columns_to_remove = []
        for col, info in reversible_cols.items():
            if col not in self.data.columns:
                continue
            try:
                key, _ = self.generate_key(password, info.salt)
                cipher = Fernet(key)
                if info.method == 'encryption':
                    test_value = None
                    for val in self.data[col]:
                        if val and not pd.isna(val) and str(val).strip():
                            test_value = str(val)
                            break
                    if test_value:
                        cipher.decrypt(test_value.encode())
                    values = []
                    for val in self.data[col]:
                        if not val or pd.isna(val):
                            values.append("")
                        else:
                            try:
                                decrypted = cipher.decrypt(str(val).encode())
                                values.append(decrypted.decode())
                            except Exception:
                                values.append(val)
                    self.data[col] = values
                    columns_to_remove.append(col)
                    successful_deanonymization = True
                elif info.method == 'pseudo':
                    if not info.encrypted_mapping:
                        continue
                    try:
                        decrypted_mapping = cipher.decrypt(info.encrypted_mapping.encode())
                        pseudonym_map = json.loads(decrypted_mapping.decode())
                        reverse_map = {v: k for k, v in pseudonym_map.items()}
                        values = []
                        for val in self.data[col]:
                            if not val or pd.isna(val):
                                values.append("")
                            else:
                                original = reverse_map.get(str(val), str(val))
                                values.append(original)
                        self.data[col] = values
                        columns_to_remove.append(col)
                        successful_deanonymization = True
                    except (InvalidKey, json.JSONDecodeError, Exception):
                        continue
            except (InvalidKey, Exception) as e:
                continue
        for col in columns_to_remove:
            del self.anonymization_info[col]
        if successful_deanonymization:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "DEANONYMIZE",
                    f"Деобезличивание {len(columns_to_remove)} столбцов",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=columns_to_remove,
                    success=True
                )
        else:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "DEANONYMIZE_ATTEMPT",
                    "Неудачная попытка деобезличивания",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=list(reversible_cols.keys()),
                    success=False
                )
        return successful_deanonymization
    
    def detect_personal_columns(self):
        if self.data is None:
            return []
        personal_keywords = {
            'имен': ['имя', 'fio', 'fullname', 'фио', 'name', 'фамилия', 'отчество'],
            'контакт': ['email', 'почта', 'mail', 'телефон', 'phone', 'тел', 'contact'],
            'адрес': ['адрес', 'address', 'город', 'city', 'улица', 'street', 'location'],
            'личное': ['паспорт', 'passport', 'снилс', 'snils', 'дата', 'birth', 'возраст', 'age'],
            'финансы': ['зарплата', 'salary', 'доход', 'income', 'счет', 'account', 'карта', 'card']
        }
        detected_columns = []
        for col in self.columns:
            col_lower = col.lower()
            if self.data[col].dtype == 'object' and len(self.data[col]) > 0:
                non_null = self.data[col].dropna()
                if len(non_null) > 0:
                    sample = str(non_null.iloc[0])
                    if '@' in sample and '.' in sample and ' ' not in sample:
                        detected_columns.append(col)
                        continue
                    if any(char.isdigit() for char in sample) and len(sample) >= 10:
                        phone_chars = sum(1 for c in sample if c.isdigit())
                        if phone_chars >= 10:
                            detected_columns.append(col)
                            continue
            for category, keywords in personal_keywords.items():
                if any(keyword in col_lower for keyword in keywords):
                    if col not in detected_columns:
                        detected_columns.append(col)
                    break
        return detected_columns
    
    def anonymize_with_hashing(self, check_double: bool = True):
        if not self.selected_columns:
            raise ValueError("Не выбраны столбцы для обезличивания")
        already_anonymized = [col for col in self.selected_columns if col in self.anonymization_info]
        if check_double and already_anonymized:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_HASH_ATTEMPT",
                    f"Попытка повторного хеширования: {', '.join(already_anonymized)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            return False, already_anonymized
        try:
            salt = secrets.token_bytes(16)
            for col in self.selected_columns:
                if col not in self.data.columns:
                    continue
                hashed_values = []
                for val in self.data[col]:
                    if pd.isna(val) or val == "":
                        hashed_values.append("")
                    else:
                        salted = str(val).encode() + salt
                        hashed = hashlib.sha256(salted).hexdigest()
                        hashed_values.append(hashed)
                self.data[col] = hashed_values
                self.anonymization_info[col] = AnonymizationInfo(col, salt, 'hashing', 1)
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_HASH",
                    f"Хеширование {len(self.selected_columns)} столбцов",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=True
                )
            return True, []
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_HASH_ERROR",
                    f"Ошибка при хешировании: {str(e)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            raise ValueError(f"Ошибка при хешировании данных: {str(e)}")
    
    def anonymize_with_generalization(self, check_double: bool = True):
        if not self.selected_columns:
            raise ValueError("Не выбраны столбцы для обезличивания")
        already_anonymized = [col for col in self.selected_columns if col in self.anonymization_info]
        if check_double and already_anonymized:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_GENERALIZATION_ATTEMPT",
                    f"Попытка повторного обобщения: {', '.join(already_anonymized)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            return False, already_anonymized
        try:
            salt = secrets.token_bytes(16)
            for col in self.selected_columns:
                if col not in self.data.columns:
                    continue
                generalized_values = []
                for val in self.data[col]:
                    if pd.isna(val) or val == "":
                        generalized_values.append("")
                    else:
                        val_str = str(val).strip()
                        try:
                            num = float(val_str)
                            if num < 0:
                                generalized = "negative"
                            elif num == 0:
                                generalized = "zero"
                            elif num < 10:
                                generalized = "0-10"
                            elif num < 100:
                                generalized = f"{int(num // 10)}0+"
                            elif num < 1000:
                                generalized = f"{int(num // 100)}00+"
                            else:
                                generalized = "1000+"
                            generalized_values.append(generalized)
                            continue
                        except (ValueError, TypeError):
                            pass
                        try:
                            if len(val_str) >= 7 and ('-' in val_str or '.' in val_str):
                                parts = val_str.replace('.', '-').split('-')
                                if len(parts) >= 2:
                                    if len(parts[0]) == 4:
                                        year = parts[0]
                                        month = parts[1]
                                    else:
                                        year = parts[2] if len(parts) > 2 else "unknown"
                                        month = parts[1]
                                    generalized = f"{year}-{month:0>2}"
                                    generalized_values.append(generalized)
                                    continue
                        except (ValueError, IndexError, TypeError):
                            pass
                        text_length = len(val_str)
                        first_char = val_str[0].upper() if val_str else "?"
                        if text_length <= 5:
                            generalized = f"short({first_char})"
                        elif text_length <= 15:
                            generalized = f"medium({first_char})"
                        else:
                            generalized = f"long({first_char})"
                        generalized_values.append(generalized)
                self.data[col] = generalized_values
                self.anonymization_info[col] = AnonymizationInfo(col, salt, 'generalization', 1)
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_GENERALIZATION",
                    f"Обобщение {len(self.selected_columns)} столбцов",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=True
                )
            return True, []
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_GENERALIZATION_ERROR",
                    f"Ошибка при обобщении: {str(e)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            raise ValueError(f"Ошибка при обобщении данных: {str(e)}")
    
    def anonymize_with_randomization(self, check_double: bool = True):
        if not self.selected_columns:
            raise ValueError("Не выбраны столбцы для обезличивания")
        already_anonymized = [col for col in self.selected_columns if col in self.anonymization_info]
        if check_double and already_anonymized:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_RANDOM_ATTEMPT",
                    f"Попытка повторного перемешивания: {', '.join(already_anonymized)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            return False, already_anonymized
        try:
            salt = secrets.token_bytes(16)
            for col in self.selected_columns:
                if col not in self.data.columns:
                    continue
                values = self.data[col].tolist()
                non_empty_indices = [i for i, v in enumerate(values) if not (pd.isna(v) or v == "")]
                non_empty_values = [values[i] for i in non_empty_indices]
                shuffled_values = non_empty_values.copy()
                random.shuffle(shuffled_values)
                result = values.copy()
                for idx, orig_idx in enumerate(non_empty_indices):
                    result[orig_idx] = shuffled_values[idx]
                self.data[col] = result
                self.anonymization_info[col] = AnonymizationInfo(col, salt, 'randomization', 1)
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_RANDOM",
                    f"Случайное перемешивание {len(self.selected_columns)} столбцов",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=True
                )
            return True, []
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_RANDOM_ERROR",
                    f"Ошибка при перемешивании: {str(e)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            raise ValueError(f"Ошибка при перемешивании данных: {str(e)}")
    
    def anonymize_with_pseudonymization(self, password: str, prefix: str = "ANON", check_double: bool = True):
        if not self.selected_columns:
            raise ValueError("Не выбраны столбцы для обезличивания")
        already_anonymized = [col for col in self.selected_columns if col in self.anonymization_info]
        if check_double and already_anonymized:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_PSEUDO_ATTEMPT",
                    f"Попытка повторной псевдонимизации: {', '.join(already_anonymized)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            return False, already_anonymized
        try:
            salt = secrets.token_bytes(16)
            key, _ = self.generate_key(password, salt)
            cipher = Fernet(key)
            for col in self.selected_columns:
                if col not in self.data.columns:
                    continue
                unique_values = self.data[col].unique()
                pseudonym_map = {}
                for idx, val in enumerate(unique_values):
                    if pd.isna(val) or val == "":
                        pseudonym_map[val if isinstance(val, str) else str(val)] = ""
                    else:
                        pseudo_id = f"{prefix}_{idx+1:06d}"
                        pseudonym_map[str(val)] = pseudo_id
                mapping_json = json.dumps(pseudonym_map, ensure_ascii=False)
                encrypted_mapping = cipher.encrypt(mapping_json.encode()).decode()
                pseudo_values = []
                for val in self.data[col]:
                    key = val if isinstance(val, str) else str(val)
                    if pd.isna(val):
                        pseudo_values.append("")
                    else:
                        pseudo_values.append(pseudonym_map.get(key, f"{prefix}_0"))
                self.data[col] = pseudo_values
                self.anonymization_info[col] = AnonymizationInfo(col, salt, 'pseudo', 1, encrypted_mapping)
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_PSEUDO",
                    f"Псевдонимизация {len(self.selected_columns)} столбцов с префиксом '{prefix}'",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=True
                )
            return True, []
        except Exception as e:
            if self.audit_logger.current_user:
                self.audit_logger.log_action(
                    "ANONYMIZE_PSEUDO_ERROR",
                    f"Ошибка при псевдонимизации: {str(e)}",
                    file_name=os.path.basename(self.current_file_path) if self.current_file_path else None,
                    columns=self.selected_columns,
                    success=False
                )
            raise ValueError(f"Ошибка при псевдонимизации данных: {str(e)}")

class DataAnonymizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Data Anonymizer - Профессиональная программа для обезличивания данных")
        self.root.geometry("1400x900")
        self.audit_logger = AuditLogger()
        self.current_user = None
        self.user_role = None
        self._login()
        if not self.current_user:
            self.root.destroy()
            return
        self.model = DataModel(self.audit_logger)
        self.search_results = []
        self.current_search_idx = 0
        self.column_checkboxes = {}
        self._create_ui()
        self._bind_events()
        self.audit_logger.log_action(
            "APP_START",
            f"Запуск приложения. Пользователь: {self.current_user}",
            success=True
        )
    
    def _login(self):
        login_window = LoginWindow(self.root, self.audit_logger)
        result = login_window.show()
        if result:
            self.current_user = result['username']
            self.user_role = result['role']
            self.root.title(f"Data Anonymizer - {self.current_user} ({'Admin' if self.user_role == 'admin' else 'User'})")
        else:
            self.current_user = None
    
    def _create_ui(self):
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(toolbar_frame, text="Открыть:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar_frame, text="Excel", command=self.load_excel, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="JSON", command=self.load_json, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Label(toolbar_frame, text="Сохранить:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=20)
        ttk.Button(toolbar_frame, text="Excel", command=self.save_excel, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="JSON", command=self.save_json, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Frame(toolbar_frame, width=2, relief=tk.SUNKEN).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        restore_btn = tk.Button(toolbar_frame, text="Восстановить", command=self.deanonymize, 
                               font=("Arial", 9, "bold"), bg="#4CAF50", fg="white", 
                               relief=tk.RAISED, padx=8, pady=5, cursor="hand2",
                               activebackground="#45a049", activeforeground="white",
                               bd=2, highlightthickness=0, width=15)
        restore_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="Очистить", command=self.clear_data, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="Анализ", command=self.analyze_risks, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="О программе", command=self.show_about, width=15).pack(side=tk.RIGHT, padx=2)
        user_frame = ttk.Frame(self.root)
        user_frame.pack(fill=tk.X, padx=10, pady=5)
        user_info = f"{self.current_user} | {'Admin' if self.user_role == 'admin' else 'User'}"
        ttk.Label(user_frame, text=user_info, font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        if self.user_role == 'admin':
            ttk.Button(user_frame, text="Журнал действий", command=self.show_audit_logs, width=20).pack(side=tk.RIGHT, padx=2)
        ttk.Button(user_frame, text="Смена пользователя", command=self.change_user, width=20).pack(side=tk.RIGHT, padx=2)
        anon_frame = ttk.LabelFrame(self.root, text="Методы обезличивания", padding=10)
        anon_frame.pack(fill=tk.X, padx=10, pady=5)
        methods_container = ttk.Frame(anon_frame)
        methods_container.pack(fill=tk.BOTH, expand=True)
        description_frame = ttk.Frame(methods_container)
        description_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        methods_text = tk.Text(description_frame, height=8, wrap=tk.WORD, bg="#f0f0f0", 
                              relief=tk.FLAT, font=("Arial", 9), padx=10, pady=10)
        methods_text.pack(fill=tk.BOTH, expand=True)
        methods_info = """ШИФРОВАНИЕ (Обратимо): Защита паролем, можно восстановить данные.

ХЕШИРОВАНИЕ (Необратимо): Безопасно для ID, данные нельзя восстановить.

ОБОБЩЕНИЕ (Необратимо): Замена на категории (например, возраст→20+), данные нельзя восстановить.

ПЕРЕМЕШИВАНИЕ (Необратимо): Случайная перестановка значений, данные нельзя восстановить.

ПСЕВДОНИМИЗАЦИЯ (Обратимо): Замена на ID (например, ANON_000001), сохраняет связи между данными."""
        methods_text.insert(tk.END, methods_info)
        methods_text.config(state=tk.DISABLED)
        buttons_frame = ttk.Frame(methods_container)
        buttons_frame.pack(side=tk.RIGHT, fill=tk.Y)
        button_grid = ttk.Frame(buttons_frame)
        button_grid.pack()
        methods = [
            (0, 0, 2, "Шифрование\n(Обратимо)", self.anonymize, "#2196F3"),
            (1, 0, 1, "Хеширование\n(Необратимо)", self.anonymize_hashing, "#FF9800"),
            (1, 1, 1, "Обобщение\n(Необратимо)", self.anonymize_generalization, "#FF9800"),
            (2, 0, 1, "Перемешивание\n(Необратимо)", self.anonymize_randomization, "#FF9800"),
            (2, 1, 1, "Псевдонимизация\n(Обратимо)", self.anonymize_pseudonymization, "#2196F3"),
        ]
        button_grid.columnconfigure(0, weight=1)
        button_grid.columnconfigure(1, weight=1)
        for row, col, colspan, text, cmd, color in methods:
            btn = tk.Button(button_grid, text=text, command=cmd, font=("Arial", 9, "bold"),
                            bg=color, fg="white", relief=tk.RAISED, padx=12, pady=10, cursor="hand2",
                            activebackground=self._darken_color(color), activeforeground="white",
                            bd=2, highlightthickness=0, width=18)
            btn.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5, sticky="ew")
        column_frame = ttk.LabelFrame(self.root, text="Выбор столбцов", padding=5)
        column_frame.pack(fill=tk.X, padx=10, pady=5)
        control_frame = ttk.Frame(column_frame)
        control_frame.pack(fill=tk.X, pady=5)
        ttk.Button(control_frame, text="Выбрать все", width=15, command=self.select_all_columns).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Снять все", width=15, command=self.deselect_all_columns).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Авто-определение", width=20, command=self.auto_detect_personal_data).pack(side=tk.LEFT, padx=2)
        self.columns_canvas = tk.Canvas(column_frame, height=30, bg="white")
        scrollbar = ttk.Scrollbar(column_frame, orient="horizontal", command=self.columns_canvas.xview)
        self.checkbox_frame = ttk.Frame(self.columns_canvas)
        self.columns_canvas.configure(xscrollcommand=scrollbar.set)
        self.columns_canvas.create_window((0, 0), window=self.checkbox_frame, anchor="nw")
        self.checkbox_frame.bind("<Configure>", 
            lambda e: self.columns_canvas.configure(scrollregion=self.columns_canvas.bbox("all")))
        self.columns_canvas.pack(side=tk.TOP, fill=tk.X)
        scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        tree_frame = ttk.LabelFrame(self.root, text="Данные", padding=5)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.tree = ttk.Treeview(tree_frame, show="headings")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Готово к работе")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
    
    def _create_column_checkboxes(self):
        for widget in self.checkbox_frame.winfo_children():
            widget.destroy()
        self.column_checkboxes.clear()
        if not self.model.columns:
            return
        for col in self.model.columns:
            frame = ttk.Frame(self.checkbox_frame)
            frame.pack(side=tk.LEFT, padx=5, pady=2)
            var = tk.BooleanVar(value=col in self.model.selected_columns)
            self.column_checkboxes[col] = var
            status = ""
            color = "black"
            if col in self.model.anonymization_info:
                info = self.model.anonymization_info[col]
                if info.is_reversible:
                    status = " (Обратимо)"
                    color = "blue"
                else:
                    status = " (Необратимо)"
                    color = "red"
            cb = ttk.Checkbutton(frame, variable=var, 
                command=lambda c=col, v=var: self._on_column_checkbox_change(c, v))
            cb.pack(side=tk.LEFT)
            label_text = f"{col}{status}"
            label = ttk.Label(frame, text=label_text, foreground=color, font=("Arial", 9, "bold" if status else "normal"))
            label.pack(side=tk.LEFT, padx=2)
    
    def _on_column_checkbox_change(self, column_name, var):
        if var.get():
            if column_name not in self.model.selected_columns:
                self.model.selected_columns.append(column_name)
        else:
            if column_name in self.model.selected_columns:
                self.model.selected_columns.remove(column_name)
        self.status_var.set(f"Выбрано столбцов: {len(self.model.selected_columns)}")
    
    def _bind_events(self):
        self.root.bind("<Control-o>", lambda e: self.load_excel())
        self.root.bind("<Control-s>", lambda e: self.save_excel())
    
    def load_excel(self):
        path = filedialog.askopenfilename(filetypes=[("Excel", "*.xlsx *.xls")])
        if not path:
            return
        try:
            self.model.load_excel(path)
            self.display_data()
            self._create_column_checkboxes()
            self.status_var.set(f"Загружен: {os.path.basename(path)} ({len(self.model.columns)} столбцов)")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка загрузки: {str(e)}")
            self.status_var.set("Ошибка загрузки файла")
    
    def load_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self.model.load_json(path)
            self.display_data()
            self._create_column_checkboxes()
            self.status_var.set(f"Загружен: {os.path.basename(path)} ({len(self.model.columns)} столбцов)")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка загрузки: {str(e)}")
            self.status_var.set("Ошибка загрузки файла")
    
    def save_excel(self):
        if self.model.data is None:
            messagebox.showwarning("Нет данных", "Сначала загрузите файл")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if path:
            try:
                self.model.save_excel(path)
                self.status_var.set(f"Сохранено: {os.path.basename(path)}")
                messagebox.showinfo("Успех", f"Файл сохранен: {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {str(e)}")
                self.status_var.set("Ошибка сохранения")
    
    def save_json(self):
        if self.model.data is None:
            messagebox.showwarning("Нет данных", "Сначала загрузите файл")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            try:
                self.model.save_json(path)
                self.status_var.set(f"Сохранено: {os.path.basename(path)}")
                messagebox.showinfo("Успех", f"Файл сохранен: {path}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка сохранения: {str(e)}")
                self.status_var.set("Ошибка сохранения")
    
    def display_data(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if self.model.data is None:
            self.status_var.set("Нет данных для отображения")
            return
        self.tree["columns"] = self.model.columns
        for col in self.model.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150, anchor="w")
        for idx, row in self.model.data.iterrows():
            values = ["" if pd.isna(v) else str(v)[:100] for v in row]
            self.tree.insert("", "end", iid=idx, values=values)
    
    def select_all_columns(self):
        if not self.model.columns:
            return
        self.model.selected_columns = self.model.columns.copy()
        for var in self.column_checkboxes.values():
            var.set(True)
        self.status_var.set(f"Выбраны все столбцы: {len(self.model.selected_columns)}")
    
    def deselect_all_columns(self):
        self.model.selected_columns.clear()
        for var in self.column_checkboxes.values():
            var.set(False)
        self.status_var.set("Выбор снят")
    
    def auto_detect_personal_data(self):
        if self.model.data is None:
            messagebox.showwarning("Нет данных", "Сначала загрузите файл")
            return
        detected = self.model.detect_personal_columns()
        if detected:
            self.deselect_all_columns()
            for col in detected:
                if col in self.column_checkboxes:
                    self.column_checkboxes[col].set(True)
                if col not in self.model.selected_columns:
                    self.model.selected_columns.append(col)
            self.status_var.set(f"Авто-определено {len(detected)} столбцов")
            messagebox.showinfo("Успех", f"Обнаружено {len(detected)} столбцов:\n\n" + "\n".join(detected))
        else:
            messagebox.showinfo("Результат", "Персональные данные не обнаружены")
    
    def clear_data(self):
        if messagebox.askyesno("Очистка", "Вы уверены? Все несохраненные данные будут потеряны."):
            self.model.clear()
            self.display_data()
            self._create_column_checkboxes()
            self.status_var.set("Данные очищены")
    
    def analyze_risks(self):
        if self.model.data is None:
            messagebox.showwarning("Нет данных", "Сначала загрузите файл")
            return
        detected = self.model.detect_personal_columns()
        report = "АНАЛИЗ РИСКОВ УТЕЧКИ ДАННЫХ\n"
        report += "=" * 50 + "\n\n"
        if not detected:
            report += "Потенциальные персональные данные не обнаружены\n"
        else:
            report += f"Обнаружено {len(detected)} столбцов с ПДн:\n\n"
            for col in detected:
                report += f"• {col}\n"
            report += "\n" + "=" * 50 + "\n"
            report += "РЕКОМЕНДАЦИИ:\n"
            report += "1. Обезличить обнаруженные столбцы\n"
            report += "2. Использовать шифрование для чувствительных данных\n"
            report += "3. Проверить на уникальные идентификаторы\n"
        self.show_report_window("Анализ рисков", report)
        self.audit_logger.log_action(
            "RISK_ANALYSIS",
            f"Анализ рисков. Обнаружено: {len(detected)} столбцов",
            file_name=os.path.basename(self.model.current_file_path) if self.model.current_file_path else None,
            columns=detected,
            success=True
        )
    
    def show_report_window(self, title: str, content: str):
        report_window = tk.Toplevel(self.root)
        report_window.title(title)
        report_window.geometry("700x600")
        text_frame = ttk.Frame(report_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("Courier", 10))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        text_widget.insert(tk.END, content)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        button_frame = ttk.Frame(report_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(button_frame, text="Закрыть", command=report_window.destroy).pack(side=tk.RIGHT)
    
    def anonymize(self):
        if not self.model.selected_columns:
            messagebox.showwarning("Внимание", "Выберите столбцы!")
            return
        already_anonymized = [col for col in self.model.selected_columns if col in self.model.anonymization_info]
        if already_anonymized:
            if not messagebox.askyesno("ВНИМАНИЕ!", 
                f"Столбцы уже обезличены:\n{', '.join(already_anonymized)}\n\n"
                "Повторное обезличивание невозможно обратить!\n"
                "Продолжить?"):
                return
        password_dialog = tk.Toplevel(self.root)
        password_dialog.title("Пароль для шифрования")
        password_dialog.geometry("400x200")
        password_dialog.transient(self.root)
        password_dialog.grab_set()
        ttk.Label(password_dialog, text="Запомните пароль! Без него данные не восстановить!",
            foreground="red", font=("Arial", 9, "bold")).pack(pady=5)
        ttk.Label(password_dialog, text="Введите пароль для шифрования:",
            font=("Arial", 10)).pack(pady=10)
        password_frame = ttk.Frame(password_dialog)
        password_frame.pack(pady=10)
        ttk.Label(password_frame, text="Пароль:").grid(row=0, column=0, padx=5, pady=5)
        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(password_frame, text="Подтверждение:").grid(row=1, column=0, padx=5, pady=5)
        confirm_entry = ttk.Entry(password_frame, show="*", width=30)
        confirm_entry.grid(row=1, column=1, padx=5, pady=5)
        result = {"password": None, "confirmed": False}
        def on_ok():
            pwd = password_entry.get()
            confirm = confirm_entry.get()
            if not pwd:
                messagebox.showerror("Ошибка", "Пароль не может быть пустым!")
                return
            if pwd != confirm:
                messagebox.showerror("Ошибка", "Пароли не совпадают!")
                password_entry.delete(0, tk.END)
                confirm_entry.delete(0, tk.END)
                password_entry.focus()
                return
            result["password"] = pwd
            result["confirmed"] = True
            password_dialog.destroy()
        button_frame = ttk.Frame(password_dialog)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="ОК", width=15, command=on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Отмена", width=15, command=password_dialog.destroy).pack(side=tk.LEFT, padx=10)
        password_entry.focus()
        self.root.wait_window(password_dialog)
        if not result["confirmed"]:
            self.status_var.set("Обезличивание отменено")
            return
        try:
            success, _ = self.model.anonymize_columns(result["password"], check_double=False)
            self.display_data()
            self._create_column_checkboxes()
            messagebox.showinfo("Успех", "Данные успешно зашифрованы!")
            self.status_var.set(f"Зашифровано {len(self.model.selected_columns)} столбцов")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
            self.status_var.set("Ошибка при шифровании")
    
    def deanonymize(self):
        reversible_cols = {col: info for col, info in self.model.anonymization_info.items() if info.is_reversible}
        if not reversible_cols:
            messagebox.showinfo("Информация", 
                "Нет обратимых методов обезличивания\n\n"
                "Обратимые методы:\n"
                "- Шифрование\n"
                "- Псевдонимизация\n\n"
                "Необратимые методы:\n"
                "- Хеширование\n"
                "- Обобщение\n"
                "- Перемешивание")
            return
        pwd = simpledialog.askstring("Пароль", "Введите пароль для восстановления:", show='*')
        if not pwd:
            self.status_var.set("Восстановление отменено")
            return
        try:
            success = self.model.deanonymize_columns(pwd)
            if success:
                self.display_data()
                self._create_column_checkboxes()
                if self.model.anonymization_info:
                    remaining = list(self.model.anonymization_info.keys())
                    messagebox.showwarning("Частичный успех",
                        f"Восстановлены не все столбцы.\n"
                        f"Осталось зашифрованными:\n{', '.join(remaining)}")
                    self.status_var.set(f"Частично восстановлено. Осталось: {len(remaining)}")
                else:
                    messagebox.showinfo("Успех", "Все данные успешно восстановлены!")
                    self.status_var.set("Данные восстановлены")
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить данные")
                self.status_var.set("Ошибка при восстановлении")
        except InvalidKey:
            messagebox.showerror("Ошибка", "Неверный пароль!")
            self.status_var.set("Неверный пароль")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при восстановлении: {str(e)}")
            self.status_var.set("Ошибка при восстановлении")
    
    def _confirm_irreversible_action(self, method_name: str):
        return messagebox.askyesno(
            "ВНИМАНИЕ! Необратимое действие",
            f"Метод '{method_name}' является НЕОБРАТИМЫМ!\n\n"
            f"Данные нельзя будет восстановить после применения этого метода.\n\n"
            f"Вы уверены, что хотите продолжить?",
            icon='warning'
        )
    
    def anonymize_hashing(self):
        if not self.model.selected_columns:
            messagebox.showwarning("Внимание", "Выберите столбцы!")
            return
        if not self._confirm_irreversible_action("Хеширование"):
            self.status_var.set("Хеширование отменено")
            return
        try:
            success, _ = self.model.anonymize_with_hashing()
            if success:
                self.display_data()
                self._create_column_checkboxes()
                messagebox.showinfo("Успех", "Данные успешно хешированы!")
                self.status_var.set(f"Хеширование: {len(self.model.selected_columns)} столбцов")
            else:
                messagebox.showwarning("Внимание", "Некоторые столбцы уже обезличены")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")
            self.status_var.set("Ошибка при хешировании")
    
    def anonymize_generalization(self):
        if not self.model.selected_columns:
            messagebox.showwarning("Внимание", "Выберите столбцы!")
            return
        if not self._confirm_irreversible_action("Обобщение"):
            self.status_var.set("Обобщение отменено")
            return
        try:
            success, _ = self.model.anonymize_with_generalization()
            if success:
                self.display_data()
                self._create_column_checkboxes()
                messagebox.showinfo("Успех", "Данные успешно обобщены!")
                self.status_var.set(f"Обобщение: {len(self.model.selected_columns)} столбцов")
            else:
                messagebox.showwarning("Внимание", "Некоторые столбцы уже обезличены")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")
            self.status_var.set("Ошибка при обобщении")
    
    def anonymize_randomization(self):
        if not self.model.selected_columns:
            messagebox.showwarning("Внимание", "Выберите столбцы!")
            return
        if not self._confirm_irreversible_action("Перемешивание"):
            self.status_var.set("Перемешивание отменено")
            return
        try:
            success, _ = self.model.anonymize_with_randomization()
            if success:
                self.display_data()
                self._create_column_checkboxes()
                messagebox.showinfo("Успех", "Данные успешно перемешаны!")
                self.status_var.set(f"Перемешивание: {len(self.model.selected_columns)} столбцов")
            else:
                messagebox.showwarning("Внимание", "Некоторые столбцы уже обезличены")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")
            self.status_var.set("Ошибка при перемешивании")
    
    def anonymize_pseudonymization(self):
        if not self.model.selected_columns:
            messagebox.showwarning("Внимание", "Выберите столбцы!")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Параметры псевдонимизации")
        dialog.geometry("450x280")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Запомните пароль! Без него данные не восстановить!",
            foreground="red", font=("Arial", 9, "bold")).pack(pady=5)
        ttk.Label(dialog, text="Введите префикс для псевдонимов:",
            font=("Arial", 10)).pack(pady=(10, 5))
        ttk.Label(dialog, text="Примеры: USER, PERSON, ID, CUST",
            font=("Arial", 9), foreground="gray").pack(pady=2)
        prefix_var = tk.StringVar(value="ANON")
        prefix_entry = ttk.Entry(dialog, textvariable=prefix_var, width=30)
        prefix_entry.pack(pady=5)
        prefix_entry.select_range(0, tk.END)
        ttk.Label(dialog, text="Введите пароль для восстановления:",
            font=("Arial", 10)).pack(pady=(15, 5))
        password_frame = ttk.Frame(dialog)
        password_frame.pack(pady=5)
        ttk.Label(password_frame, text="Пароль:").grid(row=0, column=0, padx=5, pady=5)
        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(password_frame, text="Подтверждение:").grid(row=1, column=0, padx=5, pady=5)
        confirm_entry = ttk.Entry(password_frame, show="*", width=30)
        confirm_entry.grid(row=1, column=1, padx=5, pady=5)
        result = {"confirmed": False, "prefix": "ANON", "password": None}
        def on_ok():
            prefix = prefix_var.get().strip()
            if not prefix:
                messagebox.showerror("Ошибка", "Префикс не может быть пустым")
                return
            pwd = password_entry.get()
            confirm = confirm_entry.get()
            if not pwd:
                messagebox.showerror("Ошибка", "Пароль не может быть пустым!")
                return
            if pwd != confirm:
                messagebox.showerror("Ошибка", "Пароли не совпадают!")
                password_entry.delete(0, tk.END)
                confirm_entry.delete(0, tk.END)
                password_entry.focus()
                return
            result["prefix"] = prefix
            result["password"] = pwd
            result["confirmed"] = True
            dialog.destroy()
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="ОК", width=10, command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Отмена", width=10, command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        prefix_entry.focus()
        prefix_entry.bind('<Return>', lambda e: password_entry.focus())
        password_entry.bind('<Return>', lambda e: confirm_entry.focus())
        confirm_entry.bind('<Return>', lambda e: on_ok())
        self.root.wait_window(dialog)
        if not result["confirmed"]:
            self.status_var.set("Псевдонимизация отменена")
            return
        try:
            success, _ = self.model.anonymize_with_pseudonymization(
                password=result["password"],
                prefix=result["prefix"]
            )
            if success:
                self.display_data()
                self._create_column_checkboxes()
                messagebox.showinfo("Успех", f"Данные псевдонимизированы с префиксом '{result['prefix']}'!")
                self.status_var.set(f"Псевдонимизация: {len(self.model.selected_columns)} столбцов")
            else:
                messagebox.showwarning("Внимание", "Некоторые столбцы уже обезличены")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")
            self.status_var.set("Ошибка при псевдонимизации")
    
    def show_audit_logs(self):
        if self.user_role != 'admin':
            messagebox.showwarning("Доступ запрещен", "Только администраторы")
            return
        audit_window = tk.Toplevel(self.root)
        audit_window.title("Журнал аудита")
        audit_window.geometry("900x600")
        columns = ("timestamp", "user", "action", "details", "file", "status")
        tree = ttk.Treeview(audit_window, columns=columns, show="headings", height=20)
        tree.heading("timestamp", text="Дата/Время")
        tree.heading("user", text="Пользователь")
        tree.heading("action", text="Действие")
        tree.heading("details", text="Детали")
        tree.heading("file", text="Файл")
        tree.heading("status", text="Статус")
        for col in columns:
            tree.column(col, width=120)
        logs = self.audit_logger.get_audit_logs()
        for log in logs:
            status_text = "OK" if log['success'] else "ОШИБКА"
            tree.insert("", "end", values=(
                log['timestamp'],
                log['username'],
                log['action_type'],
                log['action_details'][:50] + "..." if len(log['action_details']) > 50 else log['action_details'],
                log['file_name'] or "",
                status_text
            ))
        scrollbar = ttk.Scrollbar(audit_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
    
    def change_user(self):
        if messagebox.askyesno("Смена пользователя", 
            "Вы уверены?\nВсе несохраненные данные будут потеряны."):
            self.audit_logger.log_action(
                "USER_CHANGE",
                f"Смена пользователя с {self.current_user}",
                success=True
            )
            self.model.clear()
            self.display_data()
            self._create_column_checkboxes()
            self.audit_logger.logout()
            self._login()
            if self.current_user:
                self.root.title(f"Data Anonymizer - {self.current_user}")
                self.status_var.set(f"Пользователь: {self.current_user}")
            else:
                self.root.destroy()
    
    def _darken_color(self, color: str):
        if color.startswith('#'):
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            r = max(0, r - 30)
            g = max(0, g - 30)
            b = max(0, b - 30)
            return f"#{r:02x}{g:02x}{b:02x}"
        return color
    
    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("О программе")
        about_window.geometry("600x500")
        about_window.resizable(False, False)
        about_window.transient(self.root)
        about_window.grab_set()
        about_window.update_idletasks()
        x = (about_window.winfo_screenwidth() // 2) - (600 // 2)
        y = (about_window.winfo_screenheight() // 2) - (500 // 2)
        about_window.geometry(f"600x500+{x}+{y}")
        title_frame = ttk.Frame(about_window, padding=20)
        title_frame.pack(fill=tk.X)
        title_label = tk.Label(title_frame, text="Data Anonymizer", 
                              font=("Arial", 20, "bold"), fg="#2196F3")
        title_label.pack()
        version_label = tk.Label(title_frame, text="Версия 1.0", 
                                font=("Arial", 10), fg="gray")
        version_label.pack(pady=5)
        ttk.Separator(about_window, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=10)
        content_frame = ttk.Frame(about_window, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        about_text = tk.Text(content_frame, wrap=tk.WORD, font=("Arial", 10), 
                            bg="#f9f9f9", relief=tk.FLAT, padx=10, pady=10, height=15)
        about_text.pack(fill=tk.BOTH, expand=True)
        about_content = """
ПРОГРАММА ДЛЯ ОБЕЗЛИЧИВАНИЯ ПЕРСОНАЛЬНЫХ ДАННЫХ

Описание:
Data Anonymizer - это мощный инструмент для защиты персональных данных 
путем их обезличивания. Программа поддерживает множество методов 
анонимизации данных с различными уровнями защиты.

Основные возможности:

МЕТОДЫ ОБЕЗЛИЧИВАНИЯ:
  • Шифрование (обратимо) - защита паролем
  • Хеширование (необратимо) - безопасно для ID
  • Обобщение (необратимо) - замена на категории
  • Перемешивание (необратимо) - случайная перестановка
  • Псевдонимизация (обратимо) - замена на ID с сохранением связей

ФУНКЦИИ:
  • Поддержка форматов Excel и JSON
  • Автоматическое определение персональных данных
  • Анализ рисков утечки данных
  • Система учета действий (аудит)
  • Разграничение доступа (Admin/User)
  • Сохранение метаданных для восстановления

БЕЗОПАСНОСТЬ:
  • Все действия логируются
  • Подтверждение необратимых операций
  • Защита паролем для обратимых методов
  • Шифрование маппингов

Технологии:
  • Python 3.x
  • Tkinter (GUI)
  • Pandas (обработка данных)
  • Cryptography (шифрование)
  • SQLite (база данных аудита)

Авторы:
Фот Ю.Д.
Хабиров А.А.

ВНИМАНИЕ: Используйте программу ответственно!
Необратимые методы нельзя отменить после применения.
        """
        about_text.insert(tk.END, about_content)
        about_text.config(state=tk.DISABLED)
        button_frame = ttk.Frame(about_window, padding=10)
        button_frame.pack(fill=tk.X)
        close_btn = tk.Button(button_frame, text="Закрыть", command=about_window.destroy,
                             font=("Arial", 10, "bold"), bg="#2196F3", fg="white",
                             relief=tk.RAISED, padx=20, pady=5, cursor="hand2",
                             activebackground="#1976D2", activeforeground="white")
        close_btn.pack()

def main():
    try:
        import pandas
        from cryptography.fernet import Fernet
    except ImportError as e:
        print("Установите зависимости: pip install pandas openpyxl cryptography")
        input("Нажмите Enter...")
        return
    root = tk.Tk()
    app = DataAnonymizerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()