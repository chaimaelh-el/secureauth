import sqlite3
from contextlib import closing
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "auth_app.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS otp_codes (
                user_id INTEGER NOT NULL,
                otp_code TEXT NOT NULL,
                expiration_time TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
            """
        )
        conn.commit()


def add_user(username, email, password_hash):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        conn.commit()
        return cursor.lastrowid


def get_user(username):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, password_hash, failed_attempts, is_blocked, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        return cursor.fetchone()


def get_user_by_email(email):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, password_hash, failed_attempts, is_blocked, created_at
            FROM users
            WHERE email = ?
            """,
            (email,),
        )
        return cursor.fetchone()


def get_user_by_id(user_id):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, password_hash, failed_attempts, is_blocked, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )
        return cursor.fetchone()


def update_failed_attempts(user_id, failed_attempts, is_blocked=False):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = ?, is_blocked = ?
            WHERE id = ?
            """,
            (failed_attempts, int(is_blocked), user_id),
        )
        conn.commit()


def save_log(user_id, action, status, details):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO logs (user_id, action, status, details)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, action, status, details),
        )
        conn.commit()


def save_otp(user_id, otp_code, expiration_time):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
        cursor.execute(
            """
            INSERT INTO otp_codes (user_id, otp_code, expiration_time)
            VALUES (?, ?, ?)
            """,
            (user_id, otp_code, expiration_time),
        )
        conn.commit()


def get_otp(user_id):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT user_id, otp_code, expiration_time
            FROM otp_codes
            WHERE user_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (user_id,),
        )
        return cursor.fetchone()


def delete_otp(user_id):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM otp_codes WHERE user_id = ?", (user_id,))
        conn.commit()


def get_recent_logs(limit=50):
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT logs.id, logs.action, logs.status, logs.details, logs.created_at, users.username
            FROM logs
            LEFT JOIN users ON users.id = logs.user_id
            ORDER BY logs.id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()
