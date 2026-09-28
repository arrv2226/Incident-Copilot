from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .utils import project_root


@dataclass
class AuthUser:
    user_id: int
    username: str


class ChatStore:
    def __init__(self) -> None:
        self.db_path = project_root() / ".state" / "chat.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  salt TEXT NOT NULL,
                  created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chats (
                  id TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  title TEXT NOT NULL,
                  state_json TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  updated_at REAL NOT NULL,
                  FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  chat_id TEXT NOT NULL,
                  role TEXT NOT NULL,
                  content TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  FOREIGN KEY(chat_id) REFERENCES chats(id)
                )
                """
            )

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
        return raw.hex()

    def register_user(self, username: str, password: str) -> AuthUser:
        salt = secrets.token_hex(16)
        pwh = self._hash_password(password, salt)
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (username, pwh, salt, now),
            )
            user_id = int(cur.lastrowid)
        return AuthUser(user_id=user_id, username=username)

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        with self._conn() as conn:
            row = conn.execute("SELECT id, username, password_hash, salt FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None
        expected = self._hash_password(password, row["salt"])
        if expected != row["password_hash"]:
            return None
        return AuthUser(user_id=int(row["id"]), username=str(row["username"]))

    def create_chat(self, user_id: int, title: str) -> str:
        chat_id = f"chat-{secrets.token_hex(6)}"
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO chats (id, user_id, title, state_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (chat_id, user_id, title[:120], json.dumps({"waiting_approval": False, "waiting_clarification": False}), now, now),
            )
        return chat_id

    def list_chats(self, user_id: int) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, title, updated_at FROM chats WHERE user_id=? ORDER BY updated_at DESC",
                (user_id,),
            ).fetchall()
        out = []
        for row in rows:
            out.append({"chat_id": row["id"], "title": row["title"], "updated_at": row["updated_at"]})
        return out

    def get_chat(self, user_id: int, chat_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, title, state_json, created_at, updated_at FROM chats WHERE id=? AND user_id=?",
                (chat_id, user_id),
            ).fetchone()
        if not row:
            return None
        return {
            "chat_id": row["id"],
            "title": row["title"],
            "state": json.loads(row["state_json"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_messages(self, chat_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT role, content, created_at FROM messages WHERE chat_id=? ORDER BY id ASC",
                (chat_id,),
            ).fetchall()
        return [{"role": row["role"], "content": row["content"], "created_at": row["created_at"]} for row in rows]

    def add_message(self, chat_id: str, role: str, content: str) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO messages (chat_id, role, content, created_at) VALUES (?, ?, ?, ?)",
                (chat_id, role, content, now),
            )
            conn.execute("UPDATE chats SET updated_at=? WHERE id=?", (now, chat_id))

    def set_state(self, chat_id: str, state: Dict[str, Any]) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute("UPDATE chats SET state_json=?, updated_at=? WHERE id=?", (json.dumps(state), now, chat_id))

    def set_title(self, chat_id: str, title: str) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute("UPDATE chats SET title=?, updated_at=? WHERE id=?", (title[:120], now, chat_id))
