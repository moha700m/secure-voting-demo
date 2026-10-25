"""Student accounts (simulated) and password checking."""
import hashlib
import hmac
import json
import os
import secrets

from storage import connect

PBKDF2_ROUNDS = 200_000

# 10 demo students. Passwords are only here so we can test the prototype.
DEMO_STUDENTS = {
    f"S{i:03d}": {"name": f"Student {i}", "password": f"pass{i:03d}"}
    for i in range(1, 11)
}


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)


def add_students(data_dir, students):
    """students: dict like DEMO_STUDENTS. We only save salt + hash."""
    conn = connect(data_dir)
    for sid, info in students.items():
        salt = os.urandom(16)
        conn.execute(
            "INSERT OR IGNORE INTO main.students VALUES (?, ?, ?, ?, 0)",
            (sid, info["name"], salt, hash_password(info["password"], salt)))
    conn.close()


def load_students_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_login(data_dir, student_id, password):
    """Return True only if the id exists and the password matches."""
    conn = connect(data_dir)
    row = conn.execute("SELECT salt, pw_hash FROM main.students WHERE student_id=?",
                       (student_id,)).fetchone()
    conn.close()
    if row is None:
        # still do the hash so a wrong id takes about the same time
        hash_password(password, b"0" * 16)
        return False
    salt, stored = row
    return hmac.compare_digest(hash_password(password, salt), stored)


def get_name(data_dir, student_id):
    conn = connect(data_dir)
    row = conn.execute("SELECT name FROM main.students WHERE student_id=?",
                       (student_id,)).fetchone()
    conn.close()
    return row[0] if row else None
