"""Small helper for the three SQLite files we use.

auth.db   -> students (id, name, salt, password hash, token_issued flag)
tokens.db -> token hashes and a used flag (no student id here)
votes.db  -> encrypted votes only (random id, nonce, ciphertext)
"""
import os
import sqlite3


def paths(data_dir):
    return {
        "auth": os.path.join(data_dir, "auth.db"),
        "tokens": os.path.join(data_dir, "tokens.db"),
        "votes": os.path.join(data_dir, "votes.db"),
    }


def connect(data_dir):
    """Open one connection with all three databases attached.

    Using one connection lets us do a single transaction that touches more
    than one file (SQLite commits attached databases atomically).
    isolation_level=None means we control BEGIN/COMMIT ourselves.
    """
    p = paths(data_dir)
    conn = sqlite3.connect(p["auth"], timeout=10, isolation_level=None,
                           check_same_thread=False)
    conn.execute("ATTACH DATABASE ? AS tok", (p["tokens"],))
    conn.execute("ATTACH DATABASE ? AS vot", (p["votes"],))
    return conn


def create_tables(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    conn = connect(data_dir)
    conn.execute("""CREATE TABLE IF NOT EXISTS main.students (
        student_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        salt BLOB NOT NULL,
        pw_hash BLOB NOT NULL,
        token_issued INTEGER NOT NULL DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS tok.tokens (
        token_hash TEXT PRIMARY KEY,
        used INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID""")
    # WITHOUT ROWID + random text key: rows are kept sorted by the random id,
    # so the file order does not show which vote came first.
    conn.execute("""CREATE TABLE IF NOT EXISTS vot.votes (
        vote_id TEXT PRIMARY KEY,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL) WITHOUT ROWID""")
    conn.close()
