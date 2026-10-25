"""Core voting logic: election settings, deadline and casting a vote."""
import json
import os
import secrets
import sqlite3
from datetime import datetime

import auth
import crypto_utils
import tokens
from storage import connect, create_tables

CANDIDATES = ["Aisha", "Omar", "Layla", "Yousef"]  # example candidates


class VoteError(Exception):
    pass


class Election:
    """One election stored in data_dir.

    clock is a function that returns the current time. Tests pass a fake clock
    so we can jump past the deadline without waiting.
    """

    def __init__(self, data_dir, clock=datetime.now):
        self.data_dir = data_dir
        self.clock = clock
        self.vote_key = None  # only held in memory while voting is open
        self.settings_path = os.path.join(data_dir, "election.json")

    # ---------- setup ----------
    def setup(self, admin_passphrase, students=None, candidates=None, deadline=None):
        create_tables(self.data_dir)
        auth.add_students(self.data_dir, students or auth.DEMO_STUDENTS)
        tokens.load_server_secret(self.data_dir)
        self.vote_key = crypto_utils.create_vote_key(self.data_dir, admin_passphrase)
        self._save({"candidates": candidates or CANDIDATES,
                    "deadline": deadline.isoformat() if deadline else None,
                    "closed": False})

    def unlock(self, admin_passphrase):
        """Used when the program restarts: admin unlocks the key for encrypting."""
        self.vote_key = crypto_utils.unwrap_vote_key(self.data_dir, admin_passphrase)

    def _load(self):
        with open(self.settings_path) as f:
            return json.load(f)

    def _save(self, s):
        with open(self.settings_path, "w") as f:
            json.dump(s, f, indent=2)

    @property
    def candidates(self):
        return self._load()["candidates"]

    def deadline(self):
        d = self._load()["deadline"]
        return datetime.fromisoformat(d) if d else None

    def is_open(self):
        s = self._load()
        if s["closed"]:
            return False
        d = self.deadline()
        return d is None or self.clock() < d

    # ---------- student side ----------
    def login_and_get_token(self, student_id, password):
        if not auth.check_login(self.data_dir, student_id, password):
            raise VoteError("Wrong student ID or password")
        if not self.is_open():
            raise VoteError("Voting is closed")
        try:
            return tokens.issue_token(self.data_dir, student_id)
        except tokens.TokenError as e:
            raise VoteError(str(e))

    def cast_vote(self, token, candidate):
        """Check token, encrypt vote, save vote and mark token used together."""
        if not self.is_open():
            raise VoteError("Voting is closed (deadline passed)")
        if candidate not in self.candidates:
            raise VoteError("Unknown candidate")
        if self.vote_key is None:
            raise VoteError("Server key not unlocked")

        token_hash = tokens.hash_token(tokens.load_server_secret(self.data_dir), token)
        nonce, ct = crypto_utils.encrypt_vote(self.vote_key, candidate)
        conn = connect(self.data_dir)
        try:
            # BEGIN IMMEDIATE takes the write lock straight away, so two threads
            # with the same token cannot both pass the UPDATE below.
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("UPDATE tok.tokens SET used=1 "
                               "WHERE token_hash=? AND used=0", (token_hash,))
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                raise VoteError("Invalid or already used token")
            # the vote row has no token, no student id and no time
            conn.execute("INSERT INTO vot.votes VALUES (?, ?, ?)",
                         (secrets.token_hex(16), nonce, ct))
            conn.execute("COMMIT")
        except sqlite3.Error:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return True
