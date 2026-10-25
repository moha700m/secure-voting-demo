"""Voting tokens. We never store the raw token, only HMAC-SHA256(secret, token)."""
import hashlib
import hmac
import os
import secrets

from storage import connect


def load_server_secret(data_dir):
    """Secret used for the token HMAC. Created once and kept in its own file."""
    path = os.path.join(data_dir, "token_secret.bin")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return f.read()


def hash_token(secret, token):
    return hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()


class TokenError(Exception):
    pass


def issue_token(data_dir, student_id):
    """Give ONE token to an eligible student who has not had one yet.

    Marking the student and saving the token hash happen in one transaction,
    so two requests at the same time cannot both get a token.
    The student row only says "token_issued = 1"; it does not say which token.
    """
    secret = load_server_secret(data_dir)
    token = secrets.token_urlsafe(32)
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE main.students SET token_issued=1 "
            "WHERE student_id=? AND token_issued=0", (student_id,))
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            raise TokenError("Token already issued or student not eligible")
        conn.execute("INSERT INTO tok.tokens (token_hash, used) VALUES (?, 0)",
                     (hash_token(secret, token),))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return token
