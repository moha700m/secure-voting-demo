"""AES-256-GCM for votes, and protection of the vote key.

The vote key is 32 random bytes from AESGCM.generate_key (uses os.urandom).
It is never stored in plain form. We "wrap" it: a key-encryption key (KEK) is
derived from the admin passphrase with scrypt, and the vote key is encrypted
with that KEK using AES-GCM. The wrapped key goes in vote_key.json (chmod 600),
which is a different file from votes.db.
"""
import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_FILE = "vote_key.json"


def _kek(passphrase, salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode())


def create_vote_key(data_dir, passphrase):
    """Make a new vote key, wrap it and save it. Returns the raw key."""
    key = AESGCM.generate_key(bit_length=256)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrapped = AESGCM(_kek(passphrase, salt)).encrypt(nonce, key, b"vote-key")
    path = os.path.join(data_dir, KEY_FILE)
    with open(path, "w") as f:
        json.dump({k: base64.b64encode(v).decode() for k, v in
                   {"salt": salt, "nonce": nonce, "wrapped": wrapped}.items()}, f)
    os.chmod(path, 0o600)
    return key


def unwrap_vote_key(data_dir, passphrase):
    with open(os.path.join(data_dir, KEY_FILE)) as f:
        d = {k: base64.b64decode(v) for k, v in json.load(f).items()}
    try:
        return AESGCM(_kek(passphrase, d["salt"])).decrypt(d["nonce"], d["wrapped"], b"vote-key")
    except InvalidTag:
        raise ValueError("Wrong admin passphrase")


def encrypt_vote(key, candidate):
    nonce = os.urandom(12)  # new random nonce for every vote
    return nonce, AESGCM(key).encrypt(nonce, candidate.encode(), b"vote")


def decrypt_vote(key, nonce, ciphertext):
    return AESGCM(key).decrypt(nonce, ciphertext, b"vote").decode()
