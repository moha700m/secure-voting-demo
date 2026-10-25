"""Admin actions: deadline, closing, decrypting and counting."""
from collections import Counter

import crypto_utils
from storage import connect


class AdminError(Exception):
    pass


def set_deadline(election, deadline):
    s = election._load()
    s["deadline"] = deadline.isoformat()
    election._save(s)


def close_voting(election):
    s = election._load()
    s["closed"] = True
    election._save(s)
    election.vote_key = None  # forget the key in memory once voting ends


def count_votes(election, admin_passphrase):
    """Only works after voting is closed and with the right passphrase."""
    if election.is_open():
        raise AdminError("Voting is still open - results are locked")
    key = crypto_utils.unwrap_vote_key(election.data_dir, admin_passphrase)
    conn = connect(election.data_dir)
    rows = conn.execute("SELECT nonce, ciphertext FROM vot.votes").fetchall()
    conn.close()
    counts = Counter({c: 0 for c in election.candidates})
    for nonce, ct in rows:
        counts[crypto_utils.decrypt_vote(key, nonce, ct)] += 1
    return dict(counts)


def winner(counts):
    """Return ("winner", [name]) or ("tie", [names]) or ("none", [])."""
    top = max(counts.values()) if counts else 0
    if top == 0:
        return "none", []
    best = [c for c, n in counts.items() if n == top]
    return ("winner", best) if len(best) == 1 else ("tie", best)


def result_text(counts):
    lines = [f"{c}: {n}" for c, n in counts.items()]
    kind, names = winner(counts)
    if kind == "winner":
        lines.append(f"Winner: {names[0]}")
    elif kind == "tie":
        lines.append("Tie between: " + ", ".join(names))
    else:
        lines.append("No votes were cast")
    return "\n".join(lines)
