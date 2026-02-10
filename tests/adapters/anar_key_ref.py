import json
import os
import sys
import secrets

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

ERROR_INVALID_WORD = "InvalidWord"
ERROR_INVALID_CHAR = "InvalidChar"
ERROR_INVALID_LENGTH = "InvalidLength"
ERROR_INVALID_DICT = "InvalidDictionary"


def _read_dict(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return None, ERROR_INVALID_DICT

    # Reject empty tokens
    if any(line == "" for line in lines):
        return None, ERROR_INVALID_DICT

    # Case-insensitive uniqueness
    lower = [line.lower() for line in lines]
    if len(lower) != 256 or len(set(lower)) != 256:
        return None, ERROR_INVALID_DICT

    mapping = {lower[i]: i for i in range(256)}
    return mapping, None


def _hex_bytes(data):
    return data.hex().upper()


def derive_words(dictionary_path, passphrase):
    mapping, err = _read_dict(dictionary_path)
    if err:
        return {"ok": False, "error": err}

    tokens = passphrase.split()
    if len(tokens) != 32:
        return {"ok": False, "error": ERROR_INVALID_LENGTH}

    out = bytearray()
    for tok in tokens:
        if not all(ord(c) < 128 for c in tok):
            return {"ok": False, "error": ERROR_INVALID_WORD}
        key = tok.lower()
        if key not in mapping:
            return {"ok": False, "error": ERROR_INVALID_WORD}
        out.append(mapping[key])

    return {"ok": True, "key_hex": _hex_bytes(out)}


def derive_chars(alphabet, passphrase):
    if len(passphrase) != 43:
        return {"ok": False, "error": ERROR_INVALID_LENGTH}

    # Validate alphabet
    if len(alphabet) != 64 or len(set(alphabet)) != 64:
        return {"ok": False, "error": ERROR_INVALID_DICT}

    values = []
    for ch in passphrase:
        if ord(ch) >= 128 or ch not in alphabet:
            return {"ok": False, "error": ERROR_INVALID_CHAR}
        values.append(alphabet.index(ch))

    bits = []
    for v in values:
        for b in range(5, -1, -1):
            bits.append((v >> b) & 1)

    bits = bits[:256]
    out = bytearray()
    for i in range(0, 256, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)

    return {"ok": True, "key_hex": _hex_bytes(out)}


def gen_words(dictionary_path, mode, rng_bytes_hex=None, count=32):
    mapping, err = _read_dict(dictionary_path)
    if err:
        return {"ok": False, "error": err}

    if count <= 0:
        return {"ok": False, "error": ERROR_INVALID_LENGTH}

    if mode == "stub":
        if not rng_bytes_hex:
            return {"ok": False, "error": "MissingRngBytes"}
        rng_bytes = bytes.fromhex(rng_bytes_hex)
        if len(rng_bytes) < count:
            return {"ok": False, "error": "InsufficientRngBytes"}
        data = rng_bytes[:count]
    else:
        data = secrets.token_bytes(count)

    words_by_index = [None] * 256
    # invert map
    for word, idx in mapping.items():
        words_by_index[idx] = word

    words = [words_by_index[b] for b in data]
    return {"ok": True, "words": words}


def gen_keys(dictionary_path, count=100, mode="system"):
    mapping, err = _read_dict(dictionary_path)
    if err:
        return {"ok": False, "error": err}
    if count <= 0:
        return {"ok": False, "error": ERROR_INVALID_LENGTH}

    keys = []
    for _ in range(count):
        if mode == "system":
            data = secrets.token_bytes(32)
        else:
            data = secrets.token_bytes(32)
        keys.append(_hex_bytes(data))

    return {"ok": True, "keys_hex": keys}


def handle(req):
    op = req.get("op")
    if op == "ping":
        return {"ok": True}
    if op == "derive_words":
        return derive_words(req.get("dictionary_path", ""), req.get("passphrase", ""))
    if op == "derive_chars":
        return derive_chars(req.get("alphabet", ""), req.get("passphrase", ""))
    if op == "gen_words":
        return gen_words(
            req.get("dictionary_path", ""),
            req.get("mode", "system"),
            req.get("rng_bytes_hex"),
            req.get("count", 32),
        )
    if op == "gen_keys":
        return gen_keys(
            req.get("dictionary_path", ""),
            req.get("count", 100),
            req.get("mode", "system"),
        )

    return {"ok": False, "error": "UnknownOp"}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"ok": False, "error": "BadJson"}) + "\n")
            sys.stdout.flush()
            continue

        resp = handle(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
