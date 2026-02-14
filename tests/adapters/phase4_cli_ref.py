import argparse
import hashlib
import json
import os
import secrets
import struct
import sys


MAGIC_CONTAINER = b"SCLI1\x00"
VERSION = 1
PROTO_AES = 0
PROTO_OTP = 1
PROTO_PQ = 2
PROTO_CHACHA20POLY1305 = 3
PROTO_XCHACHA20POLY1305 = 4
PROTO_SERPENT256 = 5
KIND_FILE = 0
KIND_DIR = 1
KIND_TEXT = 2

MAGIC_ARCHIVE = b"SAPK1\x00"
CHUNK_SIZE = 4096


def eprint(msg):
    sys.stderr.write(msg + "\n")


def key_stream(key_bytes, protocol_id, size):
    out = bytearray()
    counter = 0
    p = bytes([protocol_id & 0xFF])
    while len(out) < size:
        ctr = struct.pack("<Q", counter)
        out.extend(hashlib.sha256(key_bytes + p + ctr).digest())
        counter += 1
    return bytes(out[:size])


def xor_bytes(data, stream):
    return bytes([data[i] ^ stream[i] for i in range(len(data))])


def normalize_rel(path):
    return path.replace("\\", "/")


def valid_rel_path(path):
    if not path:
        return False
    if path.startswith("/") or path.startswith("\\"):
        return False
    if len(path) >= 2 and path[1] == ":":
        return False
    for p in path.split("/"):
        if p in ("", ".", ".."):
            return False
    return True


def safe_join(base_dir, rel_path):
    out = os.path.abspath(os.path.join(base_dir, rel_path.replace("/", os.sep)))
    base = os.path.abspath(base_dir)
    if os.path.commonpath([base, out]) != base:
        return None
    return out


def collect_entries(input_path):
    if os.path.isfile(input_path):
        return [(os.path.basename(input_path), input_path)]
    if not os.path.isdir(input_path):
        return None
    entries = []
    for root, _, files in os.walk(input_path):
        files.sort()
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, input_path)
            entries.append((normalize_rel(rel), full))
    entries.sort(key=lambda x: x[0])
    return entries


def pack_path_to_bytes(input_path):
    entries = collect_entries(input_path)
    if entries is None:
        return None, "InvalidPath"

    out = bytearray()
    out.extend(MAGIC_ARCHIVE)
    out.extend(struct.pack("<I", len(entries)))
    for rel, src in entries:
        rel_bytes = rel.encode("utf-8")
        if len(rel_bytes) > 0xFFFF:
            return None, "InvalidPath"
        size = os.path.getsize(src)
        out.extend(struct.pack("<H", len(rel_bytes)))
        out.extend(rel_bytes)
        out.extend(struct.pack("<Q", size))
        with open(src, "rb") as fin:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                out.extend(chunk)
    return bytes(out), None


def parse_archive(data):
    if len(data) < len(MAGIC_ARCHIVE) + 4:
        return None, "InvalidArchive"
    if data[:len(MAGIC_ARCHIVE)] != MAGIC_ARCHIVE:
        return None, "InvalidArchive"
    pos = len(MAGIC_ARCHIVE)
    entry_count = struct.unpack("<I", data[pos:pos + 4])[0]
    pos += 4
    entries = []
    for _ in range(entry_count):
        if pos + 2 > len(data):
            return None, "CorruptInput"
        rel_len = struct.unpack("<H", data[pos:pos + 2])[0]
        pos += 2
        if pos + rel_len > len(data):
            return None, "CorruptInput"
        rel = data[pos:pos + rel_len].decode("utf-8", errors="strict")
        pos += rel_len
        if not valid_rel_path(rel):
            return None, "InvalidArchive"
        if pos + 8 > len(data):
            return None, "CorruptInput"
        size = struct.unpack("<Q", data[pos:pos + 8])[0]
        pos += 8
        if pos + size > len(data):
            return None, "CorruptInput"
        payload = data[pos:pos + size]
        pos += size
        entries.append((rel, payload))
    if pos != len(data):
        return None, "InvalidArchive"
    return entries, None


def unpack_bytes_to_dir(data, output_dir):
    parsed, e = parse_archive(data)
    if e:
        return e
    os.makedirs(output_dir, exist_ok=True)
    for rel, payload in parsed:
        out = safe_join(output_dir, rel)
        if out is None:
            return "InvalidArchive"
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(payload)
    return None


def build_container(protocol_id, kind_id, name, plaintext_bytes, key_text):
    key_bytes = key_text.encode("utf-8")
    stream = key_stream(key_bytes, protocol_id, len(plaintext_bytes))
    ciphertext = xor_bytes(plaintext_bytes, stream)
    auth_tag = hashlib.sha256(key_bytes + plaintext_bytes).digest()
    name_bytes = name.encode("utf-8")

    out = bytearray()
    out.extend(MAGIC_CONTAINER)
    out.extend(bytes([VERSION, protocol_id, kind_id]))
    out.extend(struct.pack("<H", len(name_bytes)))
    out.extend(struct.pack("<Q", len(plaintext_bytes)))
    out.extend(auth_tag)
    out.extend(name_bytes)
    out.extend(ciphertext)
    return bytes(out)


def parse_container(data):
    min_len = len(MAGIC_CONTAINER) + 3 + 2 + 8 + 32
    if len(data) < min_len:
        return None, "InvalidArchive"
    pos = 0
    if data[:len(MAGIC_CONTAINER)] != MAGIC_CONTAINER:
        return None, "InvalidArchive"
    pos += len(MAGIC_CONTAINER)
    version = data[pos]
    protocol_id = data[pos + 1]
    kind_id = data[pos + 2]
    pos += 3
    if version != VERSION or protocol_id not in (
        PROTO_AES,
        PROTO_OTP,
        PROTO_PQ,
        PROTO_CHACHA20POLY1305,
        PROTO_XCHACHA20POLY1305,
        PROTO_SERPENT256,
    ) or kind_id not in (KIND_FILE, KIND_DIR, KIND_TEXT):
        return None, "InvalidArchive"
    name_len = struct.unpack("<H", data[pos:pos + 2])[0]
    pos += 2
    payload_size = struct.unpack("<Q", data[pos:pos + 8])[0]
    pos += 8
    auth_tag = data[pos:pos + 32]
    pos += 32
    if pos + name_len > len(data):
        return None, "CorruptInput"
    name = data[pos:pos + name_len].decode("utf-8", errors="strict")
    pos += name_len
    if pos + payload_size != len(data):
        return None, "CorruptInput"
    ciphertext = data[pos:pos + payload_size]
    return {
        "protocol_id": protocol_id,
        "kind_id": kind_id,
        "name": name,
        "auth_tag": auth_tag,
        "ciphertext": ciphertext,
    }, None


def encrypt_command(args):
    if (args.path is None and args.text is None) or (args.path is not None and args.text is not None):
        eprint("Provide exactly one of --path or --text with --encrypt")
        return 1
    if args.key is None:
        eprint("Missing required argument --key")
        return 1
    if args.out is None:
        eprint("Missing required argument --out")
        return 1

    protocol = args.protocol.lower()
    if protocol not in ("aes", "otp", "pq", "chacha20poly1305", "xchacha20poly1305", "serpent-256", "serpent256"):
        eprint("Invalid protocol")
        return 1
    if protocol == "aes":
        proto_id = PROTO_AES
    elif protocol == "otp":
        proto_id = PROTO_OTP
    elif protocol == "pq":
        proto_id = PROTO_PQ
    elif protocol == "chacha20poly1305":
        proto_id = PROTO_CHACHA20POLY1305
    elif protocol == "xchacha20poly1305":
        proto_id = PROTO_XCHACHA20POLY1305
    else:
        proto_id = PROTO_SERPENT256

    if args.text is not None:
        kind = KIND_TEXT
        name = ""
        plain = args.text.encode("utf-8")
    else:
        if os.path.isfile(args.path):
            kind = KIND_FILE
            name = os.path.basename(args.path)
            with open(args.path, "rb") as f:
                plain = f.read()
        elif os.path.isdir(args.path):
            kind = KIND_DIR
            name = os.path.basename(os.path.abspath(args.path))
            packed, e = pack_path_to_bytes(args.path)
            if e:
                eprint(e)
                return 1
            plain = packed
        else:
            eprint("InvalidPath")
            return 1

    container = build_container(proto_id, kind, name, plain, args.key)
    with open(args.out, "wb") as f:
        f.write(container)
    return 0


def decrypt_command(args):
    if args.path is None:
        eprint("Missing required argument --path")
        return 1
    if args.key is None:
        eprint("Missing required argument --key")
        return 1
    if args.out is None:
        eprint("Missing required argument --out")
        return 1
    if not os.path.isfile(args.path):
        eprint("InvalidPath")
        return 1

    with open(args.path, "rb") as f:
        data = f.read()
    parsed, e = parse_container(data)
    if e:
        eprint(e)
        return 1

    key_bytes = args.key.encode("utf-8")
    stream = key_stream(key_bytes, parsed["protocol_id"], len(parsed["ciphertext"]))
    plaintext = xor_bytes(parsed["ciphertext"], stream)
    expected_tag = hashlib.sha256(key_bytes + plaintext).digest()
    if expected_tag != parsed["auth_tag"]:
        eprint("Authentication Failed")
        return 1

    if parsed["kind_id"] == KIND_TEXT:
        with open(args.out, "wb") as f:
            f.write(plaintext)
        return 0
    if parsed["kind_id"] == KIND_FILE:
        with open(args.out, "wb") as f:
            f.write(plaintext)
        return 0
    if parsed["kind_id"] == KIND_DIR:
        e = unpack_bytes_to_dir(plaintext, args.out)
        if e:
            eprint(e)
            return 1
        return 0
    eprint("InvalidArchive")
    return 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "protocols":
        print("Available protocols:")
        print("  aes")
        print("  otp")
        print("  pq")
        print("  chacha20poly1305")
        print("  xchacha20poly1305")
        print("  serpent-256")
        print("  serpent256")
        return 0

    parser = argparse.ArgumentParser(prog="safeanar")
    parser.add_argument("--list-protocols", action="store_true")
    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("--decrypt", action="store_true")
    parser.add_argument("--path")
    parser.add_argument("--text")
    parser.add_argument("--out")
    parser.add_argument("--key")
    parser.add_argument("--protocol", default="aes")
    args = parser.parse_args()

    if args.list_protocols:
        print("Available protocols:")
        print("  aes")
        print("  otp")
        print("  pq")
        print("  chacha20poly1305")
        print("  xchacha20poly1305")
        print("  serpent-256")
        print("  serpent256")
        return 0

    if args.encrypt == args.decrypt:
        eprint("Specify exactly one of --encrypt or --decrypt")
        return 1
    if args.decrypt and args.text is not None:
        eprint("--text is not valid with --decrypt")
        return 1

    if args.encrypt:
        return encrypt_command(args)
    return decrypt_command(args)


if __name__ == "__main__":
    sys.exit(main())
