import json
import os
import secrets
import struct
import sys


ERROR_INVALID_PATH = "InvalidPath"
ERROR_INVALID_ARCHIVE = "InvalidArchive"
ERROR_INVALID_PADDING_TARGET = "InvalidPaddingTarget"
ERROR_CORRUPT_INPUT = "CorruptInput"
ERROR_FILE_IO = "FileIOError"
ERROR_UNKNOWN_OP = "UnknownOp"
ERROR_BAD_JSON = "BadJson"

MAGIC_ARCHIVE = b"SAPK1\x00"
MAGIC_PADDED = b"SPAD1\x00"
PAD_HEADER_SIZE = len(MAGIC_PADDED) + 8
CHUNK_SIZE = 4096


def ok(**kwargs):
    out = {"ok": True}
    out.update(kwargs)
    return out


def err(code):
    return {"ok": False, "error": code}


def normalize_rel(path):
    return path.replace("\\", "/")


def validate_rel_path(path):
    if not path:
        return False
    if path.startswith("/") or path.startswith("\\"):
        return False
    if len(path) >= 2 and path[1] == ":":
        return False
    parts = path.split("/")
    for p in parts:
        if p in ("", ".", ".."):
            return False
    return True


def safe_join(base_dir, rel_path):
    out = os.path.abspath(os.path.join(base_dir, rel_path.replace("/", os.sep)))
    base_abs = os.path.abspath(base_dir)
    common = os.path.commonpath([base_abs, out])
    if common != base_abs:
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


def pack_path(input_path, output_path):
    entries = collect_entries(input_path)
    if entries is None:
        return err(ERROR_INVALID_PATH)

    try:
        bytes_written = 0
        with open(output_path, "wb") as out:
            out.write(MAGIC_ARCHIVE)
            out.write(struct.pack("<I", len(entries)))
            bytes_written += len(MAGIC_ARCHIVE) + 4

            for rel, src in entries:
                rel_bytes = rel.encode("utf-8")
                if len(rel_bytes) > 0xFFFF:
                    return err(ERROR_INVALID_PATH)
                size = os.path.getsize(src)
                out.write(struct.pack("<H", len(rel_bytes)))
                out.write(rel_bytes)
                out.write(struct.pack("<Q", size))
                bytes_written += 2 + len(rel_bytes) + 8

                with open(src, "rb") as fin:
                    while True:
                        chunk = fin.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        out.write(chunk)
                        bytes_written += len(chunk)
        return ok(entry_count=len(entries), bytes_written=bytes_written)
    except OSError:
        return err(ERROR_FILE_IO)


def parse_archive(input_path):
    try:
        total_size = os.path.getsize(input_path)
        entries = []
        with open(input_path, "rb") as f:
            magic = f.read(len(MAGIC_ARCHIVE))
            if magic != MAGIC_ARCHIVE:
                return None, ERROR_INVALID_ARCHIVE

            count_raw = f.read(4)
            if len(count_raw) != 4:
                return None, ERROR_CORRUPT_INPUT
            entry_count = struct.unpack("<I", count_raw)[0]

            for _ in range(entry_count):
                path_len_raw = f.read(2)
                if len(path_len_raw) != 2:
                    return None, ERROR_CORRUPT_INPUT
                path_len = struct.unpack("<H", path_len_raw)[0]

                path_raw = f.read(path_len)
                if len(path_raw) != path_len:
                    return None, ERROR_CORRUPT_INPUT
                try:
                    rel_path = path_raw.decode("utf-8")
                except UnicodeDecodeError:
                    return None, ERROR_INVALID_ARCHIVE
                if not validate_rel_path(rel_path):
                    return None, ERROR_INVALID_ARCHIVE

                size_raw = f.read(8)
                if len(size_raw) != 8:
                    return None, ERROR_CORRUPT_INPUT
                size = struct.unpack("<Q", size_raw)[0]

                data_offset = f.tell()
                next_offset = data_offset + size
                if next_offset > total_size:
                    return None, ERROR_CORRUPT_INPUT
                f.seek(size, os.SEEK_CUR)
                entries.append({
                    "path": rel_path,
                    "size": size,
                    "data_offset": data_offset,
                })

            if f.tell() != total_size:
                return None, ERROR_INVALID_ARCHIVE
        return entries, None
    except OSError:
        return None, ERROR_FILE_IO


def inspect_archive(input_path):
    entries, e = parse_archive(input_path)
    if e:
        return err(e)
    stripped = [{"path": it["path"], "size": it["size"]} for it in entries]
    return ok(entries=stripped, entry_count=len(stripped))


def unpack_path(input_path, output_dir):
    parsed, e = parse_archive(input_path)
    if e:
        return err(e)

    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(input_path, "rb") as archive:
            for entry in parsed:
                out_path = safe_join(output_dir, entry["path"])
                if out_path is None:
                    return err(ERROR_INVALID_ARCHIVE)

                parent = os.path.dirname(out_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)

                archive.seek(entry["data_offset"], os.SEEK_SET)
                remaining = entry["size"]
                with open(out_path, "wb") as fout:
                    while remaining > 0:
                        to_read = CHUNK_SIZE if remaining > CHUNK_SIZE else int(remaining)
                        chunk = archive.read(to_read)
                        if len(chunk) != to_read:
                            return err(ERROR_CORRUPT_INPUT)
                        fout.write(chunk)
                        remaining -= len(chunk)
        return ok(extracted_count=len(parsed))
    except OSError:
        return err(ERROR_FILE_IO)


def pad_file(input_path, output_path, target_size):
    if not os.path.isfile(input_path):
        return err(ERROR_INVALID_PATH)

    try:
        target_size = int(target_size)
    except (TypeError, ValueError):
        return err(ERROR_INVALID_PADDING_TARGET)

    try:
        real_size = os.path.getsize(input_path)
        min_size = PAD_HEADER_SIZE + real_size
        if target_size < min_size:
            return err(ERROR_INVALID_PADDING_TARGET)

        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            fout.write(MAGIC_PADDED)
            fout.write(struct.pack("<Q", real_size))

            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(chunk)

            remaining = target_size - min_size
            while remaining > 0:
                n = CHUNK_SIZE if remaining > CHUNK_SIZE else int(remaining)
                fout.write(secrets.token_bytes(n))
                remaining -= n
        return ok(bytes_written=target_size, real_size=real_size)
    except OSError:
        return err(ERROR_FILE_IO)


def inspect_padded(input_path):
    try:
        total_size = os.path.getsize(input_path)
        with open(input_path, "rb") as f:
            magic = f.read(len(MAGIC_PADDED))
            if magic != MAGIC_PADDED:
                return err(ERROR_INVALID_ARCHIVE)
            raw_size = f.read(8)
            if len(raw_size) != 8:
                return err(ERROR_CORRUPT_INPUT)
            real_size = struct.unpack("<Q", raw_size)[0]
            if total_size < PAD_HEADER_SIZE + real_size:
                return err(ERROR_CORRUPT_INPUT)
            return ok(real_size=real_size, total_size=total_size)
    except OSError:
        return err(ERROR_FILE_IO)


def unpad_file(input_path, output_path):
    info = inspect_padded(input_path)
    if not info.get("ok"):
        return info

    real_size = info["real_size"]
    try:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            fin.seek(PAD_HEADER_SIZE, os.SEEK_SET)
            remaining = real_size
            while remaining > 0:
                to_read = CHUNK_SIZE if remaining > CHUNK_SIZE else int(remaining)
                chunk = fin.read(to_read)
                if len(chunk) != to_read:
                    return err(ERROR_CORRUPT_INPUT)
                fout.write(chunk)
                remaining -= len(chunk)
        return ok(bytes_written=real_size)
    except OSError:
        return err(ERROR_FILE_IO)


def handle(req):
    op = req.get("op")
    if op == "ping":
        return ok()
    if op == "pack_path":
        return pack_path(req.get("input_path", ""), req.get("output_path", ""))
    if op == "inspect_archive":
        return inspect_archive(req.get("input_path", ""))
    if op == "unpack_path":
        return unpack_path(req.get("input_path", ""), req.get("output_dir", ""))
    if op == "pad_file":
        return pad_file(req.get("input_path", ""), req.get("output_path", ""), req.get("target_size", 0))
    if op == "inspect_padded":
        return inspect_padded(req.get("input_path", ""))
    if op == "unpad_file":
        return unpad_file(req.get("input_path", ""), req.get("output_path", ""))
    return err(ERROR_UNKNOWN_OP)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(err(ERROR_BAD_JSON)) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()

