#!/usr/bin/env python3
import base64
import os
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, unquote

# -----------------------------
# Filesystem / sanitization
# -----------------------------

INVALID_FS_CHARS = r'<>:"\|?*'  # Windows-unsafe and generally annoying
MAX_SEG_LEN = 180

def safe_segment(seg: str) -> str:
    """
    Make a URL path segment safe for filesystem usage.
    """
    seg = unquote(seg or "")
    seg = seg.strip()
    if not seg:
        return "_"

    # Replace separators in-segment just in case
    seg = seg.replace("\\", "_").replace("/", "_")

    # Replace invalid characters
    seg = "".join("_" if c in INVALID_FS_CHARS else c for c in seg)

    # Compress whitespace
    seg = re.sub(r"\s+", " ", seg).strip()

    # Avoid absurdly long names
    if len(seg) > MAX_SEG_LEN:
        seg = seg[:MAX_SEG_LEN]

    # Avoid dot/empty edge cases
    if seg in {".", ".."}:
        seg = "_" + seg.replace(".", "_")

    return seg

def ensure_unique_path(path: str) -> str:
    """
    If path exists, add a suffix __2, __3, ...
    """
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    i = 2
    while True:
        candidate = f"{base}__{i}{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1

def ensure_dir(path: str):
    """
    Ensure `path` is a directory.

    If a file exists where we need a directory, convert it:
      path (file) -> path/ (dir) with moved file at path/index
    """
    if os.path.isdir(path):
        return

    if os.path.isfile(path):
        tmp = path + ".__file"
        os.rename(path, tmp)
        os.makedirs(path, exist_ok=True)
        # Put prior leaf content under index
        os.rename(tmp, os.path.join(path, "index"))
        return

    os.makedirs(path, exist_ok=True)

# -----------------------------
# Burp request/response parsing
# -----------------------------

def decode_maybe_b64(text: str) -> bytes:
    """
    Burp XML may store raw or base64. Try base64 first, otherwise treat as UTF-8 text.
    """
    if text is None:
        return b""
    t = text.strip()
    if not t:
        return b""
    try:
        # validate=True rejects non-b64 characters
        return base64.b64decode(t, validate=True)
    except Exception:
        return t.encode("utf-8", errors="replace")

def parse_status_and_ct_from_response(resp: bytes):
    """
    Extract HTTP status code and Content-Type from raw response (if present).
    """
    status = None
    ct = None
    try:
        if not resp:
            return None, None
        header_blob = resp.split(b"\r\n\r\n", 1)[0]
        lines = header_blob.split(b"\r\n")
        if lines:
            m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
            if m:
                status = int(m.group(1))
        for line in lines[1:]:
            if line.lower().startswith(b"content-type:"):
                ct = line.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                break
    except Exception:
        pass
    return status, ct

def guess_ext_from_content_type(ct: str) -> str:
    """
    Add a helpful extension when URL path has none.
    """
    if not ct:
        return ""
    ct = ct.lower().split(";")[0].strip()
    mapping = {
        "text/html": ".html",
        "application/xhtml+xml": ".html",
        "text/plain": ".txt",
        "text/css": ".css",
        "application/javascript": ".js",
        "text/javascript": ".js",
        "application/json": ".json",
        "application/xml": ".xml",
        "text/xml": ".xml",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "application/pdf": ".pdf",
    }
    return mapping.get(ct, "")

def split_headers_body(resp: bytes) -> tuple[bytes, bytes]:
    """
    Split raw HTTP response into headers and body if possible.
    """
    if not resp:
        return b"", b""
    if b"\r\n\r\n" in resp:
        h, b = resp.split(b"\r\n\r\n", 1)
        return h, b
    return resp, b""

def build_path_from_url(url: str):
    """
    Map URL -> (host_dir, dir_parts, filename, query)
    """
    p = urlparse(url)
    host = safe_segment(p.netloc or "unknown-host")

    raw_path = p.path or "/"
    raw_path = unquote(raw_path)

    is_dir = raw_path.endswith("/")
    parts = [safe_segment(x) for x in raw_path.split("/") if x != ""]

    if not parts:
        parts = ["index"]

    # If it ends with "/", treat it as a directory with index
    if is_dir:
        parts.append("index")

    # filename is last segment
    filename = parts[-1]
    dir_parts = parts[:-1]

    query = p.query or ""
    return host, dir_parts, filename, query

def ensure_parent_chain(root_dir: str, host: str, dir_parts: list[str]):
    """
    Create nested directory structure safely, handling file/dir collisions at any level.
    """
    cur = os.path.join(root_dir, host)
    ensure_dir(cur)

    for part in dir_parts:
        cur = os.path.join(cur, part)
        ensure_dir(cur)

    return cur

def write_bytes(path: str, data: bytes):
    ensure_dir(os.path.dirname(path))
    with open(path, "wb") as f:
        f.write(data)

def write_text(path: str, text: str):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(text)

# -----------------------------
# Main
# -----------------------------

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <burp_export.xml> <output_dir>", file=sys.stderr)
        sys.exit(1)

    xml_path = sys.argv[1]
    out_root = sys.argv[2]
    ensure_dir(out_root)

    tree = ET.parse(xml_path)
    xml_root = tree.getroot()

    items = xml_root.findall(".//item")
    if not items:
        print("No <item> nodes found. Is this a Burp 'Save selected items' XML?", file=sys.stderr)
        sys.exit(2)

    exported = 0
    skipped = 0

    for item in items:
        url_node = item.find("url")
        req_node = item.find("request")
        resp_node = item.find("response")

        if url_node is None or req_node is None:
            skipped += 1
            continue

        url = (url_node.text or "").strip()
        if not url:
            skipped += 1
            continue

        req_bytes = decode_maybe_b64(req_node.text or "")
        resp_bytes = decode_maybe_b64(resp_node.text or "") if resp_node is not None else b""

        status, ct = parse_status_and_ct_from_response(resp_bytes)

        host, dir_parts, filename, query = build_path_from_url(url)

        # Add extension if filename has none and we can infer from content-type
        if "." not in filename:
            ext = guess_ext_from_content_type(ct or "")
            if ext:
                filename = filename + ext

        # Query string gets appended to filename to avoid collisions
        if query:
            qsafe = safe_segment(query)
            base, ext = os.path.splitext(filename)
            filename = f"{base}__qs_{qsafe}{ext}"

        # Ensure directories exist (handling collisions)
        parent_dir = ensure_parent_chain(out_root, host, dir_parts)

        # Base output path for "mirrored" body file
        out_path = os.path.join(parent_dir, filename)
        out_path = ensure_unique_path(out_path)

        # Save response body at mirrored path
        _, resp_body = split_headers_body(resp_bytes)
        # If response wasn't raw HTTP, resp_body may be empty; fall back to full bytes.
        body_to_write = resp_body if resp_body else resp_bytes

        write_bytes(out_path, body_to_write)

        # Sidecars: raw request/response + meta
        write_bytes(out_path + ".__request.txt", req_bytes)
        if resp_bytes:
            write_bytes(out_path + ".__response.txt", resp_bytes)

        meta_lines = [f"URL: {url}"]
        if status is not None:
            meta_lines.append(f"HTTP Status: {status}")
        if ct:
            meta_lines.append(f"Content-Type: {ct}")
        write_text(out_path + ".__meta.txt", "\n".join(meta_lines) + "\n")

        exported += 1

    print(f"Exported {exported} items to: {out_root}")
    if skipped:
        print(f"Skipped {skipped} items (missing URL/request).")

if __name__ == "__main__":
    main()
