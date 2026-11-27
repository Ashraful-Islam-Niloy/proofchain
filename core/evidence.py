import hashlib, os, shutil, uuid

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def copy_into_evidence(src_path: str, evidence_dir: str):
    os.makedirs(evidence_dir, exist_ok=True)
    digest = sha256_file(src_path)
    ext = os.path.splitext(src_path)[1]
    dest_name = f"{uuid.uuid4().hex}{ext}"
    dest = os.path.join(evidence_dir, dest_name)
    shutil.copy2(src_path, dest)
    return dest, digest
