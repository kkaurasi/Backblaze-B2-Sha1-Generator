import os, mimetypes, hashlib, base64, zlib, threading, queue, tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "BZCalculator & CLI Command Generator"
CHUNK_SIZE = 8 * 1024 * 1024
B2_LARGE_THRESHOLD = 5 * 1024 * 1024

REGION_TO_ENDPOINT = {
    "us-west-000": "https://s3.us-west-000.backblazeb2.com",
    "us-west-001": "https://s3.us-west-001.backblazeb2.com",
    "us-west-002": "https://s3.us-west-002.backblazeb2.com",
    "eu-central-003": "https://s3.eu-central-003.backblazeb2.com",
    "us-west-004": "https://s3.us-west-004.backblazeb2.com",
    "us-east-005": "https://s3.us-east-005.backblazeb2.com",
    "ca-east-006": "https://s3.ca-east-006.backblazeb2.com",
}

def human_size(n: int) -> str:
    units = ["B","KB","MB","GB","TB"]
    i=0; f=float(n)
    while f>=1024 and i<len(units)-1:
        f/=1024.0; i+=1
    return f"{f:.2f} {units[i]}"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(1040, 810)

        # core state
        self.selected_path = ""
        self.sha1_hex = self.sha1_b64 = ""
        self.crc32_hex = self.crc32_b64 = ""
        self.md5_hex = self.md5_b64 = ""

        # worker infra
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self.worker = None

        self._build_ui()
        self._reset_all(init=True)
        self.after(100, self._poll_queue)

    # ---------- UI ----------
    def _build_ui(self):
        nb = ttk.Notebook(self); nb.pack(fill=tk.BOTH, expand=True)
        self.tab_calc = ttk.Frame(nb); nb.add(self.tab_calc, text="Bz Sha1 Calculator")
        self.tab_cli  = ttk.Frame(nb); nb.add(self.tab_cli,  text="CLI Examples")
        self.tab_verify = ttk.Frame(nb); nb.add(self.tab_verify, text="Verify")
        self._build_tab_calc(self.tab_calc)
        self._build_tab_cli(self.tab_cli)
        self._build_tab_verify(self.tab_verify)

    # ----- Tab 1 -----
    def _build_tab_calc(self, root):
        top = ttk.Frame(root, padding=(12,12)); top.pack(fill=tk.X)
        ttk.Label(top, text="File:").grid(row=0,column=0,sticky="w")
        self.var_path = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.var_path); ent.grid(row=0,column=1,sticky="ew",padx=(6,6))
        top.columnconfigure(1, weight=1)
        ttk.Button(top, text="Browse...", command=self._browse).grid(row=0,column=2)

        info = ttk.Frame(root, padding=(12,0)); info.pack(fill=tk.X)
        # file size box
        ttk.Label(info, text="File size:").pack(side=tk.LEFT)
        self.var_size = tk.StringVar()
        ttk.Entry(info, textvariable=self.var_size, state="readonly").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))
        ttk.Button(info, text="Copy", command=lambda: self._copy(self.var_size.get())).pack(side=tk.LEFT, padx=(6,0))

        self.var_large = tk.StringVar()
        ttk.Label(info, textvariable=self.var_large, foreground="#0a5").pack(side=tk.RIGHT)

        btns = ttk.Frame(root, padding=(12,8)); btns.pack(fill=tk.X)
        self.btn_calc = ttk.Button(btns, text="Calculate", command=self._start_calc); self.btn_calc.pack(side=tk.LEFT)
        self.btn_cancel = ttk.Button(btns, text="Cancel", state=tk.DISABLED, command=self._cancel); self.btn_cancel.pack(side=tk.LEFT, padx=(8,0))
        self.btn_reset = ttk.Button(btns, text="Reset", command=self._reset_all); self.btn_reset.pack(side=tk.LEFT, padx=(8,0))

        p = ttk.Frame(root, padding=(12,0)); p.pack(fill=tk.X)
        self.prog = ttk.Progressbar(p, orient="horizontal", mode="determinate"); self.prog.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,6))
        self.var_prog = tk.StringVar()
        ttk.Label(p, textvariable=self.var_prog, width=18).pack(side=tk.RIGHT)

        ttk.Separator(root).pack(fill=tk.X, pady=(8,8))

        out = ttk.Frame(root, padding=(12,0)); out.pack(fill=tk.BOTH, expand=True)

        # SHA-1
        ttk.Label(out, text="SHA-1 (hex, 40 chars) — B2 X-Bz-Content-Sha1").grid(row=0,column=0,sticky="w")
        self.var_hex = tk.StringVar(); ttk.Entry(out, textvariable=self.var_hex).grid(row=1,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_hex.get())).grid(row=1,column=1,padx=(6,0))

        ttk.Label(out, text="SHA-1 (base64) — S3 x-amz-checksum-sha1 / GetObject.ChecksumSHA1").grid(row=2,column=0,sticky="w",pady=(8,0))
        self.var_b64 = tk.StringVar(); ttk.Entry(out, textvariable=self.var_b64).grid(row=3,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_b64.get())).grid(row=3,column=1,padx=(6,0))

        # CRC32
        ttk.Label(out, text="CRC32 (hex, 8 chars)").grid(row=4,column=0,sticky="w",pady=(8,0))
        self.var_crc_hex = tk.StringVar(); ttk.Entry(out, textvariable=self.var_crc_hex).grid(row=5,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_crc_hex.get())).grid(row=5,column=1,padx=(6,0))

        ttk.Label(out, text="CRC32 (base64) — S3 x-amz-checksum-crc32 / GetObject.ChecksumCRC32").grid(row=6,column=0,sticky="w",pady=(8,0))
        self.var_crc_b64 = tk.StringVar(); ttk.Entry(out, textvariable=self.var_crc_b64).grid(row=7,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_crc_b64.get())).grid(row=7,column=1,padx=(6,0))

        # MD5
        ttk.Label(out, text="MD5 (hex, 32 chars) — Often equals S3 ETag for single-part uploads").grid(row=8,column=0,sticky="w",pady=(8,0))
        self.var_md5_hex = tk.StringVar(); ttk.Entry(out, textvariable=self.var_md5_hex).grid(row=9,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_md5_hex.get())).grid(row=9,column=1,padx=(6,0))

        ttk.Label(out, text="MD5 (base64)").grid(row=10,column=0,sticky="w",pady=(8,0))
        self.var_md5_b64 = tk.StringVar(); ttk.Entry(out, textvariable=self.var_md5_b64).grid(row=11,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_md5_b64.get())).grid(row=11,column=1,padx=(6,0))

        # Headers
        ttk.Label(out, text="B2 header (Native API):").grid(row=12,column=0,sticky="w",pady=(8,0))
        self.var_b2hdr = tk.StringVar(); ttk.Entry(out, textvariable=self.var_b2hdr).grid(row=13,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_b2hdr.get())).grid(row=13,column=1,padx=(6,0))

        ttk.Label(out, text="S3 header (PutObject, SHA-1):").grid(row=14,column=0,sticky="w",pady=(8,0))
        self.var_s3hdr = tk.StringVar(); ttk.Entry(out, textvariable=self.var_s3hdr).grid(row=15,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_s3hdr.get())).grid(row=15,column=1,padx=(6,0))

        ttk.Label(out, text="S3 header (PutObject, CRC32):").grid(row=16,column=0,sticky="w",pady=(8,0))
        self.var_s3crc = tk.StringVar(); ttk.Entry(out, textvariable=self.var_s3crc).grid(row=17,column=0,sticky="ew")
        ttk.Button(out, text="Copy", command=lambda: self._copy(self.var_s3crc.get())).grid(row=17,column=1,padx=(6,0))

        out.columnconfigure(0, weight=1)

    # ----- Tab 2 -----
    def _build_tab_cli(self, root):
        cfg = ttk.Labelframe(root, text="Inputs", padding=(12,12)); cfg.pack(fill=tk.X, padx=8, pady=8)
        self.var_bucket = tk.StringVar()
        self.var_key = tk.StringVar()

        ttk.Label(cfg, text="Selected file (from Tab 1):").grid(row=0,column=0,sticky="w")
        self.var_sel_display = tk.StringVar()
        ttk.Label(cfg, textvariable=self.var_sel_display, foreground="#555").grid(row=0,column=1,columnspan=3,sticky="w",padx=(6,0))

        ttk.Label(cfg, text="Bucket Name:").grid(row=1,column=0,sticky="e",pady=(6,0))
        ttk.Entry(cfg, textvariable=self.var_bucket, width=32).grid(row=1,column=1,sticky="w",pady=(6,0))

        ttk.Label(cfg, text="Region:").grid(row=1,column=2,sticky="e",pady=(6,0))
        self.var_region = tk.StringVar(value="us-west-004")
        cmb = ttk.Combobox(cfg, textvariable=self.var_region, values=list(REGION_TO_ENDPOINT.keys()), state="readonly", width=18)
        cmb.grid(row=1,column=3,sticky="w",pady=(6,0))

        ttk.Label(cfg, text="Key (object name):").grid(row=2,column=0,sticky="e",pady=(6,0))
        ttk.Entry(cfg, textvariable=self.var_key, width=32).grid(row=2,column=1,sticky="w",pady=(6,0))

        ttk.Button(cfg, text="Update", command=self._update_cli_outputs).grid(row=2,column=3,sticky="e")

        for i in range(4): cfg.columnconfigure(i, weight=1)

        wrap = ttk.Frame(root, padding=(8,0)); wrap.pack(fill=tk.BOTH, expand=True)

        ttk.Label(wrap, text="AWS CLI (S3-compatible on Backblaze B2)", font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        self.txt_s3 = tk.Text(wrap, height=22, wrap="word"); self.txt_s3.pack(fill=tk.BOTH, expand=True, padx=4)
        ttk.Button(wrap, text="Copy AWS CLI", command=lambda: self._copy(self.txt_s3.get('1.0','end').strip())).pack(anchor="e", padx=4, pady=(0,8))

        ttk.Label(wrap, text="B2 CLI (cliv4)", font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        self.txt_b2 = tk.Text(wrap, height=8, wrap="word"); self.txt_b2.pack(fill=tk.BOTH, expand=True, padx=4)
        ttk.Button(wrap, text="Copy B2 CLI", command=lambda: self._copy(self.txt_b2.get('1.0','end').strip())).pack(anchor="e", padx=4, pady=(0,8))

    # ----- Tab 3 -----
    def _build_tab_verify(self, root):
        wrap = ttk.Frame(root, padding=(8,8)); wrap.pack(fill=tk.BOTH, expand=True)

        ttk.Label(wrap, text="AWS S3API verification (download + local hashes)", font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        self.txt_v_s3 = tk.Text(wrap, height=12, wrap="word"); self.txt_v_s3.pack(fill=tk.BOTH, expand=True, padx=4)
        ttk.Button(wrap, text="Copy AWS Verify", command=lambda: self._copy(self.txt_v_s3.get('1.0','end').strip())).pack(anchor="e", padx=4, pady=(0,12))

        ttk.Separator(wrap).pack(fill=tk.X, pady=(4,12))

        ttk.Label(wrap, text="B2 native verification", font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        self.txt_v_b2 = tk.Text(wrap, height=6, wrap="word"); self.txt_v_b2.pack(fill=tk.BOTH, expand=True, padx=4)
        ttk.Button(wrap, text="Copy B2 Verify", command=lambda: self._copy(self.txt_v_b2.get('1.0','end').strip())).pack(anchor="e", padx=4, pady=(0,8))

    # ---------- actions ----------
    def _browse(self):
        p = filedialog.askopenfilename(title="Select a file to hash")
        if not p: return
        self.selected_path = p
        self.var_path.set(p)
        self.var_sel_display.set(p)
        self._update_size_hint(p)
        if not self.var_key.get():
            self.var_key.set(os.path.basename(p))
        self._update_cli_outputs()

    def _reset_all(self, init=False):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
        self.stop_event.clear()
        self.worker = None

        self.selected_path = ""
        self.sha1_hex = self.sha1_b64 = ""
        self.crc32_hex = self.crc32_b64 = ""
        self.md5_hex = self.md5_b64 = ""

        # calculator tab fields
        self.var_path.set("")
        self.var_size.set("—")
        self.var_large.set("")
        self.var_hex.set(""); self.var_b64.set("")
        self.var_crc_hex.set(""); self.var_crc_b64.set("")
        self.var_md5_hex.set(""); self.var_md5_b64.set("")
        self.var_b2hdr.set(""); self.var_s3hdr.set(""); self.var_s3crc.set("")
        self._set_progress(0,1,"")

        # cli inputs defaults
        self.var_sel_display.set("—")
        self.var_bucket.set("")
        self.var_region.set("us-west-004")
        self.var_key.set("")

        self.btn_calc.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)

        self._update_cli_outputs()
        if not init:
            messagebox.showinfo("Reset", "All fields have been reset to defaults.")

    def _update_size_hint(self, p):
        try:
            sz = os.path.getsize(p)
            self.var_size.set(f"{human_size(sz)} ({sz} bytes)")
            self.var_large.set("Large file (multipart)" if sz >= B2_LARGE_THRESHOLD else "")
        except Exception:
            self.var_size.set("—")
            self.var_large.set("")

    def _start_calc(self):
        p = self.var_path.get().strip()
        if not p or not os.path.isfile(p):
            messagebox.showerror("No file", "Please choose a valid file."); return
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "A calculation is already running."); return

        # clear outputs
        self.sha1_hex = self.sha1_b64 = self.crc32_hex = self.crc32_b64 = self.md5_hex = self.md5_b64 = ""
        self.var_hex.set(""); self.var_b64.set("")
        self.var_crc_hex.set(""); self.var_crc_b64.set("")
        self.var_md5_hex.set(""); self.var_md5_b64.set("")
        self.var_b2hdr.set(""); self.var_s3hdr.set(""); self.var_s3crc.set("")
        self._set_progress(0,1,"Starting…")
        self.stop_event.clear()
        self.btn_calc.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)

        self.worker = threading.Thread(target=self._hash_worker, args=(p,), daemon=True)
        self.worker.start()

    def _cancel(self):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()

    def _set_progress(self, done, total, label=""):
        self.prog['maximum'] = max(1,total)
        self.prog['value'] = done
        self.var_prog.set(label)

    def _hash_worker(self, p):
        total = os.path.getsize(p)
        sha = hashlib.sha1()
        md5 = hashlib.md5()
        crc = 0
        done = 0
        try:
            with open(p, "rb") as f:
                while True:
                    if self.stop_event.is_set():
                        self.queue.put(("cancelled",)); return
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    sha.update(chunk)
                    md5.update(chunk)
                    crc = zlib.crc32(chunk, crc) & 0xffffffff
                    done += len(chunk)
                    percent = int(done * 100 / max(1,total))
                    self.queue.put(("progress", done, total, f"{percent}%"))
        except Exception as e:
            self.queue.put(("error", str(e))); return

        sha_digest = sha.digest()
        md5_digest = md5.digest()
        sha_hex = sha_digest.hex()
        sha_b64 = base64.b64encode(sha_digest).decode("ascii")
        md5_hex = md5_digest.hex()
        md5_b64 = base64.b64encode(md5_digest).decode("ascii")
        crc_hex = f"{crc:08x}"
        crc_b64 = base64.b64encode(crc.to_bytes(4,'big')).decode("ascii")
        self.queue.put(("done", p, sha_hex, sha_b64, crc_hex, crc_b64, md5_hex, md5_b64))

    def _poll_queue(self):
        try:
            while True:
                tag, *rest = self.queue.get_nowait()
                if tag == "progress":
                    done, tot, label = rest; self._set_progress(done, tot, label)
                elif tag == "cancelled":
                    self._set_progress(0,1,"Cancelled"); self.btn_calc.config(state=tk.NORMAL); self.btn_cancel.config(state=tk.DISABLED)
                elif tag == "error":
                    err, = rest; messagebox.showerror("Error", err); self._set_progress(0,1,"Error"); self.btn_calc.config(state=tk.NORMAL); self.btn_cancel.config(state=tk.DISABLED)
                elif tag == "done":
                    p, sha_hex, sha_b64, crc_hex, crc_b64, md5_hex, md5_b64 = rest; self._on_hash_done(p, sha_hex, sha_b64, crc_hex, crc_b64, md5_hex, md5_b64)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _on_hash_done(self, p, sha_hex, sha_b64, crc_hex, crc_b64, md5_hex, md5_b64):
        self._set_progress(1,1,"Done")
        self.btn_calc.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)

        self.sha1_hex, self.sha1_b64 = sha_hex, sha_b64
        self.crc32_hex, self.crc32_b64 = crc_hex, crc_b64
        self.md5_hex, self.md5_b64 = md5_hex, md5_b64

        self.var_hex.set(sha_hex); self.var_b64.set(sha_b64)
        self.var_crc_hex.set(crc_hex); self.var_crc_b64.set(crc_b64)
        self.var_md5_hex.set(md5_hex); self.var_md5_b64.set(md5_b64)

        self.var_b2hdr.set(f"X-Bz-Content-Sha1: {sha_hex}")
        self.var_s3hdr.set(f"x-amz-checksum-sha1: {sha_b64}")
        self.var_s3crc.set(f"x-amz-checksum-crc32: {crc_b64}")

        self._update_size_hint(p)
        self._update_cli_outputs()

    def _copy(self, text):
        if not text: return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        messagebox.showinfo("Copied", "Copied to clipboard.")

    def _quote(self, s):
        s = str(s)
        if not s: return '""'
        if any(ch.isspace() for ch in s) or ('"' in s) or ("'" in s):
            return '"' + s.replace('"','\\"') + '"'
        return s

    def _guess_content_type(self, path):
        ctype, _ = mimetypes.guess_type(path)
        return ctype or "application/octet-stream"

    def _sanitize_filename(self, name):
        return "".join(c for c in name if c.isalnum() or c in ("-","_",".")).strip() or "download.bin"

    # ---------- compose outputs ----------
    def _update_cli_outputs(self):
        bucket = (self.var_bucket.get() or "<bucket>").strip()
        region = (self.var_region.get() or "us-west-004").strip()
        key    = (self.var_key.get()    or "<key>").strip()
        path   = self.selected_path or "<local/file>"

        endpoint_url = REGION_TO_ENDPOINT.get(region, f"https://s3.{region}.backblazeb2.com")

        have_sha = bool(self.sha1_hex and self.sha1_b64)
        hex40 = self.sha1_hex if have_sha else "<40-hex-sha1>"
        b64   = self.sha1_b64 if have_sha else "<base64-sha1>"

        have_crc = bool(self.crc32_hex and self.crc32_b64)
        crc_hex = self.crc32_hex if have_crc else "<8-hex-crc32>"
        crc_b64 = self.crc32_b64 if have_crc else "<base64-crc32>"

        have_md5 = bool(self.md5_hex and self.md5_b64)
        md5_hex = self.md5_hex if have_md5 else "<32-hex-md5>"
        md5_b64 = self.md5_b64 if have_md5 else "<base64-md5>"

        try:
            sz = os.path.getsize(self.selected_path) if self.selected_path else 0
        except Exception:
            sz = 0
        is_large = sz >= B2_LARGE_THRESHOLD

        content_type = self._guess_content_type(self.selected_path) if self.selected_path else "application/octet-stream"

        # AWS CLI examples
        lines = []
        lines.append("# AWS CLI (S3-compatible on Backblaze B2)")
        lines.append("## Option A: CLI computes SHA-1\n")
        lines.append("aws s3api put-object \\")
        lines.append(f"  --bucket {bucket} \\")
        lines.append(f"  --key {key} \\")
        lines.append(f"  --body {self._quote(path)} \\")
        lines.append(f"  --content-type {content_type} \\")
        lines.append(f"  --checksum-algorithm SHA1 \\")
        if sz > 0:
            lines.append(f"  --content-length {sz} \\")
        lines.append(f"  --region {region} \\")
        lines.append(f"  --endpoint-url {endpoint_url}")
        lines.append("")
        lines.append("## Option B: Precomputed SHA-1 (base64) + store metadata (SHA-1/CRC32/MD5)\n")
        lines.append("aws s3api put-object \\")
        lines.append(f"  --bucket {bucket} \\")
        lines.append(f"  --key {key} \\")
        lines.append(f"  --body {self._quote(path)} \\")
        lines.append(f"  --content-type {content_type} \\")
        meta_value = f"sha1hex={hex40},sha1b64={b64},crc32b64={crc_b64},crc32hex={crc_hex},md5b64={md5_b64},md5hex={md5_hex}"
        lines.append(f"  --metadata {self._quote(meta_value)} \\")
        lines.append(f"  --checksum-sha1 {self._quote(b64)} \\")
        if sz > 0:
            lines.append(f"  --content-length {sz} \\")
        lines.append(f"  --region {region} \\")
        lines.append(f"  --endpoint-url {endpoint_url}")
        if is_large:
            lines.append("")
            lines.append("## Option C: High-level transfer (multipart; no checksum fields on HEAD)\n")
            lines.append(f"aws s3 cp {self._quote(path)} s3://{bucket}/{key} \\")
            lines.append(f"  --content-type {content_type} \\")
            meta_value = f"sha1hex={hex40},sha1b64={b64},crc32b64={crc_b64},crc32hex={crc_hex},md5b64={md5_b64},md5hex={md5_hex}"
            lines.append(f"  --metadata {self._quote(meta_value)} \\")
            lines.append(f"  --checksum-sha1 {self._quote(b64)} \\")
            lines.append(f"  --region {region} \\")
            lines.append(f"  --endpoint-url {endpoint_url}")

        self.txt_s3.delete("1.0","end"); self.txt_s3.insert("1.0", "\n".join(lines))

        # B2 CLI one-liners
        b2_lines = []
        b2_lines.append("## Option A: B2 CLI computes SHA-1 (verified)")
        b2_lines.append(f"b2 file upload {bucket} {self._quote(path)} {self._quote(key)}")
        b2_lines.append("")
        b2_lines.append("## Option B: Provide explicit SHA-1 (hex)")
        b2_lines.append(f"b2 file upload --sha1 {hex40} {bucket} {self._quote(path)} {self._quote(key)}")
        self.txt_b2.delete("1.0","end"); self.txt_b2.insert("1.0","\n".join(b2_lines))

        self.var_sel_display.set(path)
        self._update_verify_outputs()

    def _update_verify_outputs(self):
        if not hasattr(self, "txt_v_s3"): return
        bucket = (self.var_bucket.get() or "<bucket>").strip()
        region = (self.var_region.get() or "us-west-004").strip()
        key    = (self.var_key.get()    or "<key>").strip()
        endpoint_url = REGION_TO_ENDPOINT.get(region, f"https://s3.{region}.backblazeb2.com")
        tmp = f"/tmp/{self._sanitize_filename(os.path.basename(key)) or 'download.bin'}"

        v_s3 = []
        v_s3.append("# Download and compute local SHA-1/CRC32/MD5")
        v_s3.append("aws s3api get-object \\")
        v_s3.append(f"  --bucket {bucket} --key {key} {self._quote(tmp)} \\")
        v_s3.append(f"  --region {region} \\")
        v_s3.append(f"  --endpoint-url {endpoint_url}")
        v_s3.append("")
        v_s3.append(f"openssl dgst -sha1 -binary {self._quote(tmp)} | base64")
        v_s3.append(f"python3 -c 'import sys,zlib,base64; d=open(sys.argv[1],\"rb\").read(); c=zlib.crc32(d)&0xffffffff; print(base64.b64encode(c.to_bytes(4,\"big\")).decode())' {self._quote(tmp)}")
        v_s3.append(f"python3 -c 'import sys,hashlib,base64; d=open(sys.argv[1],\"rb\").read(); m=hashlib.md5(d).digest(); print(m.hex()); print(base64.b64encode(m).decode())' {self._quote(tmp)}  # md5 hex then base64")
        v_s3.append("")
        v_s3.append("# Optional: checksums/ETag/metadata via GetObject (no file saved)")
        v_s3.append("aws s3api get-object \\")
        v_s3.append(f"  --bucket {bucket} --key {key} /dev/null \\")
        v_s3.append(f"  --query '{{ChecksumSHA1:ChecksumSHA1, ChecksumCRC32:ChecksumCRC32, ETag:ETag, Metadata:Metadata}}' \\")
        v_s3.append(f"  --region {region} \\")
        v_s3.append(f"  --endpoint-url {endpoint_url}")

        self.txt_v_s3.delete("1.0","end"); self.txt_v_s3.insert("1.0","\n".join(v_s3))

        v_b2 = f"b2 file info b2://{bucket}/{key}"
        self.txt_v_b2.delete("1.0","end"); self.txt_v_b2.insert("1.0", v_b2)

if __name__ == "__main__":
    app = App()
    app.mainloop()
