"""
Secure Banking System — Graphical User Interface
=================================================
Run with:  python gui.py

Requires:  Python 3.10+  (no external libraries)
Uses:      tkinter (built-in), all project modules
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import os
import sys
import io

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ca.certificate_authority  import CertificateAuthority
from network.bank_server        import BankServer
from network.bank_client        import BankClient
from symmetric.xtea             import xtea_encrypt_cbc, xtea_decrypt_cbc, handwritten_demo as xtea_demo
from symmetric.twofish          import twofish_encrypt_cbc, twofish_decrypt_cbc
from asymmetric.elgamal         import handwritten_demo as elgamal_demo
from symmetric.file_encryptor   import encrypt_file, decrypt_file


# ─────────────────────────────────────────────────────────────
#  THEME
# ─────────────────────────────────────────────────────────────
BG_DARK    = "#0D1117"
BG_PANEL   = "#161B22"
BG_CARD    = "#21262D"
BG_INPUT   = "#0D1117"
BORDER     = "#30363D"
ACCENT     = "#2F81F7"
ACCENT2    = "#3FB950"
ACCENT3    = "#F78166"
ACCENT4    = "#D2A8FF"
TEXT_PRI   = "#E6EDF3"
TEXT_SEC   = "#8B949E"
TEXT_MUTED = "#484F58"
GOLD       = "#E3B341"
FONT_MAIN  = ("Consolas", 10)
FONT_HEAD  = ("Consolas", 13, "bold")
FONT_TITLE = ("Consolas", 11, "bold")
FONT_SMALL = ("Consolas", 9)
FONT_MONO  = ("Courier New", 9)


# ─────────────────────────────────────────────────────────────
#  GLOBAL STATE
# ─────────────────────────────────────────────────────────────
_ca     = None
_server = None
_clients = {}   # name → BankClient


# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────

def _log(widget, msg, tag="info"):
    """Append a line to a ScrolledText log widget."""
    widget.configure(state="normal")
    ts = time.strftime("%H:%M:%S")
    prefix = {"info": "  ●  ", "ok": "  ✔  ", "err": "  ✘  ",
              "warn": "  ⚠  ", "head": "\n  ══ ", "tx": "  ▶  "}.get(tag, "     ")
    widget.insert(tk.END, f"[{ts}]{prefix}{msg}\n", tag)
    widget.see(tk.END)
    widget.configure(state="disabled")


def _clear(widget):
    widget.configure(state="normal")
    widget.delete("1.0", tk.END)
    widget.configure(state="disabled")


def _card(parent, title="", padx=16, pady=12):
    """Styled card frame with optional title."""
    outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
    inner = tk.Frame(outer, bg=BG_CARD, padx=padx, pady=pady)
    inner.pack(fill="both", expand=True)
    if title:
        tk.Label(inner, text=title, bg=BG_CARD, fg=TEXT_SEC,
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 6))
    return outer, inner


def _btn(parent, text, cmd, color=ACCENT, width=18):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=color, fg=TEXT_PRI, activebackground=color,
                  activeforeground=TEXT_PRI, relief="flat", cursor="hand2",
                  font=FONT_MAIN, padx=10, pady=6, width=width, bd=0)
    return b


def _entry(parent, placeholder="", width=24, show=None):
    e = tk.Entry(parent, bg=BG_INPUT, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                 relief="flat", font=FONT_MAIN, width=width,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BORDER, show=show or "")
    if placeholder:
        e.insert(0, placeholder)
        e.config(fg=TEXT_MUTED)
        def on_focus_in(event):
            if e.get() == placeholder:
                e.delete(0, tk.END)
                e.config(fg=TEXT_PRI)
        def on_focus_out(event):
            if not e.get():
                e.insert(0, placeholder)
                e.config(fg=TEXT_MUTED)
        e.bind("<FocusIn>",  on_focus_in)
        e.bind("<FocusOut>", on_focus_out)
    return e


def _label(parent, text, fg=TEXT_SEC, font=FONT_SMALL, **kw):
    return tk.Label(parent, text=text, bg=BG_CARD, fg=fg, font=font, **kw)


def _log_widget(parent, height=14):
    st = scrolledtext.ScrolledText(
        parent, bg=BG_INPUT, fg=TEXT_PRI, font=FONT_MONO,
        relief="flat", state="disabled", height=height,
        insertbackground=TEXT_PRI,
        highlightthickness=1, highlightbackground=BORDER,
        selectbackground=ACCENT, wrap=tk.WORD)
    st.tag_config("ok",   foreground=ACCENT2)
    st.tag_config("err",  foreground=ACCENT3)
    st.tag_config("warn", foreground=GOLD)
    st.tag_config("head", foreground=ACCENT4, font=("Courier New", 9, "bold"))
    st.tag_config("tx",   foreground=ACCENT)
    st.tag_config("info", foreground=TEXT_PRI)
    return st


def _run_in_thread(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


# ─────────────────────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────────────────────

class SecureBankApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🏦  Secure Banking System  —  Cryptography Project")
        self.configure(bg=BG_DARK)
        self.geometry("1100x740")
        self.minsize(960, 680)
        self._style()
        self._build_ui()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",        background=BG_PANEL, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",    background=BG_CARD,  foreground=TEXT_SEC,
                        font=FONT_MAIN, padding=(18, 8), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG_DARK)],
                  foreground=[("selected", ACCENT)])
        style.configure("TCombobox",        fieldbackground=BG_INPUT, background=BG_INPUT,
                        foreground=TEXT_PRI, arrowcolor=TEXT_SEC, bordercolor=BORDER,
                        lightcolor=BG_INPUT, darkcolor=BG_INPUT)
        style.map("TCombobox", fieldbackground=[("readonly", BG_INPUT)])
        style.configure("Vertical.TScrollbar", background=BG_CARD, troughcolor=BG_INPUT,
                        arrowcolor=TEXT_MUTED, borderwidth=0)

    def _build_ui(self):
        # ── TOP BAR ───────────────────────────────────────────
        bar = tk.Frame(self, bg=BG_PANEL, height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(bar, text="  🏦  SECURE BANKING SYSTEM",
                 bg=BG_PANEL, fg=TEXT_PRI, font=("Consolas", 13, "bold")).pack(side="left", padx=8)
        tk.Label(bar, text="Cryptography Project  ·  XTEA + Twofish + ElGamal",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=FONT_SMALL).pack(side="left", padx=4)

        self._status_lbl = tk.Label(bar, text="●  System offline",
                                    bg=BG_PANEL, fg=ACCENT3, font=FONT_SMALL)
        self._status_lbl.pack(side="right", padx=16)

        # ── SEPARATOR ─────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── NOTEBOOK TABS ─────────────────────────────────────
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_setup   = self._build_tab_setup(nb)
        self._tab_tx      = self._build_tab_transactions(nb)
        self._tab_file    = self._build_tab_files(nb)
        self._tab_verify  = self._build_tab_verification(nb)
        self._tab_session = self._build_tab_session(nb)
        self._tab_bench   = self._build_tab_benchmarks(nb)
        self._tab_log     = self._build_tab_auditlog(nb)

        nb.add(self._tab_setup,   text="  ⚙  System Setup  ")
        nb.add(self._tab_tx,      text="  💳  Transactions  ")
        nb.add(self._tab_file,    text="  🔒  File Encryptor  ")
        nb.add(self._tab_verify,  text="  ✍  Verification  ")
        nb.add(self._tab_session, text="  🔑  Session Protocol  ")
        nb.add(self._tab_bench,   text="  📊  Benchmarks  ")
        nb.add(self._tab_log,     text="  📋  Audit Log  ")

    # ─────────────────────────────────────────────────────────
    #  TAB 1 — SYSTEM SETUP
    # ─────────────────────────────────────────────────────────

    def _build_tab_setup(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=320)
        left.pack(side="left", fill="y", padx=(16,8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0,16), pady=16)

        # ── CA Card ───────────────────────────────────────────
        outer, ca_card = _card(left, "CERTIFICATE AUTHORITY")
        outer.pack(fill="x", pady=(0, 10))

        _label(ca_card, "CA Name", fg=TEXT_SEC).pack(anchor="w")
        self._ca_name = _entry(ca_card, "SecureBank-RootCA", width=26)
        self._ca_name.pack(anchor="w", pady=(2, 10))

        _label(ca_card, "Key Size (bits)", fg=TEXT_SEC).pack(anchor="w")
        self._ca_bits = ttk.Combobox(ca_card, values=["64","128","256"],
                                      width=10, state="readonly")
        self._ca_bits.set("128")
        self._ca_bits.pack(anchor="w", pady=(2, 10))

        _btn(ca_card, "⚡  Initialize CA", self._init_ca,
             color="#1F2D4A", width=22).pack(pady=(4, 0))

        # ── Server Card ───────────────────────────────────────
        outer2, srv_card = _card(left, "BANK SERVER")
        outer2.pack(fill="x", pady=(0, 10))

        _label(srv_card, "Server Name", fg=TEXT_SEC).pack(anchor="w")
        self._srv_name = _entry(srv_card, "BankServer-Primary", width=26)
        self._srv_name.pack(anchor="w", pady=(2, 10))

        _btn(srv_card, "🏦  Initialize Server", self._init_server,
             color="#1F3D2A", width=22).pack(pady=(4, 0))

        # ── Client Card ───────────────────────────────────────
        outer3, cli_card = _card(left, "REGISTER CLIENT")
        outer3.pack(fill="x", pady=(0, 10))

        _label(cli_card, "Client Name", fg=TEXT_SEC).pack(anchor="w")
        self._cli_name = _entry(cli_card, "Alice", width=26)
        self._cli_name.pack(anchor="w", pady=(2, 10))

        _btn(cli_card, "👤  Register Client", self._register_client,
             color="#2D1F3D", width=22).pack(pady=(2, 0))

        # Registered clients list
        _label(cli_card, "Registered Clients", fg=TEXT_SEC).pack(anchor="w", pady=(12, 2))
        self._clients_box = tk.Listbox(cli_card, bg=BG_INPUT, fg=ACCENT2,
                                        font=FONT_MONO, height=4, relief="flat",
                                        highlightthickness=1, highlightbackground=BORDER,
                                        selectbackground=ACCENT)
        self._clients_box.pack(fill="x")

        # ── Handshake Card ────────────────────────────────────
        outer4, hs_card = _card(left, "TLS HANDSHAKE")
        outer4.pack(fill="x")

        _label(hs_card, "Select Client", fg=TEXT_SEC).pack(anchor="w")
        self._hs_client = ttk.Combobox(hs_card, values=[], width=22, state="readonly")
        self._hs_client.pack(anchor="w", pady=(2, 10))

        _btn(hs_card, "🔐  Perform Handshake", self._do_handshake,
             color="#3D2A1F", width=22).pack()

        # ── Right: Terminal log ───────────────────────────────
        outer5, log_card = _card(right, "SYSTEM LOG")
        outer5.pack(fill="both", expand=True)

        self._setup_log = _log_widget(log_card, height=28)
        self._setup_log.pack(fill="both", expand=True)

        btn_row = tk.Frame(log_card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(8, 0))
        _btn(btn_row, "🚀  Run Full Demo", self._run_full_demo,
             color="#1A3A5C", width=18).pack(side="left", padx=(0, 8))
        _btn(btn_row, "🗑  Clear Log", lambda: _clear(self._setup_log),
             color=BG_INPUT, width=12).pack(side="left")

        return tab

    def _init_ca(self):
        def _run():
            global _ca
            _log(self._setup_log, "Initialising Certificate Authority...", "head")
            try:
                bits = int(self._ca_bits.get())
                name = self._ca_name.get()
                _ca  = CertificateAuthority(name=name, bits=bits)
                _log(self._setup_log, f"CA '{name}' created successfully", "ok")
                _log(self._setup_log, f"Public key (y): {hex(_ca.public_key['y'])[:32]}...", "info")
                self._status_lbl.config(text="●  CA online", fg=GOLD)
            except Exception as e:
                _log(self._setup_log, f"CA init failed: {e}", "err")
        _run_in_thread(_run)

    def _init_server(self):
        def _run():
            global _server
            if not _ca:
                _log(self._setup_log, "Initialize the CA first!", "err"); return
            _log(self._setup_log, "Starting Bank Server...", "head")
            try:
                name    = self._srv_name.get()
                _server = BankServer(ca=_ca, name=name)
                _log(self._setup_log, f"Server '{name}' online", "ok")
                _log(self._setup_log, f"Certificate #{_server.certificate['serial']} issued by CA", "ok")
                _log(self._setup_log, "Account store encrypted with Twofish (at rest)", "ok")
                self._status_lbl.config(text="●  Server online", fg=ACCENT2)
            except Exception as e:
                _log(self._setup_log, f"Server init failed: {e}", "err")
        _run_in_thread(_run)

    def _do_handshake(self):
        def _run():
            if not _server:
                _log(self._setup_log, "Initialize the server first!", "err"); return
            name = self._hs_client.get()
            if not name or name not in _clients:
                _log(self._setup_log, "Select a registered client", "err"); return
            _log(self._setup_log, f"Starting TLS handshake for {name}...", "head")
            try:
                client = _clients[name]
                ok     = client.perform_handshake(_server)
                if ok:
                    _log(self._setup_log, f"Handshake with {name} complete", "ok")
                    _log(self._setup_log, f"Session key: {client._session_key.hex()[:16]}...", "info")
                    _log(self._setup_log, "All transactions will now be XTEA-encrypted", "ok")
                    self._status_lbl.config(text="●  All systems online", fg=ACCENT2)
                    # refresh session tab dropdowns
                    self._session_update_clients()
                else:
                    _log(self._setup_log, "Handshake FAILED", "err")
            except Exception as e:
                _log(self._setup_log, f"Handshake error: {e}", "err")
        _run_in_thread(_run)

    # ─────────────────────────────────────────────────────────
    #  TAB 2 — TRANSACTIONS
    # ─────────────────────────────────────────────────────────

    def _build_tab_transactions(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=310)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        # ── Client selector ───────────────────────────────────
        outer, sess_card = _card(left, "ACTIVE SESSION")
        outer.pack(fill="x", pady=(0, 10))
        _label(sess_card, "Acting as Client", fg=TEXT_SEC).pack(anchor="w")
        self._tx_client = ttk.Combobox(sess_card, values=[], width=22, state="readonly")
        self._tx_client.pack(anchor="w", pady=(2, 0))

        # ── Balance card ──────────────────────────────────────
        outer2, bal_card = _card(left, "BALANCE INQUIRY")
        outer2.pack(fill="x", pady=(0, 10))
        _label(bal_card, "Account ID", fg=TEXT_SEC).pack(anchor="w")
        self._bal_acc = _entry(bal_card, "ACC-001", width=22)
        self._bal_acc.pack(anchor="w", pady=(2, 10))
        _btn(bal_card, "📊  Check Balance", self._check_balance,
             color="#1A3A5C", width=22).pack()

        # ── Transfer card ─────────────────────────────────────
        outer3, tx_card = _card(left, "FUND TRANSFER")
        outer3.pack(fill="x", pady=(0, 10))
        _label(tx_card, "From Account", fg=TEXT_SEC).pack(anchor="w")
        self._tx_from = _entry(tx_card, "ACC-001", width=22)
        self._tx_from.pack(anchor="w", pady=(2, 8))
        _label(tx_card, "To Account", fg=TEXT_SEC).pack(anchor="w")
        self._tx_to = _entry(tx_card, "ACC-002", width=22)
        self._tx_to.pack(anchor="w", pady=(2, 8))
        _label(tx_card, "Amount (£)", fg=TEXT_SEC).pack(anchor="w")
        self._tx_amount = _entry(tx_card, "1000.00", width=22)
        self._tx_amount.pack(anchor="w", pady=(2, 10))
        _btn(tx_card, "💸  Transfer Funds", self._do_transfer,
             color="#1F3D2A", width=22).pack()

        # ── Key rotation ──────────────────────────────────────
        outer4, key_card = _card(left, "KEY MANAGEMENT")
        outer4.pack(fill="x")
        _btn(key_card, "🔄  Rotate Session Key", self._rotate_key,
             color="#2D2A1F", width=22).pack(pady=(0, 6))
        _btn(key_card, "🔍  Verify Certificate", self._verify_cert,
             color="#1F2A3D", width=22).pack()

        # ── Right: transaction log ────────────────────────────
        outer5, log_card = _card(right, "TRANSACTION LOG")
        outer5.pack(fill="both", expand=True)

        # Live balance display
        bal_frame = tk.Frame(log_card, bg=BG_CARD)
        bal_frame.pack(fill="x", pady=(0, 10))

        self._bal_acc1 = self._mini_account(bal_frame, "ACC-001", "Alice",    "£50,000.00")
        self._bal_acc1.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._bal_acc2 = self._mini_account(bal_frame, "ACC-002", "Bob",      "£25,000.00")
        self._bal_acc2.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._bal_acc3 = self._mini_account(bal_frame, "ACC-003", "Charlie",  "£75,000.00")
        self._bal_acc3.pack(side="left", fill="x", expand=True)

        self._tx_log = _log_widget(log_card, height=16)
        self._tx_log.pack(fill="both", expand=True)

        _btn(log_card, "🗑  Clear", lambda: _clear(self._tx_log),
             color=BG_INPUT, width=10).pack(anchor="e", pady=(6, 0))

        return tab

    def _mini_account(self, parent, acc_id, owner, balance):
        f = tk.Frame(parent, bg=BG_INPUT, padx=10, pady=8,
                     highlightthickness=1, highlightbackground=BORDER)
        tk.Label(f, text=acc_id, bg=BG_INPUT, fg=TEXT_MUTED, font=FONT_SMALL).pack(anchor="w")
        tk.Label(f, text=owner,  bg=BG_INPUT, fg=TEXT_SEC,   font=FONT_MAIN).pack(anchor="w")
        lbl = tk.Label(f, text=balance, bg=BG_INPUT, fg=ACCENT2,
                       font=("Consolas", 11, "bold"))
        lbl.pack(anchor="w")
        f._bal_label = lbl
        return f

    def _check_balance(self):
        def _run():
            name = self._tx_client.get()
            if not name or name not in _clients:
                _log(self._tx_log, "Register and handshake a client first", "err"); return
            if not _server:
                _log(self._tx_log, "Initialize server first", "err"); return
            acc = self._bal_acc.get()
            _log(self._tx_log, f"{name} → Balance inquiry: {acc}", "tx")
            try:
                r = _clients[name].check_balance(_server, acc)
                if r.get("status") == "OK":
                    bal = r.get("balance", "?")
                    cur = r.get("currency", "")
                    own = r.get("owner", "")
                    _log(self._tx_log, f"Account: {acc}  Owner: {own}", "ok")
                    _log(self._tx_log, f"Balance: {cur} {bal:,.2f}", "ok")
                    self._update_balance_display(acc, bal, cur)
                else:
                    _log(self._tx_log, f"Error: {r.get('reason')}", "err")
            except Exception as e:
                _log(self._tx_log, f"Error: {e}", "err")
        _run_in_thread(_run)

    def _do_transfer(self):
        def _run():
            name = self._tx_client.get()
            if not name or name not in _clients:
                _log(self._tx_log, "Register and handshake a client first", "err"); return
            frm = self._tx_from.get()
            to  = self._tx_to.get()
            try:
                amt = float(self._tx_amount.get())
            except ValueError:
                _log(self._tx_log, "Invalid amount", "err"); return
            _log(self._tx_log, f"{name} → Transfer £{amt:,.2f} from {frm} to {to}", "tx")
            try:
                r = _clients[name].transfer(_server, frm, to, amt)
                if r.get("status") == "OK":
                    _log(self._tx_log, f"Transfer APPROVED", "ok")
                    _log(self._tx_log, f"New balance ({frm}): £{r.get('new_balance',0):,.2f}", "ok")
                    # Refresh balances
                    for acc_id in ["ACC-001", "ACC-002", "ACC-003"]:
                        r2 = _clients[name].check_balance(_server, acc_id)
                        if r2.get("status") == "OK":
                            self._update_balance_display(acc_id, r2["balance"], r2["currency"])
                else:
                    _log(self._tx_log, f"Transfer REJECTED: {r.get('reason')}", "err")
            except Exception as e:
                _log(self._tx_log, f"Error: {e}", "err")
        _run_in_thread(_run)

    def _update_balance_display(self, acc_id, balance, currency):
        mapping = {"ACC-001": self._bal_acc1,
                   "ACC-002": self._bal_acc2,
                   "ACC-003": self._bal_acc3}
        if acc_id in mapping:
            lbl = mapping[acc_id]._bal_label
            lbl.config(text=f"£{balance:,.2f}")

    def _rotate_key(self):
        def _run():
            name = self._tx_client.get()
            if not name or not _server:
                _log(self._tx_log, "Setup required first", "err"); return
            client_id = f"CLIENT:{name}"
            try:
                _server.rotate_session_key(client_id)
                _log(self._tx_log, f"Session key rotated for {name}", "ok")
                _log(self._tx_log, "New key will be used for subsequent transactions", "info")
            except Exception as e:
                _log(self._tx_log, f"Rotation failed: {e}", "err")
        _run_in_thread(_run)

    def _verify_cert(self):
        def _run():
            name = self._tx_client.get()
            if not name or name not in _clients:
                _log(self._tx_log, "Select a client", "err"); return
            client = _clients[name]
            _log(self._tx_log, f"Validating certificate for {name}...", "tx")
            valid = _ca.validate_certificate(client.certificate)
            _log(self._tx_log,
                 f"Certificate #{client.certificate['serial']}: {'VALID' if valid else 'INVALID'}",
                 "ok" if valid else "err")
        _run_in_thread(_run)

    # ─────────────────────────────────────────────────────────
    #  TAB 3 — FILE ENCRYPTOR
    # ─────────────────────────────────────────────────────────

    def _build_tab_files(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=310)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        # ── Encrypt card ──────────────────────────────────────
        outer, enc_card = _card(left, "ENCRYPT FILE")
        outer.pack(fill="x", pady=(0, 10))

        _label(enc_card, "Input File", fg=TEXT_SEC).pack(anchor="w")
        row = tk.Frame(enc_card, bg=BG_CARD)
        row.pack(fill="x", pady=(2, 8))
        self._enc_in = _entry(row, "select file...", width=18)
        self._enc_in.pack(side="left")
        _btn(row, "📂", lambda: self._browse(self._enc_in),
             color=BG_INPUT, width=3).pack(side="left", padx=(4, 0))

        _label(enc_card, "Output File", fg=TEXT_SEC).pack(anchor="w")
        row2 = tk.Frame(enc_card, bg=BG_CARD)
        row2.pack(fill="x", pady=(2, 8))
        self._enc_out = _entry(row2, "output.enc", width=18)
        self._enc_out.pack(side="left")
        _btn(row2, "📂", lambda: self._browse_save(self._enc_out),
             color=BG_INPUT, width=3).pack(side="left", padx=(4, 0))

        _label(enc_card, "Algorithm", fg=TEXT_SEC).pack(anchor="w")
        self._enc_algo = ttk.Combobox(enc_card,
                                       values=["twofish (at-rest, banking-grade)",
                                               "xtea (fast, session tokens)"],
                                       width=26, state="readonly")
        self._enc_algo.set("twofish (at-rest, banking-grade)")
        self._enc_algo.pack(anchor="w", pady=(2, 8))

        _label(enc_card, "Password", fg=TEXT_SEC).pack(anchor="w")
        self._enc_pass = _entry(enc_card, "SecureBankPass123!", width=26, show="•")
        self._enc_pass.config(show="")
        self._enc_pass.pack(anchor="w", pady=(2, 10))

        _btn(enc_card, "🔒  Encrypt File", self._do_encrypt, color="#1F3D2A", width=22).pack()

        # ── Decrypt card ──────────────────────────────────────
        outer2, dec_card = _card(left, "DECRYPT FILE")
        outer2.pack(fill="x", pady=(0, 10))

        _label(dec_card, "Encrypted File", fg=TEXT_SEC).pack(anchor="w")
        row3 = tk.Frame(dec_card, bg=BG_CARD)
        row3.pack(fill="x", pady=(2, 8))
        self._dec_in = _entry(row3, "select .enc file...", width=18)
        self._dec_in.pack(side="left")
        _btn(row3, "📂", lambda: self._browse(self._dec_in),
             color=BG_INPUT, width=3).pack(side="left", padx=(4, 0))

        _label(dec_card, "Output File", fg=TEXT_SEC).pack(anchor="w")
        row4 = tk.Frame(dec_card, bg=BG_CARD)
        row4.pack(fill="x", pady=(2, 8))
        self._dec_out = _entry(row4, "decrypted.txt", width=18)
        self._dec_out.pack(side="left")
        _btn(row4, "📂", lambda: self._browse_save(self._dec_out),
             color=BG_INPUT, width=3).pack(side="left", padx=(4, 0))

        _label(dec_card, "Password", fg=TEXT_SEC).pack(anchor="w")
        self._dec_pass = _entry(dec_card, "password", width=26)
        self._dec_pass.pack(anchor="w", pady=(2, 10))

        _btn(dec_card, "🔓  Decrypt File", self._do_decrypt, color="#1A3A5C", width=22).pack()

        # ── Right: Preview ────────────────────────────────────
        outer3, prev_card = _card(right, "FILE PREVIEW / RESULTS")
        outer3.pack(fill="both", expand=True)

        self._file_log = _log_widget(prev_card, height=10)
        self._file_log.pack(fill="both", expand=True)

        _label(prev_card, "File Contents Preview", fg=TEXT_SEC).pack(anchor="w", pady=(10, 4))
        self._file_preview = scrolledtext.ScrolledText(
            prev_card, bg=BG_INPUT, fg=ACCENT2, font=FONT_MONO,
            relief="flat", height=10, wrap=tk.WORD,
            highlightthickness=1, highlightbackground=BORDER)
        self._file_preview.pack(fill="both", expand=True)

        return tab

    def _browse(self, entry_widget):
        path = filedialog.askopenfilename()
        if path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, path)
            entry_widget.config(fg=TEXT_PRI)

    def _browse_save(self, entry_widget):
        path = filedialog.asksaveasfilename()
        if path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, path)
            entry_widget.config(fg=TEXT_PRI)

    def _do_encrypt(self):
        def _run():
            inp  = self._enc_in.get()
            out  = self._enc_out.get()
            pw   = self._enc_pass.get()
            algo = "xtea" if "xtea" in self._enc_algo.get() else "twofish"
            if not os.path.exists(inp):
                _log(self._file_log, f"File not found: {inp}", "err"); return
            _log(self._file_log, f"Encrypting '{inp}' → '{out}'  [{algo.upper()}]", "tx")
            try:
                r = encrypt_file(inp, out, pw, algo)
                _log(self._file_log, f"Algorithm:   {r['algorithm'].upper()}", "ok")
                _log(self._file_log, f"Plaintext:   {r['plaintext_size']} bytes", "info")
                _log(self._file_log, f"Ciphertext:  {r['ciphertext_size']} bytes", "info")
                _log(self._file_log, f"Ratio:       {r['ratio']}x", "info")
                _log(self._file_log, f"Time:        {r['encrypt_ms']} ms", "ok")
                # Show hex preview
                with open(out, "rb") as f:
                    raw = f.read(128)
                self._file_preview.delete("1.0", tk.END)
                self._file_preview.insert(tk.END, "── CIPHERTEXT (first 128 bytes, hex) ──\n")
                self._file_preview.insert(tk.END, raw.hex())
            except Exception as e:
                _log(self._file_log, f"Encryption failed: {e}", "err")
        _run_in_thread(_run)

    def _do_decrypt(self):
        def _run():
            inp = self._dec_in.get()
            out = self._dec_out.get()
            pw  = self._dec_pass.get()
            if not os.path.exists(inp):
                _log(self._file_log, f"File not found: {inp}", "err"); return
            _log(self._file_log, f"Decrypting '{inp}' → '{out}'", "tx")
            try:
                r = decrypt_file(inp, out, pw)
                _log(self._file_log, f"Algorithm:  {r['algorithm'].upper()}", "ok")
                _log(self._file_log, f"Output:     {r['output_size']} bytes", "info")
                _log(self._file_log, f"Time:       {r['decrypt_ms']} ms", "ok")
                with open(out, "r", errors="replace") as f:
                    content = f.read(1000)
                self._file_preview.delete("1.0", tk.END)
                self._file_preview.insert(tk.END, "── DECRYPTED CONTENT ──\n")
                self._file_preview.insert(tk.END, content)
            except Exception as e:
                _log(self._file_log, f"Decryption failed: {e}", "err")
        _run_in_thread(_run)

    # ─────────────────────────────────────────────────────────
    #  TAB 4 — HANDWRITTEN VERIFICATION
    # ─────────────────────────────────────────────────────────

    def _build_tab_verification(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=260)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        # ── XTEA params card ──────────────────────────────────
        outer, xt_card = _card(left, "XTEA PARAMETERS")
        outer.pack(fill="x", pady=(0, 10))

        fields = [("Key[0]", "0x00000001"), ("Key[1]", "0x00000002"),
                  ("Key[2]", "0x00000003"), ("Key[3]", "0x00000004"),
                  ("v0",     "0x00000001"), ("v1",     "0x00000002"),
                  ("Rounds", "2")]
        self._xtea_entries = {}
        for label, default in fields:
            _label(xt_card, label, fg=TEXT_SEC).pack(anchor="w")
            e = _entry(xt_card, default, width=22)
            e.pack(anchor="w", pady=(1, 6))
            self._xtea_entries[label] = e

        _btn(xt_card, "▶  Run XTEA Trace", self._run_xtea_verify,
             color="#1A3A5C", width=22).pack(pady=(4, 0))

        # ── ElGamal params card ───────────────────────────────
        outer2, eg_card = _card(left, "ELGAMAL PARAMETERS")
        outer2.pack(fill="x")

        eg_fields = [("p (prime)", "23"), ("g (generator)", "5"),
                     ("x (private)", "6"), ("m (message)", "10"),
                     ("k (ephemeral)", "3")]
        self._eg_entries = {}
        for label, default in eg_fields:
            _label(eg_card, label, fg=TEXT_SEC).pack(anchor="w")
            e = _entry(eg_card, default, width=22)
            e.pack(anchor="w", pady=(1, 6))
            self._eg_entries[label] = e

        _btn(eg_card, "▶  Run ElGamal Trace", self._run_eg_verify,
             color="#1F3D2A", width=22).pack(pady=(4, 0))

        # ── Right: Output ─────────────────────────────────────
        outer3, out_card = _card(right, "VERIFICATION TRACE  —  suitable for handwritten submission")
        outer3.pack(fill="both", expand=True)

        self._verify_log = _log_widget(out_card, height=28)
        self._verify_log.pack(fill="both", expand=True)

        btn_row = tk.Frame(out_card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(8, 0))
        _btn(btn_row, "▶▶  Run Both", self._run_both_verify,
             color="#2D1F3D", width=14).pack(side="left", padx=(0, 8))
        _btn(btn_row, "📋  Copy", self._copy_verify,
             color=BG_INPUT, width=10).pack(side="left", padx=(0, 8))
        _btn(btn_row, "🗑  Clear", lambda: _clear(self._verify_log),
             color=BG_INPUT, width=10).pack(side="left")

        return tab

    def _run_xtea_verify(self):
        def _run():
            try:
                k0 = int(self._xtea_entries["Key[0]"].get(), 16)
                k1 = int(self._xtea_entries["Key[1]"].get(), 16)
                k2 = int(self._xtea_entries["Key[2]"].get(), 16)
                k3 = int(self._xtea_entries["Key[3]"].get(), 16)
                v0 = int(self._xtea_entries["v0"].get(), 16)
                v1 = int(self._xtea_entries["v1"].get(), 16)
                nr = int(self._xtea_entries["Rounds"].get())
            except ValueError:
                _log(self._verify_log, "Invalid input — use hex values like 0x00000001", "err"); return

            DELTA  = 0x9E3779B9
            MASK32 = 0xFFFFFFFF
            key    = [k0, k1, k2, k3]
            total  = 0

            _log(self._verify_log, "XTEA ENCRYPTION TRACE", "head")
            _log(self._verify_log, f"  Key     : {[hex(k) for k in key]}", "info")
            _log(self._verify_log, f"  Input   : v0={hex(v0)}  v1={hex(v1)}", "info")
            _log(self._verify_log, f"  Rounds  : {nr}", "info")
            _log(self._verify_log, f"  DELTA   : {hex(DELTA)}", "info")

            orig_v0, orig_v1 = v0, v1
            for r in range(1, nr + 1):
                total  = (total + DELTA) & MASK32
                v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & MASK32
                v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32
                _log(self._verify_log,
                     f"  Round {r:>2}: sum={hex(total):<14} v0={hex(v0):<14} v1={hex(v1)}", "ok")

            enc_v0, enc_v1 = v0, v1
            _log(self._verify_log, f"\n  Ciphertext : v0={hex(enc_v0)}  v1={hex(enc_v1)}", "tx")

            _log(self._verify_log, "\nXTEA DECRYPTION TRACE", "head")
            total = (DELTA * nr) & MASK32
            for r in range(1, nr + 1):
                v1    = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & MASK32
                v0    = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & MASK32
                total = (total - DELTA) & MASK32
                _log(self._verify_log,
                     f"  Round {r:>2}: sum={hex(total):<14} v0={hex(v0):<14} v1={hex(v1)}", "ok")

            match = (v0 == orig_v0 and v1 == orig_v1)
            _log(self._verify_log,
                 f"\n  Recovered: v0={hex(v0)}  v1={hex(v1)}", "tx")
            _log(self._verify_log,
                 f"  Match original? {'✔ YES' if match else '✘ NO'}",
                 "ok" if match else "err")
        _run_in_thread(_run)

    def _run_eg_verify(self):
        def _run():
            from asymmetric.elgamal import _mod_exp, _mod_inverse
            try:
                p = int(self._eg_entries["p (prime)"].get())
                g = int(self._eg_entries["g (generator)"].get())
                x = int(self._eg_entries["x (private)"].get())
                m = int(self._eg_entries["m (message)"].get())
                k = int(self._eg_entries["k (ephemeral)"].get())
            except ValueError:
                _log(self._verify_log, "Invalid input — use integers", "err"); return

            y  = _mod_exp(g, x, p)
            c1 = _mod_exp(g, k, p)
            c2 = (m * _mod_exp(y, k, p)) % p
            s  = _mod_exp(c1, x, p)
            s_inv = _mod_inverse(s, p)
            m_rec = (c2 * s_inv) % p

            _log(self._verify_log, "ELGAMAL ENCRYPTION TRACE", "head")
            _log(self._verify_log, f"  Domain    : p={p}  g={g}", "info")
            _log(self._verify_log, f"  Private   : x={x}", "info")
            _log(self._verify_log, f"  Public    : y = {g}^{x} mod {p} = {y}", "ok")
            _log(self._verify_log, f"  Message   : m={m}", "info")
            _log(self._verify_log, f"  Ephemeral : k={k}", "info")

            _log(self._verify_log, "\nENCRYPTION", "head")
            _log(self._verify_log, f"  c1 = g^k mod p  =  {g}^{k} mod {p}  =  {c1}", "ok")
            _log(self._verify_log,
                 f"  c2 = m * y^k mod p  =  {m} * {y}^{k} mod {p}  =  {c2}", "ok")
            _log(self._verify_log, f"  Ciphertext: ({c1}, {c2})", "tx")

            _log(self._verify_log, "\nDECRYPTION", "head")
            _log(self._verify_log,
                 f"  s     = c1^x mod p  =  {c1}^{x} mod {p}  =  {s}", "ok")
            _log(self._verify_log,
                 f"  s_inv = {s}^(-1) mod {p}  =  {s_inv}  (since {s}×{s_inv} mod {p} = {(s*s_inv)%p})", "ok")
            _log(self._verify_log,
                 f"  m     = c2 * s_inv mod p  =  {c2} × {s_inv} mod {p}  =  {m_rec}", "ok")
            _log(self._verify_log,
                 f"\n  Match original? {'✔ YES' if m_rec == m else '✘ NO'}",
                 "ok" if m_rec == m else "err")
        _run_in_thread(_run)

    def _run_both_verify(self):
        _clear(self._verify_log)
        self._run_xtea_verify()
        time.sleep(0.1)
        self._run_eg_verify()

    def _copy_verify(self):
        content = self._verify_log.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(content)
        _log(self._verify_log, "Copied to clipboard", "ok")

    # ─────────────────────────────────────────────────────────
    #  TAB 5 — BENCHMARKS
    # ─────────────────────────────────────────────────────────

    def _build_tab_benchmarks(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=260)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        outer, ctrl_card = _card(left, "BENCHMARK CONTROLS")
        outer.pack(fill="x", pady=(0, 10))

        _label(ctrl_card, "Algorithm", fg=TEXT_SEC).pack(anchor="w")
        self._bench_algo = ttk.Combobox(ctrl_card,
                                         values=["XTEA-CBC", "Twofish-CBC", "Both"],
                                         width=22, state="readonly")
        self._bench_algo.set("Both")
        self._bench_algo.pack(anchor="w", pady=(2, 10))

        _label(ctrl_card, "Payload Size", fg=TEXT_SEC).pack(anchor="w")
        self._bench_size = ttk.Combobox(ctrl_card,
                                         values=["64 bytes", "256 bytes", "1 KB",
                                                 "10 KB", "50 KB", "All sizes"],
                                         width=22, state="readonly")
        self._bench_size.set("All sizes")
        self._bench_size.pack(anchor="w", pady=(2, 10))

        _label(ctrl_card, "Iterations", fg=TEXT_SEC).pack(anchor="w")
        self._bench_iters = ttk.Combobox(ctrl_card, values=["1", "3", "5"],
                                          width=10, state="readonly")
        self._bench_iters.set("1")
        self._bench_iters.pack(anchor="w", pady=(2, 10))

        _btn(ctrl_card, "▶  Run Benchmark", self._run_bench,
             color="#1A3A5C", width=22).pack(pady=(4, 0))

        outer2, tip_card = _card(left, "NOTE")
        outer2.pack(fill="x")
        _label(tip_card,
               "Pure-Python implementations\nare slower than C-based\nlibraries by design.\n\n"
               "This demonstrates the\nalgorithms from scratch\nwithout any libraries.",
               fg=TEXT_SEC, justify="left").pack(anchor="w")

        # Right
        outer3, bench_card = _card(right, "RESULTS")
        outer3.pack(fill="both", expand=True)
        self._bench_log = _log_widget(bench_card, height=28)
        self._bench_log.pack(fill="both", expand=True)

        return tab

    def _run_bench(self):
        def _run():
            import time as _time
            algo  = self._bench_algo.get()
            size_sel = self._bench_size.get()
            iters = int(self._bench_iters.get())
            key   = os.urandom(16)

            size_map = {
                "64 bytes": [64], "256 bytes": [256], "1 KB": [1024],
                "10 KB": [10240], "50 KB": [51200],
                "All sizes": [64, 256, 1024, 10240, 51200]
            }
            sizes = size_map.get(size_sel, [1024])

            _clear(self._bench_log)
            _log(self._bench_log, "BENCHMARK RESULTS", "head")
            _log(self._bench_log,
                 f"  {'Algorithm':<14} {'Payload':>8}  {'Enc ms':>9}  {'Dec ms':>9}  {'CT/PT':>7}",
                 "info")
            _log(self._bench_log, "  " + "─" * 55, "info")

            algos = []
            if algo in ("XTEA-CBC", "Both"):    algos.append(("XTEA",    xtea_encrypt_cbc,    xtea_decrypt_cbc))
            if algo in ("Twofish-CBC", "Both"): algos.append(("Twofish", twofish_encrypt_cbc, twofish_decrypt_cbc))

            for name, enc_fn, dec_fn in algos:
                for sz in sizes:
                    data = b"X" * sz
                    enc_times, dec_times = [], []
                    for _ in range(iters):
                        t0 = _time.perf_counter()
                        ct = enc_fn(data, key)
                        enc_times.append((_time.perf_counter() - t0) * 1000)
                        t0 = _time.perf_counter()
                        dec_fn(ct, key)
                        dec_times.append((_time.perf_counter() - t0) * 1000)

                    enc_ms = sum(enc_times) / len(enc_times)
                    dec_ms = sum(dec_times) / len(dec_times)
                    ratio  = len(ct) / sz
                    label  = f"{sz} B" if sz < 1024 else f"{sz//1024} KB"
                    _log(self._bench_log,
                         f"  {name+'-CBC':<14} {label:>8}   {enc_ms:>8.4f}   {dec_ms:>8.4f}   {ratio:>6.4f}",
                         "ok")

            _log(self._bench_log, "\nINSIGHTS", "head")
            _log(self._bench_log, "  XTEA  → best for high-frequency in-transit data (fast)", "info")
            _log(self._bench_log, "  Twofish → best for at-rest storage (stronger security)", "info")
            _log(self._bench_log, "  Both expand ciphertext by ≤ 1 block (minimal overhead)", "info")
        _run_in_thread(_run)

    # ─────────────────────────────────────────────────────────
    #  TAB 6 — AUDIT LOG
    # ─────────────────────────────────────────────────────────

    def _build_tab_auditlog(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK, padx=16, pady=16)

        top_row = tk.Frame(tab, bg=BG_DARK)
        top_row.pack(fill="x", pady=(0, 10))
        tk.Label(top_row, text="SERVER AUDIT LOG", bg=BG_DARK, fg=TEXT_SEC,
                 font=FONT_SMALL).pack(side="left")
        _btn(top_row, "🔄  Refresh", self._refresh_audit,
             color=ACCENT, width=12).pack(side="right")
        _btn(top_row, "🗑  Clear Display", lambda: _clear(self._audit_log),
             color=BG_INPUT, width=14).pack(side="right", padx=(0, 8))

        outer, audit_card = _card(tab)
        outer.pack(fill="both", expand=True)

        # Summary row
        self._audit_summary = tk.Frame(audit_card, bg=BG_CARD)
        self._audit_summary.pack(fill="x", pady=(0, 10))

        self._audit_total = self._stat_box(self._audit_summary, "0", "Total Transactions")
        self._audit_total.pack(side="left", padx=(0, 8))
        self._audit_ok    = self._stat_box(self._audit_summary, "0", "Approved", ACCENT2)
        self._audit_ok.pack(side="left", padx=(0, 8))
        self._audit_err   = self._stat_box(self._audit_summary, "0", "Rejected", ACCENT3)
        self._audit_err.pack(side="left")

        self._audit_log = _log_widget(audit_card, height=24)
        self._audit_log.pack(fill="both", expand=True)

        return tab

    def _stat_box(self, parent, value, label, color=ACCENT):
        f = tk.Frame(parent, bg=BG_INPUT, padx=14, pady=8,
                     highlightthickness=1, highlightbackground=BORDER)
        n = tk.Label(f, text=value, bg=BG_INPUT, fg=color,
                     font=("Consolas", 18, "bold"))
        n.pack()
        tk.Label(f, text=label, bg=BG_INPUT, fg=TEXT_MUTED,
                 font=FONT_SMALL).pack()
        f._num_label = n
        return f

    def _refresh_audit(self):
        if not _server:
            messagebox.showinfo("Info", "Initialize the server first (System Setup tab).")
            return
        _clear(self._audit_log)
        log = _server.get_audit_log()

        ok_count  = sum(1 for e in log if e["result"] == "OK")
        err_count = sum(1 for e in log if e["result"] != "OK")

        self._audit_total._num_label.config(text=str(len(log)))
        self._audit_ok._num_label.config(text=str(ok_count))
        self._audit_err._num_label.config(text=str(err_count))

        _log(self._audit_log, f"AUDIT LOG — {len(log)} entries", "head")
        _log(self._audit_log,
             f"  {'#':<4} {'Timestamp':<12} {'Client':<18} {'Type':<10} {'Result':<8} {'Detail'}",
             "info")
        _log(self._audit_log, "  " + "─" * 70, "info")

        for i, entry in enumerate(log, 1):
            ts     = time.strftime("%H:%M:%S", time.localtime(entry["timestamp"]))
            client = entry["client"].replace("CLIENT:", "")
            tx     = entry["tx"]
            typ    = tx.get("type", "?")
            result = entry["result"]
            detail = ""
            if typ == "TRANSFER":
                detail = f"{tx.get('from')} → {tx.get('to')}  £{tx.get('amount',0):,.2f}"
            elif typ == "BALANCE":
                detail = f"Account: {tx.get('account')}"
            tag = "ok" if result == "OK" else "err"
            _log(self._audit_log,
                 f"  {i:<4} {ts:<12} {client:<18} {typ:<10} {result:<8} {detail}", tag)


    # ─────────────────────────────────────────────────────────
    #  TAB 5 — SESSION KEY ESTABLISHMENT PROTOCOL
    # ─────────────────────────────────────────────────────────

    def _build_tab_session(self, parent):
        tab = tk.Frame(parent, bg=BG_DARK)

        left = tk.Frame(tab, bg=BG_DARK, width=310)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(tab, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        # ── Protocol info card ────────────────────────────────
        outer0, info_card = _card(left, "PROTOCOL REFERENCE")
        outer0.pack(fill="x", pady=(0, 10))

        steps = [
            ("Step 1", "Server → Client",  "Certificate + public key"),
            ("Step 2", "Client validates", "CA verifies server cert"),
            ("Step 3", "Client generates", "Fresh 128-bit session key"),
            ("Step 4", "Client → Server",  "ElGamal-encrypted key"),
            ("Step 5", "Server → Client",  "XTEA-encrypted ACK"),
        ]
        for step, who, desc in steps:
            row = tk.Frame(info_card, bg=BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=step, bg=BG_CARD, fg=ACCENT4,
                     font=("Consolas", 8, "bold"), width=7, anchor="w").pack(side="left")
            tk.Label(row, text=who, bg=BG_CARD, fg=TEXT_SEC,
                     font=FONT_SMALL, width=14, anchor="w").pack(side="left")
            tk.Label(row, text=desc, bg=BG_CARD, fg=TEXT_MUTED,
                     font=FONT_SMALL, anchor="w").pack(side="left")

        # ── Dynamicity demo card ──────────────────────────────
        outer1, dyn_card = _card(left, "DYNAMICITY DEMONSTRATION")
        outer1.pack(fill="x", pady=(0, 10))

        _label(dyn_card,
               "Proves the same client + server\nproduce a DIFFERENT session key\non every protocol execution.",
               fg=TEXT_SEC, justify="left").pack(anchor="w", pady=(0, 8))

        _label(dyn_card, "Client", fg=TEXT_SEC).pack(anchor="w")
        self._dyn_client = ttk.Combobox(dyn_card, values=[], width=22, state="readonly")
        self._dyn_client.pack(anchor="w", pady=(2, 10))

        _label(dyn_card, "Executions to run", fg=TEXT_SEC).pack(anchor="w")
        self._dyn_runs = ttk.Combobox(dyn_card, values=["2", "3", "4"],
                                       width=10, state="readonly")
        self._dyn_runs.set("2")
        self._dyn_runs.pack(anchor="w", pady=(2, 10))

        _btn(dyn_card, "▶  Run Dynamicity Test",
             self._run_dynamicity, color="#2D1F3D", width=22).pack(pady=(0, 4))

        # ── Auto-rotation demo card ───────────────────────────
        outer2, rot_card = _card(left, "AUTO KEY ROTATION DEMO")
        outer2.pack(fill="x", pady=(0, 10))

        _label(rot_card,
               "Sends N transactions and watches\nthe server auto-rotate the key\nevery 5 transactions.",
               fg=TEXT_SEC, justify="left").pack(anchor="w", pady=(0, 8))

        _label(rot_card, "Client", fg=TEXT_SEC).pack(anchor="w")
        self._rot_client = ttk.Combobox(rot_card, values=[], width=22, state="readonly")
        self._rot_client.pack(anchor="w", pady=(2, 10))

        _label(rot_card, "Transactions to send", fg=TEXT_SEC).pack(anchor="w")
        self._rot_count = ttk.Combobox(rot_card, values=["5", "10", "12", "15"],
                                        width=10, state="readonly")
        self._rot_count.set("12")
        self._rot_count.pack(anchor="w", pady=(2, 10))

        _btn(rot_card, "▶  Run Rotation Demo",
             self._run_rotation_demo, color="#1F3D2A", width=22).pack(pady=(0, 4))

        # ── Session summary card ──────────────────────────────
        outer3, sum_card = _card(left, "SESSION SUMMARY")
        outer3.pack(fill="x")

        _label(sum_card, "Client", fg=TEXT_SEC).pack(anchor="w")
        self._sum_client = ttk.Combobox(sum_card, values=[], width=22, state="readonly")
        self._sum_client.pack(anchor="w", pady=(2, 10))

        _btn(sum_card, "📋  Show Key History",
             self._show_session_summary, color="#1A3A5C", width=22).pack()

        # ── Right panel ───────────────────────────────────────
        right_top = tk.Frame(right, bg=BG_DARK)
        right_top.pack(fill="x", pady=(0, 10))

        # Key comparison boxes
        outer4, cmp_card = _card(right_top)
        outer4.pack(fill="x")

        tk.Label(cmp_card,
                 text="SESSION KEY COMPARISON  —  Visual Dynamicity Proof",
                 bg=BG_CARD, fg=TEXT_SEC, font=FONT_SMALL).pack(anchor="w", pady=(0, 8))

        cmp_row = tk.Frame(cmp_card, bg=BG_CARD)
        cmp_row.pack(fill="x")

        # Up to 4 key boxes side by side
        self._key_boxes = []
        for i in range(4):
            box = tk.Frame(cmp_row, bg=BG_INPUT, padx=12, pady=10,
                           highlightthickness=1, highlightbackground=BORDER)
            box.pack(side="left", fill="x", expand=True,
                     padx=(0, 6) if i < 3 else 0)

            tk.Label(box, text=f"Execution {i+1}", bg=BG_INPUT,
                     fg=TEXT_MUTED, font=FONT_SMALL).pack(anchor="w")

            key_lbl = tk.Label(box, text="—", bg=BG_INPUT,
                               fg=TEXT_MUTED, font=("Courier New", 9, "bold"),
                               wraplength=130, justify="left")
            key_lbl.pack(anchor="w", pady=(4, 2))

            status_lbl = tk.Label(box, text="", bg=BG_INPUT,
                                  fg=TEXT_MUTED, font=FONT_SMALL)
            status_lbl.pack(anchor="w")

            self._key_boxes.append((box, key_lbl, status_lbl))

        # Verdict banner
        self._verdict_frame = tk.Frame(cmp_card, bg=BG_CARD)
        self._verdict_frame.pack(fill="x", pady=(10, 0))
        self._verdict_lbl = tk.Label(
            self._verdict_frame,
            text="Run the dynamicity test to see results",
            bg=BG_CARD, fg=TEXT_MUTED, font=FONT_MAIN)
        self._verdict_lbl.pack()

        # Protocol trace log
        outer5, log_card = _card(right, "PROTOCOL TRACE LOG")
        outer5.pack(fill="both", expand=True)

        self._session_log = _log_widget(log_card, height=18)
        self._session_log.pack(fill="both", expand=True)

        btn_row = tk.Frame(log_card, bg=BG_CARD)
        btn_row.pack(fill="x", pady=(8, 0))
        _btn(btn_row, "📋  Copy Log", self._copy_session_log,
             color=BG_INPUT, width=12).pack(side="left", padx=(0, 8))
        _btn(btn_row, "🗑  Clear", lambda: _clear(self._session_log),
             color=BG_INPUT, width=10).pack(side="left")

        return tab

    # ── Session tab helpers ───────────────────────────────────

    def _session_update_clients(self):
        """Refresh client dropdowns on the session tab."""
        vals = list(_clients.keys())
        for cb in [self._dyn_client, self._rot_client, self._sum_client]:
            cb["values"] = vals
            if vals and not cb.get():
                cb.set(vals[0])

    def _run_dynamicity(self):
        """Run the handshake N times with the same client+server and compare keys."""
        def _run():
            name = self._dyn_client.get()
            if not name or name not in _clients:
                _log(self._session_log, "Register a client first (System Setup tab)", "err")
                return
            if not _server:
                _log(self._session_log, "Initialize the server first", "err")
                return

            runs    = int(self._dyn_runs.get())
            client  = _clients[name]
            keys    = []

            _clear(self._session_log)
            _log(self._session_log,
                 f"DYNAMICITY TEST — {runs} executions of the session key protocol", "head")
            _log(self._session_log,
                 f"Same parties: CLIENT:{name}  ↔  {_server.name}", "info")
            _log(self._session_log,
                 "Goal: prove every execution yields a DIFFERENT shared secret\n", "info")

            # Reset all key boxes
            for box, key_lbl, status_lbl in self._key_boxes:
                key_lbl.config(text="—", fg=TEXT_MUTED)
                status_lbl.config(text="", fg=TEXT_MUTED)
                box.config(highlightbackground=BORDER)

            for i in range(runs):
                _log(self._session_log,
                     f"── EXECUTION {i+1}  ──────────────────────────────────", "head")

                # Step 1
                _log(self._session_log,
                     f"[STEP 1] Server sends certificate #{_server.certificate['serial']}", "info")

                # Step 2
                _log(self._session_log,
                     f"[STEP 2] Client validates server cert with CA...", "info")

                # Step 3 — the key moment
                _log(self._session_log,
                     f"[STEP 3] Client calls random.getrandbits(128)  ← SOURCE OF DYNAMICITY", "warn")

                # Actually run the handshake
                ok = client.perform_handshake(_server)

                if ok:
                    key_hex = client._session_key.hex()
                    keys.append(key_hex)

                    _log(self._session_log,
                         f"[STEP 4] Session key encrypted via ElGamal → sent to server", "info")
                    _log(self._session_log,
                         f"[STEP 5] Server ACK decrypted — handshake confirmed", "info")
                    _log(self._session_log,
                         f"         Session key {i+1}: {key_hex[:16]}...{key_hex[-8:]}", "ok")

                    # Update key box if within 4
                    if i < 4:
                        box, key_lbl, status_lbl = self._key_boxes[i]
                        key_lbl.config(
                            text=f"{key_hex[:16]}\n{key_hex[16:32]}\n{key_hex[32:]}",
                            fg=ACCENT2)
                        status_lbl.config(text="✔ Generated", fg=ACCENT2)
                        box.config(highlightbackground=ACCENT2)
                else:
                    _log(self._session_log, f"Execution {i+1} FAILED", "err")

            # ── Verdict ───────────────────────────────────────
            _log(self._session_log, "\n── DYNAMICITY VERDICT ─────────────────────────────", "head")

            if len(keys) < 2:
                _log(self._session_log, "Not enough successful handshakes to compare", "warn")
                return

            all_unique = len(set(keys)) == len(keys)

            for i, k in enumerate(keys):
                _log(self._session_log, f"  Key {i+1}: {k}", "info")

            _log(self._session_log, "", "info")

            if all_unique:
                _log(self._session_log,
                     f"  ✔ ALL {len(keys)} KEYS ARE DISTINCT — DYNAMICITY CONFIRMED", "ok")
                _log(self._session_log,
                     "  Interpretation: Compromising key N gives zero information", "ok")
                _log(self._session_log,
                     "  about keys 1…N-1 or N+1…∞. Sessions are isolated.", "ok")

                # Update boxes to show uniqueness
                for i, (box, key_lbl, status_lbl) in enumerate(self._key_boxes[:len(keys)]):
                    status_lbl.config(text="✔ Unique", fg=ACCENT2)

                self._verdict_lbl.config(
                    text=f"✔  DYNAMICITY CONFIRMED  —  {len(keys)} independent keys generated",
                    fg=ACCENT2, font=("Consolas", 11, "bold"))
                self._verdict_frame.config(bg=BG_CARD)
            else:
                _log(self._session_log, "  ❌ DUPLICATE KEY DETECTED — BUG IN RNG", "err")
                self._verdict_lbl.config(
                    text="❌  DUPLICATE KEY DETECTED  —  RNG failure",
                    fg=ACCENT3, font=("Consolas", 11, "bold"))

            # Update rotation demo dropdowns too
            self._session_update_clients()

        _run_in_thread(_run)

    def _run_rotation_demo(self):
        """Send N transactions and show auto key rotation happening every 5."""
        def _run():
            name = self._rot_client.get()
            if not name or name not in _clients:
                _log(self._session_log, "Register and handshake a client first", "err")
                return
            if not _server:
                _log(self._session_log, "Initialize the server first", "err")
                return

            client    = _clients[name]
            client_id = f"CLIENT:{name}"
            n_tx      = int(self._rot_count.get())

            if client._session_key is None:
                _log(self._session_log,
                     f"No session for {name} — run handshake first (System Setup tab)", "err")
                return

            _clear(self._session_log)
            _log(self._session_log,
                 f"AUTO KEY ROTATION DEMO — sending {n_tx} transactions", "head")
            _log(self._session_log,
                 f"Rotation interval: every {5} transactions", "info")
            _log(self._session_log,
                 f"Motivation 1: limits ciphertext per key  "
                 f"Motivation 2: isolates compromise exposure\n", "info")

            prev_key   = client._session_key.hex()
            rotations  = 0

            for i in range(1, n_tx + 1):
                result = client.check_balance(_server, "ACC-001")
                curr_key = _server.get_session_key_history(client_id)
                curr_hex = curr_key[-1] if curr_key else prev_key

                rotated = (curr_hex != prev_key)

                if rotated:
                    rotations += 1
                    _log(self._session_log,
                         f"  Tx {i:>2}  ✔  "
                         f"{'ROTATION #' + str(rotations) + ' TRIGGERED':^30}  "
                         f"new key: {curr_hex[:12]}...", "warn")
                    _log(self._session_log,
                         f"        old: {prev_key[:16]}...  →  "
                         f"new: {curr_hex[:16]}...", "info")
                else:
                    _log(self._session_log,
                         f"  Tx {i:>2}  ✔  "
                         f"{'key unchanged':^30}  "
                         f"key: {curr_hex[:12]}...", "ok")

                prev_key = curr_hex

            _log(self._session_log, "\n── ROTATION SUMMARY ───────────────────────────────", "head")
            hist = _server.get_session_key_history(client_id)
            _log(self._session_log,
                 f"  Transactions sent : {n_tx}", "info")
            _log(self._session_log,
                 f"  Keys rotated      : {rotations}", "info")
            _log(self._session_log,
                 f"  Total keys used   : {len(hist)}", "info")
            _log(self._session_log,
                 f"  Max CT per key    : {5} transactions  (Motivation 1)", "info")
            _log(self._session_log,
                 f"  Compromise scope  : at most {5} transactions exposed per key  (Motivation 2)", "ok")
            _log(self._session_log,
                 f"  Key storage needed: 0 pre-stored keys  (Motivation 3 — on-demand)", "ok")

            _log(self._session_log, "\n  All keys used (proving on-demand generation):", "head")
            for j, k in enumerate(hist):
                label = "initial  " if j == 0 else f"rotation #{j}"
                _log(self._session_log, f"    [{label}]  {k[:32]}...", "info")

        _run_in_thread(_run)

    def _show_session_summary(self):
        """Fetch and display the session key history from the server."""
        def _run():
            name = self._sum_client.get()
            if not name or not _server:
                _log(self._session_log, "Setup required first", "err")
                return

            client_id = f"CLIENT:{name}"
            _log(self._session_log,
                 f"SESSION SUMMARY — {client_id}", "head")

            hist = _server.get_session_key_history(client_id)
            if not hist:
                _log(self._session_log,
                     "No session history found. Perform a handshake first.", "warn")
                return

            _log(self._session_log,
                 f"  Total keys generated : {len(hist)}  "
                 f"(1 initial + {len(hist)-1} rotations)", "info")
            _log(self._session_log,
                 f"  All distinct?        : "
                 f"{'✔ YES — dynamicity confirmed' if len(set(hist))==len(hist) else '❌ NO — BUG'}",
                 "ok" if len(set(hist)) == len(hist) else "err")
            _log(self._session_log, "", "info")

            for j, k in enumerate(hist):
                label = "Initial   " if j == 0 else f"Rotation #{j}"
                _log(self._session_log, f"  [{label}]  {k}", "info")

            _log(self._session_log,
                 "\n  Motivation 3 — No key was pre-stored or pre-distributed.", "ok")
            _log(self._session_log,
                 "  Each key was created on-demand when the session or rotation occurred.", "ok")

        _run_in_thread(_run)

    def _copy_session_log(self):
        content = self._session_log.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(content)
        _log(self._session_log, "Copied to clipboard", "ok")

    # ── Override register client to also refresh session tab ──

    def _register_client(self):
        def _run():
            if not _ca:
                _log(self._setup_log, "Initialize the CA first!", "err"); return
            name = self._cli_name.get().strip()
            if not name or name == "Alice":
                name = "Alice"
            if name in _clients:
                _log(self._setup_log, f"Client '{name}' already registered", "warn"); return
            _log(self._setup_log, f"Registering client: {name}...", "head")
            try:
                c = BankClient(name=name, ca=_ca)
                _clients[name] = c
                _log(self._setup_log, f"Client '{name}' registered", "ok")
                _log(self._setup_log, f"Certificate #{c.certificate['serial']} issued", "ok")
                self._clients_box.insert(tk.END, f"  {name}  (cert #{c.certificate['serial']})")
                vals = list(_clients.keys())
                for cb in [self._hs_client, self._tx_client,
                           self._dyn_client, self._rot_client, self._sum_client]:
                    cb["values"] = vals
                if vals:
                    self._hs_client.set(vals[-1])
                    self._tx_client.set(vals[0])
                    self._dyn_client.set(vals[-1])
                    self._rot_client.set(vals[-1])
                    self._sum_client.set(vals[-1])
            except Exception as e:
                _log(self._setup_log, f"Registration failed: {e}", "err")
        _run_in_thread(_run)

    def _run_full_demo(self):
        def _run():
            global _ca, _server
            _clear(self._setup_log)
            _log(self._setup_log, "Running full end-to-end demo...", "head")

            _ca = CertificateAuthority(name="SecureBank-RootCA", bits=128)
            _log(self._setup_log, "CA initialized", "ok")

            _server = BankServer(ca=_ca, name="BankServer-Primary")
            _log(self._setup_log, "Server initialized  (Twofish at-rest active)", "ok")

            for name in ["Alice", "Bob"]:
                if name not in _clients:
                    c = BankClient(name=name, ca=_ca)
                    _clients[name] = c
                    self._clients_box.insert(
                        tk.END, f"  {name}  (cert #{c.certificate['serial']})")
            _log(self._setup_log, "Clients Alice and Bob registered", "ok")

            vals = list(_clients.keys())
            for cb in [self._hs_client, self._tx_client,
                       self._dyn_client, self._rot_client, self._sum_client]:
                cb["values"] = vals
            if vals:
                self._hs_client.set(vals[0])
                self._tx_client.set(vals[0])
                self._dyn_client.set(vals[0])
                self._rot_client.set(vals[0])
                self._sum_client.set(vals[0])

            for name in ["Alice", "Bob"]:
                ok = _clients[name].perform_handshake(_server)
                _log(self._setup_log,
                     f"Handshake {name}: {'SUCCESS' if ok else 'FAILED'}",
                     "ok" if ok else "err")

            _log(self._setup_log,
                 "Full demo ready!  Try the Session Protocol tab → Run Dynamicity Test.",
                 "head")
            self._status_lbl.config(text="●  All systems online", fg=ACCENT2)

            self._tx_from.delete(0, tk.END); self._tx_from.insert(0, "ACC-001")
            self._tx_to.delete(0, tk.END);   self._tx_to.insert(0, "ACC-002")
        _run_in_thread(_run)


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = SecureBankApp()
    app.mainloop()
