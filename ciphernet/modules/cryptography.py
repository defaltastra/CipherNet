"""
CipherNet Cryptography Lab Module (PySide6)
Interactive cryptographic workspace implementing AES-256-GCM AEAD,
RSA-PSS digital signatures, multi-algorithm hashing, and file integrity verifier.
Uses background workers for RSA keypair generation and chunked file hashing.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ciphernet.services.crypto_service import CryptoService
from ciphernet.widgets.panels import CryptoEntropyWidget, SectionHeader
from ciphernet.workers import FileIntegrityWorker, RsaKeyGenWorker


RSA_KEY_SIZE_OPTIONS = [
    ("2048-bit (Standard Security)", 2048),
    ("4096-bit (High Security)", 4096),
]

HASH_ALGO_OPTIONS = [
    ("SHA-256", "SHA-256"),
    ("SHA-512", "SHA-512"),
    ("SHA3-256", "SHA3-256"),
    ("BLAKE2b", "BLAKE2b"),
]


class CryptographyView(QWidget):
    """
    Cryptography Lab interactive view for testing symmetric, asymmetric,
    and hashing primitives.
    """

    def __init__(self, crypto_service: CryptoService, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.crypto_service = crypto_service
        self.cached_rsa_keypair: Optional[Dict[str, Any]] = None
        self.cached_aes_result: Optional[Dict[str, str]] = None
        self.cached_signature: str = ""
        self._rsa_worker: Optional[RsaKeyGenWorker] = None
        self._hash_worker: Optional[FileIntegrityWorker] = None

        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # Header Title
        header_col = QVBoxLayout()
        header_col.setSpacing(2)
        h_title = QLabel("CRYPTOGRAPHY LAB & DIGITAL FORENSICS")
        h_title.setStyleSheet("color: #FFFFFF; font-size: 18px; font-weight: 900; letter-spacing: 0.5px;")
        h_sub = QLabel("NIST-Compliant Symmetric Ciphers, Asymmetric Keypairs, Signatures & Integrity Verifiers")
        h_sub.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        header_col.addWidget(h_title)
        header_col.addWidget(h_sub)
        main_layout.addLayout(header_col)

        # -------------------------------------------------------------
        # Top: Dynamic Tumbling Cryptographic Entropy Streamer
        # -------------------------------------------------------------
        self.entropy_widget = CryptoEntropyWidget()
        main_layout.addWidget(self.entropy_widget)

        # -------------------------------------------------------------
        # Central Tabs: AES, RSA, Hash & Integrity
        # -------------------------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_aes_tab(), "🔒  AES-256-GCM Ciphers")
        self.tabs.addTab(self._build_rsa_tab(), "🔑  RSA Digital Signatures")
        self.tabs.addTab(self._build_hash_tab(), "⚙️  Hash & File Integrity")

        main_layout.addWidget(self.tabs, 1)

        # Initial computations
        self.action_aes_encrypt()
        self.action_compute_hashes()

    def refresh_entropy(self) -> None:
        """Advances live entropy stream frame."""
        self.entropy_widget.advance_cycle()

    # =========================================================================
    # TAB 1: AES-256-GCM Authenticated Encryption & Decryption
    # =========================================================================
    def _build_aes_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(SectionHeader("AES-256-GCM Authenticated Encryption", "NIST FIPS Approved Galois/Counter Mode"))

        row1 = QHBoxLayout()
        row1.setSpacing(16)

        # Left Inputs
        left_box = QFrame()
        left_box.setProperty("class", "panel-card")
        left_box.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        l_layout = QVBoxLayout(left_box)
        l_layout.setSpacing(10)

        l_layout.addWidget(QLabel("1. Passphrase or 256-bit Key:"))
        self.input_aes_key = QLineEdit("CipherNet-Secret-Passphrase-2026")
        l_layout.addWidget(self.input_aes_key)

        l_layout.addWidget(QLabel("2. Plaintext Message to Encrypt:"))
        self.input_aes_plain = QLineEdit("CLASSIFIED: Network payload authentication verified.")
        l_layout.addWidget(self.input_aes_plain)

        btn_row1 = QHBoxLayout()
        self.btn_aes_encrypt = QPushButton("🔒 Encrypt (AES-256-GCM)")
        self.btn_aes_encrypt.setProperty("class", "btn-primary")
        self.btn_aes_encrypt.clicked.connect(self.action_aes_encrypt)
        btn_row1.addWidget(self.btn_aes_encrypt)

        self.btn_aes_genkey = QPushButton("🎲 Gen 256-bit Key")
        self.btn_aes_genkey.clicked.connect(self._on_gen_aes_key)
        btn_row1.addWidget(self.btn_aes_genkey)
        l_layout.addLayout(btn_row1)

        row1.addWidget(left_box, 1)

        # Right Outputs
        right_box = QFrame()
        right_box.setProperty("class", "panel-card")
        right_box.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        r_layout = QVBoxLayout(right_box)
        r_layout.setSpacing(6)

        r_title = QLabel("ENCRYPTION OUTPUT (SALT, NONCE, TAG, CIPHERTEXT):")
        r_title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        r_layout.addWidget(r_title)

        self.output_aes_enc = QLabel()
        self.output_aes_enc.setTextFormat(Qt.RichText)
        self.output_aes_enc.setWordWrap(True)
        r_layout.addWidget(self.output_aes_enc)
        r_layout.addStretch()

        row1.addWidget(right_box, 1)
        layout.addLayout(row1)

        # Decryption & Tamper Test Section
        layout.addWidget(SectionHeader("Decryption & Tamper Verification", "Integrity & Authentication Tag Validation"))

        row2 = QHBoxLayout()
        row2.setSpacing(16)

        dec_actions = QFrame()
        dec_actions.setProperty("class", "panel-card")
        dec_actions.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        da_layout = QVBoxLayout(dec_actions)
        da_layout.setSpacing(12)

        self.btn_aes_decrypt = QPushButton("🔓 Decrypt & Authenticate")
        self.btn_aes_decrypt.setProperty("class", "btn-success")
        self.btn_aes_decrypt.clicked.connect(lambda: self.action_aes_decrypt(tamper=False))
        da_layout.addWidget(self.btn_aes_decrypt)

        self.btn_aes_tamper = QPushButton("⚠️ Tamper Test (Flip 1 Byte)")
        self.btn_aes_tamper.setProperty("class", "btn-danger")
        self.btn_aes_tamper.clicked.connect(lambda: self.action_aes_decrypt(tamper=True))
        da_layout.addWidget(self.btn_aes_tamper)
        da_layout.addStretch()

        row2.addWidget(dec_actions, 1)

        dec_out_box = QFrame()
        dec_out_box.setProperty("class", "panel-card")
        dec_out_box.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        do_layout = QVBoxLayout(dec_out_box)
        do_layout.setSpacing(6)

        do_title = QLabel("DECRYPTED RESULT / AUTHENTICATION VERDICT:")
        do_title.setStyleSheet("color: #4ECCA3; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        do_layout.addWidget(do_title)

        self.output_aes_dec = QLabel("Awaiting decryption action...")
        self.output_aes_dec.setTextFormat(Qt.RichText)
        self.output_aes_dec.setWordWrap(True)
        do_layout.addWidget(self.output_aes_dec)
        do_layout.addStretch()

        row2.addWidget(dec_out_box, 2)
        layout.addLayout(row2)

        scroll.setWidget(container)
        return scroll

    def action_aes_encrypt(self) -> None:
        key_str = self.input_aes_key.text().strip()
        plain_str = self.input_aes_plain.text().strip()
        if not key_str or not plain_str:
            return

        res = self.crypto_service.encrypt_aes_gcm(plain_str, key_str, is_passphrase=True)
        self.cached_aes_result = res

        html = (
            f"<div style='font-family: monospace; font-size: 11px; line-height: 1.6;'>"
            f"<b style='color: #9CA3AF;'>Ciphertext:</b> &nbsp;<span style='color: #FFFFFF;'>{res['ciphertext_hex'][:40]}...</span><br>"
            f"<b style='color: #9CA3AF;'>Auth Tag (128-bit):</b> &nbsp;<span style='color: #F72585; font-weight: bold;'>{res['tag_hex']}</span><br>"
            f"<b style='color: #9CA3AF;'>Nonce (96-bit IV):</b> &nbsp;<span style='color: #FF70A6;'>{res['nonce_hex']}</span><br>"
            f"<b style='color: #9CA3AF;'>Salt (128-bit):</b> &nbsp;<span style='color: #83A598;'>{res['salt_hex']}</span><br>"
            f"<b style='color: #9CA3AF;'>Combined Base64:</b><br><span style='color: #4ECCA3; word-break: break-all;'>{res['bundle_b64']}</span>"
            f"</div>"
        )
        self.output_aes_enc.setText(html)

    def _on_gen_aes_key(self) -> None:
        new_key = self.crypto_service.generate_aes_key()
        self.input_aes_key.setText(new_key)

    def action_aes_decrypt(self, tamper: bool = False) -> None:
        if not self.cached_aes_result:
            self.action_aes_encrypt()

        res = self.cached_aes_result
        if not res:
            return

        key_str = self.input_aes_key.text().strip()
        ciphertext = res["ciphertext_hex"]
        tag = res["tag_hex"]

        if tamper:
            last = ciphertext[-2:]
            flipped = "00" if last != "00" else "ff"
            ciphertext = ciphertext[:-2] + flipped

        ok, result = self.crypto_service.decrypt_aes_gcm(
            ciphertext_hex=ciphertext,
            tag_hex=tag,
            nonce_hex=res["nonce_hex"],
            key_or_passphrase=key_str,
            is_passphrase=True,
            salt_hex=res["salt_hex"],
        )

        if ok:
            html = (
                f"<div style='line-height: 1.6;'>"
                f"<b style='color: #4ECCA3; font-size: 13px;'>✔ AUTHENTICATION & DECRYPTION SUCCESSFUL</b><br>"
                f"<span style='color: #FFFFFF; font-size: 13px;'>\"{result}\"</span><br>"
                f"<span style='color: #9CA3AF; font-size: 11px;'>Verified authentic with 128-bit GCM MAC Tag.</span>"
                f"</div>"
            )
        else:
            html = (
                f"<div style='line-height: 1.6;'>"
                f"<b style='color: #FF4D6D; font-size: 13px;'>✖ AUTHENTICATION FAILURE (INTEGRITY BREACH)</b><br>"
                f"<span style='color: #FABD2F; font-size: 12px;'>{result}</span><br>"
                f"<span style='color: #FF70A6; font-size: 11px;'>AES-GCM Galois field verification detected ciphertext tampering.</span>"
                f"</div>"
            )
        self.output_aes_dec.setText(html)

    # =========================================================================
    # TAB 2: RSA Keypair & Digital Signatures (RSA-PSS)
    # =========================================================================
    def _build_rsa_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        layout.addWidget(SectionHeader("Asymmetric Cryptography: RSA Key Pair Generation", "PKCS#8 & SubjectPublicKeyInfo PEM"))

        row1 = QHBoxLayout()
        row1.setSpacing(16)

        left_box = QFrame()
        left_box.setProperty("class", "panel-card")
        left_box.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        l_layout = QVBoxLayout(left_box)
        l_layout.setSpacing(10)

        l_layout.addWidget(QLabel("Key Modulus Size:"))
        self.combo_rsa_size = QComboBox()
        for label, val in RSA_KEY_SIZE_OPTIONS:
            self.combo_rsa_size.addItem(label, val)
        l_layout.addWidget(self.combo_rsa_size)

        self.btn_rsa_gen = QPushButton("🔑 Generate RSA Key Pair")
        self.btn_rsa_gen.setProperty("class", "btn-primary")
        self.btn_rsa_gen.clicked.connect(self.action_rsa_generate)
        l_layout.addWidget(self.btn_rsa_gen)

        self.output_rsa_metrics = QLabel("Key Metrics: Not yet generated")
        self.output_rsa_metrics.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        l_layout.addWidget(self.output_rsa_metrics)
        l_layout.addStretch()

        row1.addWidget(left_box, 1)

        right_box = QFrame()
        right_box.setProperty("class", "panel-card")
        right_box.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        r_layout = QVBoxLayout(right_box)
        r_layout.setSpacing(6)

        r_title = QLabel("PUBLIC KEY FINGERPRINT & PEM PREVIEW:")
        r_title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        r_layout.addWidget(r_title)

        self.output_rsa_pub = QLabel("Generate a keypair to inspect public PEM and fingerprint.")
        self.output_rsa_pub.setTextFormat(Qt.RichText)
        self.output_rsa_pub.setWordWrap(True)
        r_layout.addWidget(self.output_rsa_pub)
        r_layout.addStretch()

        row1.addWidget(right_box, 2)
        layout.addLayout(row1)

        # Digital Signature Section
        layout.addWidget(SectionHeader("Digital Signature Generation & Verification (RSA-PSS SHA-256)", "Cryptographic Proof of Origin & Integrity"))

        row2 = QHBoxLayout()
        row2.setSpacing(16)

        sig_left = QFrame()
        sig_left.setProperty("class", "panel-card")
        sig_left.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        sl_layout = QVBoxLayout(sig_left)
        sl_layout.setSpacing(10)

        sl_layout.addWidget(QLabel("Message to Sign:"))
        self.input_rsa_msg = QLineEdit("Authorized transmission from CipherNet Core Operator.")
        sl_layout.addWidget(self.input_rsa_msg)

        btn_row2 = QHBoxLayout()
        self.btn_rsa_sign = QPushButton("✍️ Sign Message")
        self.btn_rsa_sign.setProperty("class", "btn-warning")
        self.btn_rsa_sign.clicked.connect(self.action_rsa_sign)
        btn_row2.addWidget(self.btn_rsa_sign)

        self.btn_rsa_verify = QPushButton("🔍 Verify Signature")
        self.btn_rsa_verify.setProperty("class", "btn-success")
        self.btn_rsa_verify.clicked.connect(lambda: self.action_rsa_verify(tamper=False))
        btn_row2.addWidget(self.btn_rsa_verify)

        self.btn_rsa_tamper = QPushButton("⚡ Tamper Test")
        self.btn_rsa_tamper.setProperty("class", "btn-danger")
        self.btn_rsa_tamper.clicked.connect(lambda: self.action_rsa_verify(tamper=True))
        btn_row2.addWidget(self.btn_rsa_tamper)

        sl_layout.addLayout(btn_row2)
        sl_layout.addStretch()
        row2.addWidget(sig_left, 1)

        sig_right = QFrame()
        sig_right.setProperty("class", "panel-card")
        sig_right.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        sr_layout = QVBoxLayout(sig_right)
        sr_layout.setSpacing(6)

        sr_title = QLabel("SIGNATURE BASE64 & VERIFICATION STATUS:")
        sr_title.setStyleSheet("color: #4ECCA3; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        sr_layout.addWidget(sr_title)

        self.output_rsa_sig = QLabel("Sign message to generate digital signature.")
        self.output_rsa_sig.setTextFormat(Qt.RichText)
        self.output_rsa_sig.setWordWrap(True)
        sr_layout.addWidget(self.output_rsa_sig)
        sr_layout.addStretch()

        row2.addWidget(sig_right, 1)
        layout.addLayout(row2)

        scroll.setWidget(container)
        return scroll

    def action_rsa_generate(self) -> None:
        key_size = self.combo_rsa_size.currentData()
        self.btn_rsa_gen.setEnabled(False)
        self.btn_rsa_gen.setText(f"Generating {key_size}-bit RSA...")

        self._rsa_worker = RsaKeyGenWorker(self.crypto_service, key_size, self)
        self._rsa_worker.keypair_generated.connect(self._on_rsa_generated)
        self._rsa_worker.start()

    def _on_rsa_generated(self, res: dict) -> None:
        self.cached_rsa_keypair = res
        self.btn_rsa_gen.setEnabled(True)
        self.btn_rsa_gen.setText("🔑 Generate RSA Key Pair")

        self.output_rsa_metrics.setText(
            f"Active Key Size: {res['key_size']} bits | Exponent: 65537 | Security: High"
        )

        pem_snippet = "\n".join(res["public_pem"].splitlines()[:5]) + "\n..."
        html = (
            f"<div style='font-family: monospace; font-size: 11px; line-height: 1.5;'>"
            f"<b style='color: #9CA3AF;'>SHA-256 Fingerprint:</b><br><span style='color: #F72585;'>{res['fingerprint']}</span><br><br>"
            f"<b style='color: #9CA3AF;'>Public Key PEM:</b><br><span style='color: #83A598;'>{pem_snippet}</span>"
            f"</div>"
        )
        self.output_rsa_pub.setText(html)

    def action_rsa_sign(self) -> None:
        if not self.cached_rsa_keypair:
            self.cached_rsa_keypair = self.crypto_service.generate_rsa_keypair(2048)

        msg = self.input_rsa_msg.text()
        ok, sig = self.crypto_service.sign_message(msg, self.cached_rsa_keypair["private_pem"])
        if ok:
            self.cached_signature = sig
            html = (
                f"<div style='font-family: monospace; font-size: 11px; line-height: 1.5;'>"
                f"<b style='color: #9CA3AF;'>Generated RSA-PSS Signature (Base64):</b><br>"
                f"<span style='color: #FF70A6; word-break: break-all;'>{sig}</span><br><br>"
                f"<span style='color: #4ECCA3; font-weight: bold;'>Status: Ready for verification against public key.</span>"
                f"</div>"
            )
        else:
            html = f"<span style='color: #FF4D6D;'>Signing Error: {sig}</span>"
        self.output_rsa_sig.setText(html)

    def action_rsa_verify(self, tamper: bool = False) -> None:
        if not self.cached_rsa_keypair:
            self.cached_rsa_keypair = self.crypto_service.generate_rsa_keypair(2048)
        if not self.cached_signature:
            self.action_rsa_sign()

        msg = self.input_rsa_msg.text()
        if tamper:
            msg += " [TAMPERED_PAYLOAD]"

        ok, ver_msg = self.crypto_service.verify_signature(
            msg,
            self.cached_signature,
            self.cached_rsa_keypair["public_pem"],
        )

        if ok:
            html = (
                f"<div style='line-height: 1.6;'>"
                f"<b style='color: #4ECCA3; font-size: 13px;'>✔ DIGITAL SIGNATURE VALID</b><br>"
                f"<span style='color: #F3F4F6;'>{ver_msg}</span><br>"
                f"<span style='color: #9CA3AF; font-size: 11px;'>Verified authentic using RSA-PSS SHA-256.</span>"
                f"</div>"
            )
        else:
            html = (
                f"<div style='line-height: 1.6;'>"
                f"<b style='color: #FF4D6D; font-size: 13px;'>✖ VERIFICATION FAILED (FORGERY / TAMPER DETECTED)</b><br>"
                f"<span style='color: #FABD2F;'>{ver_msg}</span><br>"
                f"<span style='color: #FF70A6; font-size: 11px;'>Message payload was modified after signature generation!</span>"
                f"</div>"
            )
        self.output_rsa_sig.setText(html)

    # =========================================================================
    # TAB 3: Hash & File Integrity
    # =========================================================================
    def _build_hash_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Multi-Algorithm Hashing
        layout.addWidget(SectionHeader("Multi-Algorithm Cryptographic Hashing", "Collision Resistant One-Way Functions"))

        row1 = QHBoxLayout()
        row1.setSpacing(16)

        h_left = QFrame()
        h_left.setProperty("class", "panel-card")
        h_left.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        hl_layout = QVBoxLayout(h_left)
        hl_layout.setSpacing(10)

        hl_layout.addWidget(QLabel("Input String to Hash:"))
        self.input_hash_text = QLineEdit("Cybersecurity and Cryptography Toolkit 2026")
        hl_layout.addWidget(self.input_hash_text)

        hl_layout.addWidget(QLabel("Optional Salt Prefix:"))
        self.input_hash_salt = QLineEdit()
        self.input_hash_salt.setPlaceholderText("Optional salt string...")
        hl_layout.addWidget(self.input_hash_salt)

        self.btn_compute_hashes = QPushButton("⚙️ Compute Hashes")
        self.btn_compute_hashes.setProperty("class", "btn-primary")
        self.btn_compute_hashes.clicked.connect(self.action_compute_hashes)
        hl_layout.addWidget(self.btn_compute_hashes)
        hl_layout.addStretch()

        row1.addWidget(h_left, 1)

        h_right = QFrame()
        h_right.setProperty("class", "panel-card")
        h_right.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        hr_layout = QVBoxLayout(h_right)
        hr_layout.setSpacing(6)

        hr_title = QLabel("DIGEST OUTPUTS:")
        hr_title.setStyleSheet("color: #FF70A6; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        hr_layout.addWidget(hr_title)

        self.output_multi_hash = QLabel()
        self.output_multi_hash.setTextFormat(Qt.RichText)
        self.output_multi_hash.setWordWrap(True)
        hr_layout.addWidget(self.output_multi_hash)
        hr_layout.addStretch()

        row1.addWidget(h_right, 2)
        layout.addLayout(row1)

        # File Checksum Verifier
        layout.addWidget(SectionHeader("File Checksum & Integrity Verifier", "Verify Local Files Against Expected Checksums"))

        row2 = QHBoxLayout()
        row2.setSpacing(16)

        f_left = QFrame()
        f_left.setProperty("class", "panel-card")
        f_left.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        fl_layout = QVBoxLayout(f_left)
        fl_layout.setSpacing(10)

        fl_layout.addWidget(QLabel("Local File Path:"))
        path_row = QHBoxLayout()
        self.input_file_path = QLineEdit("ciphernet/config/settings.json")
        path_row.addWidget(self.input_file_path)

        self.btn_browse_file = QPushButton("Browse...")
        self.btn_browse_file.clicked.connect(self._on_browse_file)
        path_row.addWidget(self.btn_browse_file)
        fl_layout.addLayout(path_row)

        fl_layout.addWidget(QLabel("Checksum Algorithm:"))
        self.combo_file_algo = QComboBox()
        for label, val in HASH_ALGO_OPTIONS:
            self.combo_file_algo.addItem(label, val)
        fl_layout.addWidget(self.combo_file_algo)

        fl_layout.addWidget(QLabel("Expected Hash (Optional for match comparison):"))
        self.input_expected_hash = QLineEdit()
        self.input_expected_hash.setPlaceholderText("Paste expected hexadecimal hash...")
        fl_layout.addWidget(self.input_expected_hash)

        self.btn_verify_file = QPushButton("🛡️ Verify File Integrity")
        self.btn_verify_file.setProperty("class", "btn-success")
        self.btn_verify_file.clicked.connect(self.action_verify_file)
        fl_layout.addWidget(self.btn_verify_file)
        fl_layout.addStretch()

        row2.addWidget(f_left, 1)

        f_right = QFrame()
        f_right.setProperty("class", "panel-card")
        f_right.setStyleSheet(
            "QFrame { background-color: #12141A; border: 1px solid #1E232E; border-radius: 10px; padding: 16px; }"
        )
        fr_layout = QVBoxLayout(f_right)
        fr_layout.setSpacing(6)

        fr_title = QLabel("VERIFICATION VERDICT & COMPUTED HASH:")
        fr_title.setStyleSheet("color: #4ECCA3; font-size: 11px; font-weight: 800; letter-spacing: 1px;")
        fr_layout.addWidget(fr_title)

        self.output_file_result = QLabel("Submit file verification to view verdict.")
        self.output_file_result.setTextFormat(Qt.RichText)
        self.output_file_result.setWordWrap(True)
        fr_layout.addWidget(self.output_file_result)
        fr_layout.addStretch()

        row2.addWidget(f_right, 2)
        layout.addLayout(row2)

        scroll.setWidget(container)
        return scroll

    def action_compute_hashes(self) -> None:
        text = self.input_hash_text.text()
        salt = self.input_hash_salt.text()
        digests = self.crypto_service.hash_text(text, salt)

        lines = []
        for algo, d in digests.items():
            color = "#F72585" if "SHA-256" in algo else ("#FF70A6" if "SHA-512" in algo else "#83A598")
            lines.append(f"<b style='color: #9CA3AF;'>{algo:<22}:</b> &nbsp;<span style='color: {color};'>{d}</span>")

        html = f"<div style='font-family: monospace; font-size: 11px; line-height: 1.7;'>{'<br>'.join(lines)}</div>"
        self.output_multi_hash.setText(html)

    def _on_browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Verify", str(Path.cwd()))
        if path:
            self.input_file_path.setText(path)

    def action_verify_file(self) -> None:
        file_path = self.input_file_path.text().strip()
        algo = self.combo_file_algo.currentData()
        expected = self.input_expected_hash.text().strip()

        self.btn_verify_file.setEnabled(False)
        self.btn_verify_file.setText("Computing Checksum...")

        self._hash_worker = FileIntegrityWorker(
            crypto_service=self.crypto_service,
            file_path=file_path,
            expected_hash=expected,
            algorithm=algo,
            parent=self,
        )
        self._hash_worker.verification_done.connect(self._on_file_verified)
        self._hash_worker.start()

    def _on_file_verified(self, res: dict) -> None:
        self.btn_verify_file.setEnabled(True)
        self.btn_verify_file.setText("🛡️ Verify File Integrity")

        if "error" in res:
            html = f"<span style='color: #FF4D6D;'><b>File Error:</b> {res['error']}</span>"
        else:
            status_html = ""
            if res["expected_hash"]:
                if res["verified"]:
                    status_html = "<b style='color: #4ECCA3; font-size: 13px;'>Status: ✔ PASSED (File checksum verified authentic)</b>"
                else:
                    status_html = "<b style='color: #FF4D6D; font-size: 13px;'>Status: ✖ MISMATCH (File has been altered or corrupted)</b>"
            else:
                status_html = "<span style='color: #FABD2F;'>Status: Checksum computed. (No expected hash provided)</span>"

            html = (
                f"<div style='line-height: 1.7; font-size: 12px;'>"
                f"<b>File Name:</b> &nbsp;<span>{res['file_name']}</span> &nbsp;({res['file_size']:,} bytes)<br>"
                f"<b>Algorithm:</b> &nbsp;<span style='color: #83A598;'>{res['algorithm']}</span><br>"
                f"<b>Computed Hash:</b> &nbsp;<span style='color: #FF70A6; font-family: monospace;'>{res['computed_hash']}</span><br>"
                f"{status_html}"
                f"</div>"
            )
        self.output_file_result.setText(html)
