"""
CipherNet Cryptography Service
Implements standard cryptographic algorithms with secure defaults:
- AES-256-GCM authenticated symmetric encryption & decryption.
- RSA 2048/4096-bit key pair generation, PEM serialization & key inspection.
- RSA-PSS SHA-256 digital signature creation & verification.
- Cryptographic hashing (SHA-256, SHA-512, SHA3-256, BLAKE2b) with salt.
- File integrity verification (chunked streaming checksum comparison).
"""

from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ciphernet.services.event_service import EventService


class CryptoService:
    """Provides cryptographic primitives and audit logging."""

    def __init__(self, event_service: Optional[EventService] = None) -> None:
        self.event_service = event_service

    def _audit(self, title: str, details: str, severity: str = "INFO", metadata: Optional[Dict[str, Any]] = None) -> None:
        if self.event_service:
            self.event_service.log(
                title=title,
                details=details,
                severity=severity,
                category="CRYPTO",
                simulated=False,
                metadata=metadata or {},
            )

    # ---------------------------------------------------------
    # 1. AES-256-GCM Authenticated Encryption & Decryption
    # ---------------------------------------------------------
    @staticmethod
    def generate_aes_key() -> str:
        """Generates a cryptographically secure 256-bit AES key (hex-encoded)."""
        return os.urandom(32).hex()

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
        """Derives a 256-bit key from passphrase using PBKDF2 with SHA-256 (100,000 iterations)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def encrypt_aes_gcm(
        self,
        plaintext: str,
        key_or_passphrase: str,
        is_passphrase: bool = False,
        associated_data: str = "",
    ) -> Dict[str, str]:
        """
        Encrypts plaintext with AES-256-GCM.
        Returns a dict with hex/base64 encoded salt, nonce, ciphertext, and combined bundle.
        """
        if is_passphrase:
            salt = os.urandom(16)
            key = self.derive_key_from_passphrase(key_or_passphrase, salt)
        else:
            salt = b""
            # Treat as hex key or hash to 32 bytes if invalid length
            try:
                raw = bytes.fromhex(key_or_passphrase.strip())
                if len(raw) == 32:
                    key = raw
                else:
                    key = hashlib.sha256(key_or_passphrase.encode("utf-8")).digest()
            except ValueError:
                key = hashlib.sha256(key_or_passphrase.encode("utf-8")).digest()

        # 96-bit (12 bytes) recommended IV for AES-GCM
        nonce = os.urandom(12)
        aad = associated_data.encode("utf-8") if associated_data else None

        aesgcm = AESGCM(key)
        # AESGCM.encrypt appends 16-byte authentication tag to ciphertext
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        # Create combined base64 bundle: salt (16) + nonce (12) + tag (16) + ciphertext
        bundle_bytes = salt + nonce + tag + ciphertext
        bundle_b64 = base64.b64encode(bundle_bytes).decode("ascii")

        self._audit(
            title="AES-256-GCM Encrypted",
            details=f"Encrypted {len(plaintext)} characters. Nonce: {nonce.hex()[:8]}..., Tag: {tag.hex()[:8]}...",
            severity="INFO",
            metadata={"mode": "AES-256-GCM", "authenticated": True},
        )

        return {
            "key_hex": key.hex(),
            "salt_hex": salt.hex() if salt else "N/A",
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "bundle_b64": bundle_b64,
        }

    def decrypt_aes_gcm(
        self,
        ciphertext_hex: str,
        tag_hex: str,
        nonce_hex: str,
        key_or_passphrase: str,
        is_passphrase: bool = False,
        salt_hex: str = "",
        associated_data: str = "",
    ) -> Tuple[bool, str]:
        """
        Decrypts and authenticates AES-256-GCM payload.
        Returns (success: bool, result_text: str).
        """
        try:
            nonce = bytes.fromhex(nonce_hex.strip())
            tag = bytes.fromhex(tag_hex.strip())
            ciphertext = bytes.fromhex(ciphertext_hex.strip())
            combined = ciphertext + tag

            if is_passphrase:
                if not salt_hex or salt_hex == "N/A":
                    return False, "Error: Salt is required for passphrase-based decryption."
                salt = bytes.fromhex(salt_hex.strip())
                key = self.derive_key_from_passphrase(key_or_passphrase, salt)
            else:
                try:
                    raw = bytes.fromhex(key_or_passphrase.strip())
                    key = raw if len(raw) == 32 else hashlib.sha256(key_or_passphrase.encode("utf-8")).digest()
                except ValueError:
                    key = hashlib.sha256(key_or_passphrase.encode("utf-8")).digest()

            aad = associated_data.encode("utf-8") if associated_data else None
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, combined, aad)
            plaintext = decrypted_bytes.decode("utf-8")

            self._audit(
                title="AES-256-GCM Decrypted Successfully",
                details=f"Authenticated and decrypted {len(plaintext)} characters.",
                severity="INFO",
            )
            return True, plaintext

        except InvalidTag:
            self._audit(
                title="AES-256-GCM Authentication Failed",
                details="Decryption aborted: Authentication tag mismatch or ciphertext was tampered with!",
                severity="CRITICAL",
            )
            return False, "AUTHENTICATION FAILED: Invalid key, wrong authentication tag, or ciphertext tampered!"
        except Exception as ex:
            return False, f"Decryption Error: {str(ex)}"

    # ---------------------------------------------------------
    # 2. RSA Key Generation & Digital Signatures (RSA-PSS)
    # ---------------------------------------------------------
    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict[str, Any]:
        """Generates an RSA key pair and returns PEM strings and key metrics."""
        if key_size not in (2048, 3072, 4096):
            key_size = 2048

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Public key fingerprint (SHA-256 of DER)
        pub_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = hashlib.sha256(pub_der).hexdigest()

        self._audit(
            title="RSA Keypair Generated",
            details=f"Generated {key_size}-bit RSA key pair. Fingerprint: {fingerprint[:16]}...",
            severity="INFO",
            metadata={"key_size": key_size, "fingerprint": fingerprint},
        )

        return {
            "key_size": key_size,
            "private_pem": private_pem,
            "public_pem": public_pem,
            "fingerprint": fingerprint,
            "public_numbers": {
                "e": public_key.public_numbers().e,
                "n_bits": public_key.key_size,
            },
        }

    def sign_message(self, message: str, private_pem: str) -> Tuple[bool, str]:
        """Signs arbitrary text using RSA-PSS with SHA-256."""
        try:
            private_key = serialization.load_pem_private_key(
                private_pem.encode("utf-8"),
                password=None,
                backend=default_backend(),
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                return False, "Key provided is not an RSA private key."

            signature = private_key.sign(
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            sig_b64 = base64.b64encode(signature).decode("ascii")

            self._audit(
                title="RSA Digital Signature Created",
                details=f"Signed message of {len(message)} chars using RSA-PSS SHA-256.",
                severity="INFO",
            )
            return True, sig_b64

        except Exception as ex:
            return False, f"Signing Error: {str(ex)}"

    def verify_signature(self, message: str, signature_b64: str, public_pem: str) -> Tuple[bool, str]:
        """Verifies RSA-PSS digital signature."""
        try:
            public_key = serialization.load_pem_public_key(
                public_pem.encode("utf-8"),
                backend=default_backend(),
            )

            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "Key provided is not an RSA public key."

            signature = base64.b64decode(signature_b64.strip())

            public_key.verify(
                signature,
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            self._audit(
                title="RSA Signature Verified: VALID",
                details="Digital signature is cryptographically authentic.",
                severity="INFO",
            )
            return True, "VERIFIED: Digital signature is authentic and verified with the public key."

        except InvalidSignature:
            self._audit(
                title="RSA Signature Verification: INVALID",
                details="Signature mismatch: Data altered or forged key!",
                severity="HIGH",
            )
            return False, "INVALID SIGNATURE: Verification failed! Data was modified or signed by an untrusted key."
        except Exception as ex:
            return False, f"Verification Error: {str(ex)}"

    # ---------------------------------------------------------
    # 3. Multi-Algorithm Hashing & Integrity
    # ---------------------------------------------------------
    @staticmethod
    def hash_text(text: str, salt: str = "") -> Dict[str, str]:
        """Calculates multi-algorithm cryptographic hashes of input string."""
        data = (salt + text).encode("utf-8")
        return {
            "SHA-256": hashlib.sha256(data).hexdigest(),
            "SHA-512": hashlib.sha512(data).hexdigest(),
            "SHA3-256": hashlib.sha3_256(data).hexdigest(),
            "BLAKE2b": hashlib.blake2b(data).hexdigest(),
            "MD5 (Legacy/Insecure)": hashlib.md5(data).hexdigest(),
        }

    def verify_file_integrity(
        self,
        file_path: str | Path,
        expected_hash: str,
        algorithm: str = "SHA-256",
    ) -> Dict[str, Any]:
        """
        Reads a file in 64KB chunks to compute checksum and checks against expected hash.
        """
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return {
                "verified": False,
                "error": f"File '{file_path}' does not exist or is not a regular file.",
                "computed_hash": "N/A",
                "expected_hash": expected_hash,
            }

        algo = algorithm.upper()
        if algo == "SHA-512":
            hasher = hashlib.sha512()
        elif algo == "SHA3-256":
            hasher = hashlib.sha3_256()
        elif algo == "BLAKE2B":
            hasher = hashlib.blake2b()
        else:
            hasher = hashlib.sha256()

        bytes_read = 0
        try:
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
                    bytes_read += len(chunk)

            computed = hasher.hexdigest()
            expected = expected_hash.strip().lower()
            matched = computed.lower() == expected

            self._audit(
                title=f"File Integrity Check: {'PASSED' if matched else 'FAILED'}",
                details=f"File: '{p.name}' ({bytes_read} bytes). Algorithm: {algo}.",
                severity="INFO" if matched else "HIGH",
                metadata={"file": str(p), "computed": computed, "matched": matched},
            )

            return {
                "verified": matched,
                "file_name": p.name,
                "file_size": bytes_read,
                "algorithm": algo,
                "computed_hash": computed,
                "expected_hash": expected_hash.strip(),
                "status": "VERIFIED (MATCH)" if matched else "CORRUPTED / TAMPERED (MISMATCH)",
            }
        except Exception as ex:
            return {
                "verified": False,
                "error": f"File Read Error: {str(ex)}",
                "computed_hash": "N/A",
                "expected_hash": expected_hash,
            }
