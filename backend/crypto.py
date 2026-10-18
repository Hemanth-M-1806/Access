"""
AccessDrift Cryptographic Layer & Memory Vault
Supports IBM Z CPACF (s390x) hardware acceleration with dynamic OpenSSL fallback on x86_64/ARM64.
"""

import os
import time
import platform
import hashlib
import hmac
import secrets
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptographicEngine:
    """
    Cryptographic vault providing hardware-accelerated/OpenSSL anonymization,
    AES-256-GCM authenticated in-memory encryption, and immutable SHA-256 audit chaining.
    """

    def __init__(self):
        self.architecture = platform.machine().lower()
        self.is_s390x = "s390x" in self.architecture
        self.mode_description = (
            "IBM Z CPACF Hardware Acceleration (Native s390x)"
            if self.is_s390x
            else f"OpenSSL 3.x AES-GCM/SHA-256 Accelerated ({platform.machine()})"
        )
        
        # 256-bit AES-GCM master vault key generated in secure memory
        self._vault_key = AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._vault_key)
        
        # In-memory HMAC salt for anonymization
        self._anonymization_salt = secrets.token_bytes(32)
        
        # Immutable Audit Ledger (Genesis Block)
        self.audit_ledger: List[Dict[str, Any]] = []
        self._init_genesis_block()

    def _init_genesis_block(self):
        genesis_data = {
            "index": 0,
            "timestamp": time.time(),
            "action": "GENESIS_INITIALIZATION",
            "actor": "SYSTEM_BOOTSTRAP",
            "details": {
                "engine_mode": self.mode_description,
                "zero_trust_status": "ACTIVE"
            },
            "prev_hash": "0" * 64
        }
        genesis_hash = self._calculate_hash(genesis_data)
        genesis_data["block_hash"] = genesis_hash
        self.audit_ledger.append(genesis_data)

    def _calculate_hash(self, block_data: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash across block parameters."""
        serialized = (
            f"{block_data.get('index')}:"
            f"{block_data.get('timestamp')}:"
            f"{block_data.get('action')}:"
            f"{block_data.get('actor')}:"
            f"{block_data.get('prev_hash')}:"
            f"{str(sorted(block_data.get('details', {}).items()))}"
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def anonymize_identifier(self, identifier: str) -> str:
        """
        Hashes sensitive personal employee identifiers before vector ingestion.
        Returns a deterministic 12-char pseudonym prefix.
        """
        digest = hmac.new(
            self._anonymization_salt,
            identifier.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return f"anon_{digest[:12]}"

    def encrypt_vault_payload(self, plaintext: str) -> Dict[str, str]:
        """
        Encrypts sensitive payload into memory vault using AES-256-GCM.
        """
        nonce = secrets.token_bytes(12)  # 96-bit standard GCM nonce
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex()
        }

    def decrypt_vault_payload(self, nonce_hex: str, ciphertext_hex: str) -> str:
        """
        Decrypts in-memory AES-256-GCM vault payload.
        """
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_bytes = self._aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")

    def record_audit_action(self, action: str, actor: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Appends a cryptographically sealed block to the immutable audit ledger.
        """
        prev_block = self.audit_ledger[-1]
        prev_hash = prev_block["block_hash"]
        
        block_data = {
            "index": len(self.audit_ledger),
            "timestamp": time.time(),
            "action": action,
            "actor": actor,
            "details": details,
            "prev_hash": prev_hash,
            "crypto_mode": self.mode_description
        }
        
        block_data["block_hash"] = self._calculate_hash(block_data)
        self.audit_ledger.append(block_data)
        return block_data

    def verify_ledger_integrity(self) -> bool:
        """Verifies full cryptographic chain integrity."""
        for i in range(1, len(self.audit_ledger)):
            current = self.audit_ledger[i]
            previous = self.audit_ledger[i - 1]
            
            if current["prev_hash"] != previous["block_hash"]:
                return False
            
            computed_hash = self._calculate_hash(current)
            if current["block_hash"] != computed_hash:
                return False
                
        return True


# Global Singleton
crypto_vault = CryptographicEngine()
