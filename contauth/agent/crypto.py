"""At-rest encryption for the agent's local store.

Threat model (stated honestly, because that is what a security control is worth):
This protects the stored behavioural features and event log against *casual disk
inspection* — another user browsing the machine, a backup or a stolen drive, a
support person glancing at the file. It is NOT a defence against an attacker already
running code as the same OS user: that attacker can read the key file too. On a
single-user device, binding the key to the OS user account is the honest ceiling for
a local agent with no server and no password prompt; we document that rather than
overclaim. For stronger protection the key file should be backed by full-disk
encryption (BitLocker/FileVault/LUKS), which this design assumes is present.

Mechanism: AES-256-GCM (authenticated encryption) via the `cryptography` package.
A 256-bit key is generated once and stored in `key` next to the database with
owner-only permissions (0600). Each value is encrypted with a fresh random 96-bit
nonce; the stored blob is base64(nonce || ciphertext || tag). GCM's tag also makes
tampering with the stored features detectable.

If `cryptography` is unavailable, the store degrades to plaintext and says so, so the
agent keeps working on a minimal install — the encryption is a hardening layer, not a
hard dependency that could stop the agent from protecting the screen.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:                      # pragma: no cover - minimal install
    HAVE_CRYPTO = False

_PREFIX = "enc:v1:"                     # marks an encrypted value; plaintext has no prefix


class Vault:
    """Loads or creates the local key and transparently encrypts/decrypts strings."""

    def __init__(self, key_path: str | os.PathLike, enabled: bool = True):
        self.path = Path(key_path)
        self.enabled = bool(enabled and HAVE_CRYPTO)
        self._aes = None
        if self.enabled:
            self._aes = AESGCM(self._load_or_create_key())

    @property
    def active(self) -> bool:
        return self.enabled and self._aes is not None

    def _load_or_create_key(self) -> bytes:
        if self.path.exists():
            raw = self.path.read_bytes()
            if len(raw) == 32:
                return raw
        key = AESGCM.generate_key(bit_length=256)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # write with owner-only permissions where the OS supports it
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return key

    def encrypt(self, text: str) -> str:
        if not self.active or text is None:
            return text
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, text.encode("utf-8"), None)
        return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, blob: str) -> str:
        if blob is None or not isinstance(blob, str) or not blob.startswith(_PREFIX):
            return blob                 # plaintext (written before encryption was on)
        if not self.active:
            raise RuntimeError("stored data is encrypted but the key is unavailable")
        raw = base64.b64decode(blob[len(_PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        return self._aes.decrypt(nonce, ct, None).decode("utf-8")

    def wipe_key(self):
        """Delete the key file. Without the key the ciphertext is unrecoverable, so
        this is part of a crypto-erase of the user's data."""
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass
