"""The token vault: the local, secret token->original mapping (plan §8).

The vault is the only thing that can reverse pseudonymisation, so it is treated
as the crown jewels:

* **Session-scoped by default.** A run gets its own ``session_id``; tokens are not
  global forever, so unrelated documents can't be correlated through a shared
  ``PERSON_001 = Alejandro`` mapping.
* **Authenticated encryption at rest** via AES-256-GCM with a scrypt-derived key,
  when a passphrase is supplied and the optional ``cryptography`` extra is
  installed. Without a passphrase the vault refuses to write plaintext unless you
  explicitly pass ``allow_plaintext=True``.
* Only tokens the vault *issued* are ever rehydrated (see :mod:`censorbot.rehydrate`).
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import asdict, dataclass, field

from .resolver import Entity
from .spans import EntityType
from .tokens import make_token

VAULT_MAGIC = "censorbot.vault"
VAULT_VERSION = 1


@dataclass
class VaultEntry:
    token: str
    entity_type: str
    value: str
    action: str
    occurrences: list[tuple[int, int]] = field(default_factory=list)


class Vault:
    """In-memory token->value store with encrypted persistence."""

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or secrets.token_hex(8)
        self._by_token: dict[str, VaultEntry] = {}

    # -- population --------------------------------------------------------
    def add_entity(self, entity: Entity, action: str, token: str | None = None) -> str:
        # `token` lets a caller supply a cross-document token (see TokenRegistry);
        # otherwise use the entity's per-document index.
        if token is None:
            token = make_token(entity.entity_type, entity.index)
        entry = self._by_token.get(token)
        occ = [(s.start, s.end) for s in entity.members]
        if entry is None:
            self._by_token[token] = VaultEntry(
                token, entity.entity_type.value, entity.canonical, action, occ
            )
        else:
            entry.occurrences.extend(occ)
        return token

    # -- lookup ------------------------------------------------------------
    def get(self, token: str) -> VaultEntry | None:
        return self._by_token.get(token)

    def value_for(self, token: str) -> str | None:
        entry = self._by_token.get(token)
        return entry.value if entry else None

    def tokens(self) -> list[str]:
        return list(self._by_token)

    def values(self) -> list[str]:
        return [e.value for e in self._by_token.values()]

    def __len__(self) -> int:
        return len(self._by_token)

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "magic": VAULT_MAGIC,
            "version": VAULT_VERSION,
            "session_id": self.session_id,
            "entries": [asdict(e) for e in self._by_token.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Vault":
        if data.get("magic") != VAULT_MAGIC:
            raise ValueError("not a censorbot vault")
        v = cls(session_id=data.get("session_id"))
        for e in data.get("entries", []):
            occ = [tuple(o) for o in e.get("occurrences", [])]
            v._by_token[e["token"]] = VaultEntry(
                e["token"], e["entity_type"], e["value"], e["action"], occ
            )
        return v

    # -- persistence -------------------------------------------------------
    def save(self, path: str, passphrase: str | None = None,
             allow_plaintext: bool = False) -> None:
        payload = json.dumps(self.to_dict()).encode("utf-8")
        if passphrase:
            envelope = _encrypt(payload, passphrase)
        elif allow_plaintext:
            envelope = {"magic": VAULT_MAGIC, "encrypted": False,
                        "data": base64.b64encode(payload).decode()}
        else:
            raise ValueError(
                "refusing to write an unencrypted vault; pass a passphrase or "
                "allow_plaintext=True"
            )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)

    @classmethod
    def load(cls, path: str, passphrase: str | None = None) -> "Vault":
        with open(path, encoding="utf-8") as fh:
            envelope = json.load(fh)
        if envelope.get("magic") != VAULT_MAGIC:
            raise ValueError("not a censorbot vault file")
        if envelope.get("encrypted"):
            if not passphrase:
                raise ValueError("vault is encrypted; a passphrase is required")
            try:
                payload = _decrypt(envelope, passphrase)
            except RuntimeError:
                raise  # missing crypto extra - already a clear message
            except Exception as exc:  # InvalidTag etc.
                raise ValueError("wrong passphrase or corrupted vault") from exc
        else:
            payload = base64.b64decode(envelope["data"])
        return cls.from_dict(json.loads(payload.decode("utf-8")))


# -- encryption helpers ----------------------------------------------------

def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except Exception as exc:  # pragma: no cover - depends on optional extra
        raise RuntimeError(
            "encryption needs the optional 'crypto' extra: pip install 'censorbot[crypto]'"
        ) from exc
    return AESGCM, Scrypt


def _derive(passphrase: str, salt: bytes):
    _, Scrypt = _require_crypto()
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt(payload: bytes, passphrase: str) -> dict:
    AESGCM, _ = _require_crypto()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, payload, None)
    return {
        "magic": VAULT_MAGIC,
        "encrypted": True,
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def _decrypt(envelope: dict, passphrase: str) -> bytes:
    AESGCM, _ = _require_crypto()
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    key = _derive(passphrase, salt)
    return AESGCM(key).decrypt(nonce, base64.b64decode(envelope["ct"]), None)
