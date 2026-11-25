"""
Módulo de criptografía aplicada y seguridad de la aplicación.

Implementa:
1. Hashing de contraseñas con Argon2id (`pwdlib`, `argon2-cffi` o `PyNaCl`) y validación de fortaleza.
2. Cifrado simétrico autenticado de PII en reposo con Fernet (AES-128-CBC + HMAC-SHA256).
3. Blind Indexing determinístico con HMAC-SHA256 y hashing SHA-256 de tokens de un solo uso / refresh.
4. Emisión y verificación estricta de JWT Access Tokens (30 minutos, HS256, `jti`, `sub`, `role`, `type="access"`).
5. Generación de Refresh Tokens (7 días) con soporte de rotación estricta.
6. Generación y verificación en tiempo constante de tokens CSRF firmados con HMAC-SHA256 (Double Submit Cookie).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


_PASSWORD_BACKEND: str = "none"
_pwdlib_hasher: Any = None
_argon2_cffi_hasher: Any = None
_nacl_pwhash: Any = None

try:
    from pwdlib import PasswordHash

    _pwdlib_hasher = PasswordHash.recommended()
    _PASSWORD_BACKEND = "pwdlib"
except ImportError:
    try:
        from argon2 import PasswordHasher as _Argon2PasswordHasher

        _argon2_cffi_hasher = _Argon2PasswordHasher(
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            salt_len=16,
        )
        _PASSWORD_BACKEND = "argon2-cffi"
    except ImportError:
        try:
            import nacl.exceptions
            import nacl.pwhash

            _nacl_pwhash = nacl.pwhash
            _PASSWORD_BACKEND = "pynacl"
        except ImportError as exc:
            raise RuntimeError(
                "No se encontró ningún motor Argon2id instalado (pwdlib, argon2-cffi o PyNaCl)."
            ) from exc

_UPPERCASE_RE = re.compile(r"[A-Z]")
_LOWERCASE_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"\d")
_SPECIAL_RE = re.compile(r"[^A-Za-z0-9\s]")
_MIN_PASSWORD_LENGTH = 10


def validate_password_strength(password: str) -> str:
    """
    Valida que la contraseña cumpla la política de seguridad:
    - Mínimo 10 caracteres.
    - Al menos 1 letra mayúscula.
    - Al menos 1 letra minúscula.
    - Al menos 1 número.
    - Al menos 1 símbolo especial.

    Lanza `ValueError` descriptivo si no cumple los requisitos.
    """
    if not isinstance(password, str):
        raise ValueError("La contraseña debe ser una cadena de texto válida.")

    errors: list[str] = []
    if len(password) < _MIN_PASSWORD_LENGTH:
        errors.append(
            f"debe tener al menos {_MIN_PASSWORD_LENGTH} caracteres (actual: {len(password)})"
        )
    if not _UPPERCASE_RE.search(password):
        errors.append("debe incluir al menos una letra mayúscula (A-Z)")
    if not _LOWERCASE_RE.search(password):
        errors.append("debe incluir al menos una letra minúscula (a-z)")
    if not _DIGIT_RE.search(password):
        errors.append("debe incluir al menos un número (0-9)")
    if not _SPECIAL_RE.search(password):
        errors.append(
            "debe incluir al menos un carácter especial (ej. !@#$%^&*()-_=+)"
        )

    if errors:
        raise ValueError(
            "La contraseña no cumple con la política de seguridad: "
            + "; ".join(errors)
            + "."
        )
    return password


def hash_password(password: str) -> str:
    """
    Genera un hash Argon2id en formato PHC estándar (`$argon2id$v=19$...`).
    """
    if not password or not isinstance(password, str):
        raise ValueError("La contraseña a hashear no puede estar vacía.")

    if _PASSWORD_BACKEND == "pwdlib":
        return str(_pwdlib_hasher.hash(password))
    if _PASSWORD_BACKEND == "argon2-cffi":
        return str(_argon2_cffi_hasher.hash(password))
    if _PASSWORD_BACKEND == "pynacl":
        hashed_bytes: bytes = _nacl_pwhash.argon2id.str(password.encode("utf-8"))
        return hashed_bytes.decode("utf-8")

    raise RuntimeError("Motor Argon2id no inicializado.")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica en tiempo constante una contraseña en texto plano contra su hash Argon2id.
    Retorna `False` ante cualquier discrepancia o formato inválido sin propagar excepciones.
    """
    if (
        not plain_password
        or not hashed_password
        or not isinstance(plain_password, str)
        or not isinstance(hashed_password, str)
    ):
        return False

    try:
        if _PASSWORD_BACKEND == "pwdlib":
            return bool(_pwdlib_hasher.verify(plain_password, hashed_password))
        if _PASSWORD_BACKEND == "argon2-cffi":
            return bool(
                _argon2_cffi_hasher.verify(hashed_password, plain_password)
            )
        if _PASSWORD_BACKEND == "pynacl":
            return bool(
                _nacl_pwhash.verify(
                    hashed_password.encode("utf-8"),
                    plain_password.encode("utf-8"),
                )
            )
    except Exception:
        return False

    return False


def _build_fernet(raw_key: str | bytes | None = None) -> Fernet:
    """
    Construye una instancia `Fernet` validando que la clave sea de 32 bytes
    codificada en URL-safe Base64. Si recibe una cadena arbitraria, deriva
    de forma determinística una clave Fernet válida mediante SHA-256.
    """
    key_material = raw_key if raw_key is not None else settings.FERNET_KEY
    key_bytes = (
        key_material.encode("utf-8")
        if isinstance(key_material, str)
        else bytes(key_material)
    )
    try:
        decoded = base64.urlsafe_b64decode(key_bytes)
        if len(decoded) == 32:
            return Fernet(key_bytes)
    except Exception:
        pass

    derived_key = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    return Fernet(derived_key)


def encrypt_pii(plaintext: str | None) -> str | None:
    """
    Cifra un dato sensible (PII) mediante Fernet (AES-128-CBC + HMAC-SHA256).
    Si `plaintext` es `None` o cadena vacía, retorna `None`.
    """
    if plaintext is None or plaintext == "":
        return None
    fernet = _build_fernet()
    token_bytes = fernet.encrypt(str(plaintext).encode("utf-8"))
    return token_bytes.decode("utf-8")


def decrypt_pii(ciphertext: str | None) -> str | None:
    """
    Descifra un dato sensible (PII) cifrado con Fernet.
    Si `ciphertext` es `None` o cadena vacía, retorna `None`.
    Lanza `ValueError` si el token está adulterado o la clave no coincide.
    """
    if ciphertext is None or ciphertext == "":
        return None
    fernet = _build_fernet()
    try:
        decrypted_bytes = fernet.decrypt(str(ciphertext).encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "No fue posible descifrar el campo PII: firma inválida o clave incorrecta."
        ) from exc


def compute_blind_index(value: str) -> str:
    """
    Calcula un Blind Index determinístico mediante HMAC-SHA256 sobre el valor
    normalizado (`strip().lower()`). Retorna un digest hexadecimal de 64 caracteres.
    """
    if value is None:
        raise ValueError("El valor para blind index no puede ser None.")
    normalized = str(value).strip().lower()
    secret_bytes = settings.HMAC_SECRET.encode("utf-8")
    return hmac.new(
        secret_bytes, normalized.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def hash_token(raw_token: str) -> str:
    """
    Calcula el hash SHA-256 hexadecimal (64 caracteres) de un token opaco
    para su almacenamiento seguro en base de datos.
    """
    if not raw_token or not isinstance(raw_token, str):
        raise ValueError("El token a hashear no puede estar vacío.")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_one_time_token(
    expire_minutes: int | None = None,
) -> tuple[str, str, datetime]:
    """
    Genera un token criptográficamente seguro de un solo uso (verificación de email
    o recuperación de contraseña).

    Retorna `(raw_token, token_sha256_hash, expires_at)` con expiración por defecto
    de 15 minutos (`settings.ONE_TIME_TOKEN_EXPIRE_MINUTES`).
    """
    minutes = (
        expire_minutes
        if expire_minutes is not None
        else settings.ONE_TIME_TOKEN_EXPIRE_MINUTES
    )
    raw_token = secrets.token_urlsafe(32)
    token_sha256_hash = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=int(minutes))
    return raw_token, token_sha256_hash, expires_at


def create_access_token(
    subject: str,
    role: str,
    token_version: int = 1,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str, datetime]:
    """
    Crea un JWT Access Token firmado con HS256 y expiración exacta de 30 minutos
    (`settings.ACCESS_TOKEN_EXPIRE_MINUTES`).

    Incluye los claims obligatorios:
    - `sub`: Identificador del usuario (str)
    - `role`: Rol del usuario (`user` | `admin`)
    - `jti`: Identificador único del token (UUID4)
    - `iat`: Timestamp UTC de emisión
    - `exp`: Timestamp UTC de expiración
    - `type`: `"access"`

    Retorna `(encoded_jwt, jti, expires_at)`.
    """
    if not subject:
        raise ValueError("El subject ('sub') del JWT no puede estar vacío.")
    if not role:
        raise ValueError("El rol ('role') del JWT no puede estar vacío.")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = str(uuid.uuid4())

    payload: dict[str, Any] = {}
    if extra_claims:
        payload.update(extra_claims)

    payload.update(
        {
            "sub": str(subject),
            "role": str(role),
            "ver": int(token_version),
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "type": "access",
        }
    )

    encoded_jwt = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt, jti, expires_at


_revoked_jtis_lock = threading.Lock()
_revoked_jtis: dict[str, float] = {}


def revoke_access_token_jti(jti: str | None, exp: float | int | None = None) -> None:
    """Registra el `jti` de un Access Token revocado hasta su expiración."""
    if not jti or not isinstance(jti, str):
        return
    now_ts = datetime.now(timezone.utc).timestamp()
    exp_ts = float(exp) if exp is not None else now_ts + float(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60.0
    with _revoked_jtis_lock:
        expired = [k for k, v in _revoked_jtis.items() if v <= now_ts]
        for k in expired:
            _revoked_jtis.pop(k, None)
        _revoked_jtis[jti] = exp_ts


def is_access_token_revoked(jti: str | None) -> bool:
    """Verifica si un `jti` de Access Token fue revocado."""
    if not jti or not isinstance(jti, str):
        return False
    now_ts = datetime.now(timezone.utc).timestamp()
    with _revoked_jtis_lock:
        exp_ts = _revoked_jtis.get(jti)
        if exp_ts is None:
            return False
        if exp_ts <= now_ts:
            _revoked_jtis.pop(jti, None)
            return False
        return True


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodifica y valida un JWT Access Token verificando firma criptográfica,
    expiración y presencia de todos los claims obligatorios (`sub`, `role`,
    `jti`, `exp`, `iat`, `type == "access"`).

    Lanza `jwt.InvalidTokenError` (o subclases como `jwt.ExpiredSignatureError`)
    si el token es inválido, expiró o no es de tipo `"access"`.
    """
    if not token or not isinstance(token, str):
        raise jwt.InvalidTokenError("El token JWT proporcionado está vacío.")

    payload: dict[str, Any] = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "role", "jti", "exp", "iat", "type"]},
    )

    if payload.get("type") != "access":
        raise jwt.InvalidTokenError(
            f"Tipo de token inválido: se esperaba 'access', se recibió '{payload.get('type')}'."
        )

    if not payload.get("sub") or not payload.get("role") or not payload.get("jti"):
        raise jwt.InvalidTokenError(
            "El token JWT carece de valores válidos en 'sub', 'role' o 'jti'."
        )

    return payload


def generate_refresh_token(
    expire_days: int | None = None,
) -> tuple[str, str, datetime]:
    """
    Genera un Refresh Token opaco de alta entropía con expiración de 7 días
    (`settings.REFRESH_TOKEN_EXPIRE_DAYS`).

    Retorna `(raw_token, token_sha256_hash, expires_at)`.
    """
    days = (
        expire_days
        if expire_days is not None
        else settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    raw_token = secrets.token_urlsafe(48)
    token_sha256_hash = hash_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=int(days))
    return raw_token, token_sha256_hash, expires_at


def generate_csrf_token(session_hint: str = "") -> str:
    """
    Genera un token CSRF firmado con HMAC-SHA256 para el patrón Double Submit Cookie.
    Formato: `<nonce>.<timestamp>.<hint_digest>.<hmac_sha256_signature>`
    """
    nonce = secrets.token_hex(16)
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    hint_digest = (
        hashlib.sha256(session_hint.encode("utf-8")).hexdigest()[:12]
        if session_hint
        else "anon"
    )
    message = f"{nonce}.{timestamp}.{hint_digest}"
    signature = hmac.new(
        settings.CSRF_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{message}.{signature}"


def verify_csrf_token_signature(csrf_token: str) -> bool:
    """
    Verifica en tiempo constante (`hmac.compare_digest`) la integridad y autenticidad
    de la firma HMAC-SHA256 de un token CSRF.
    """
    if not csrf_token or not isinstance(csrf_token, str):
        return False

    parts = csrf_token.rsplit(".", 1)
    if len(parts) != 2:
        return False

    message, provided_signature = parts
    if not message or not provided_signature:
        return False

    msg_parts = message.split(".")
    if len(msg_parts) != 3 or not all(msg_parts):
        return False
    if not msg_parts[1].isdigit():
        return False

    expected_signature = hmac.new(
        settings.CSRF_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(provided_signature, expected_signature)


def verify_csrf_double_submit(
    cookie_token: str | None, header_token: str | None
) -> bool:
    """
    Verifica que el token CSRF enviado en la cookie coincida en tiempo constante
    con el enviado en la cabecera/formulario y que su firma HMAC-SHA256 sea válida.
    """
    if not cookie_token or not header_token:
        return False
    if not hmac.compare_digest(str(cookie_token), str(header_token)):
        return False
    return verify_csrf_token_signature(str(cookie_token))
