"""
Suite Exhaustiva de Pruebas Automatizadas de Seguridad, Criptografía, Sesiones JWT/Refresh,
Detección de Reúso, Fuerza Bruta, Anti-IDOR, RBAC, Auditoría Forense y Plantillas Jinja2.

Compatible tanto con `pytest` como con `python3 -m unittest`.
"""

from __future__ import annotations

import json
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.tests.conftest import (
    build_jinja_environment,
    isolated_db_session,
    render_template_to_string,
)

import jwt
from sqlalchemy import select, text

from app.core.security import (
    compute_blind_index,
    create_access_token,
    decode_access_token,
    decrypt_pii,
    encrypt_pii,
    generate_csrf_token,
    generate_one_time_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_csrf_double_submit,
    verify_csrf_token_signature,
    verify_password,
)
from app.models.audit_log import AuditEventType, AuditLog
from app.models.token import OneTimeToken, RefreshToken
from app.models.user import User, UserRole
from app.schemas.user import (
    AdminUserUpdate,
    PasswordChangeRequest,
    UserCreate,
    UserProfileUpdate,
    UserRead,
)
from app.services.audit_service import sanitize_audit_details
from app.services.auth_service import (
    authenticate_user,
    logout_session,
    register_user,
    request_password_reset,
    reset_password_with_token,
    rotate_refresh_token,
    verify_email_token,
)
from app.services.email_service import get_last_sent_email
from app.services.user_service import (
    admin_update_user,
    change_own_password,
    enforce_anti_idor,
    get_user_recent_logins,
    list_audit_logs,
    update_own_profile,
)


class Test01Argon2AndPasswordPolicy(unittest.IsolatedAsyncioTestCase):
    """1. Verificación de Hashing Argon2id y política estricta de contraseñas."""

    def test_argon2id_hashing_and_constant_time_verification(self) -> None:
        raw_pwd = "FarmaciaSegura#2026!"
        hashed_1 = hash_password(raw_pwd)
        hashed_2 = hash_password(raw_pwd)

        self.assertTrue(
            hashed_1.startswith("$argon2id$"),
            f"El hash debe utilizar formato PHC Argon2id, se obtuvo: {hashed_1[:20]}",
        )
        self.assertNotEqual(raw_pwd, hashed_1)
        self.assertNotEqual(
            hashed_1,
            hashed_2,
            "Dos hashes Argon2id de la misma contraseña deben diferir por su salt aleatorio.",
        )

        self.assertTrue(verify_password(raw_pwd, hashed_1))
        self.assertTrue(verify_password(raw_pwd, hashed_2))
        self.assertFalse(verify_password("ContraseñIncorrecta#2026!", hashed_1))
        self.assertFalse(verify_password("", hashed_1))
        self.assertFalse(verify_password(raw_pwd, "$argon2id$corrupted$hash"))

    def test_password_strength_policy_rejects_weak_passwords(self) -> None:
        valid_pwd = "Clav3Fuerte$2026"
        self.assertEqual(validate_password_strength(valid_pwd), valid_pwd)

        weak_candidates = [
            "Ab1!cort",
            " minusculas123!@#",
            "MAYUSCULAS123!@#",
            "SinNumerosFuerte!@",
            "SinSimbolos123456",
        ]
        for candidate in weak_candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    validate_password_strength(candidate.strip())
                with self.assertRaises(ValueError):
                    UserCreate(
                        email="test@dominio.com",
                        password=candidate.strip(),
                        full_name="Usuario Test",
                    )


class Test02FernetPiiAndBlindIndexing(unittest.IsolatedAsyncioTestCase):
    """2 & 3. Cifrado simétrico Fernet de PII en reposo y Blind Indexing HMAC-SHA256."""

    async def test_fernet_encryption_in_db_and_transparent_orm_decryption(self) -> None:
        plain_phone = "+54 9 11 5555-9876"
        plain_doc = "DNI-34890123"
        plain_addr = "Av. Santa Fe 3420, Piso 7, CABA"

        async with isolated_db_session() as db:
            user = User(
                email="dra.gonzalez@farmacia.local",
                email_hash=compute_blind_index("dra.gonzalez@farmacia.local"),
                password_hash=hash_password("SeguridadPII#2026"),
                full_name="Dra. Laura González",
            )
            user.phone = plain_phone
            user.document_id = plain_doc
            user.address = plain_addr

            db.add(user)
            await db.commit()
            await db.refresh(user)

            self.assertIsNotNone(user.email_encrypted)
            self.assertNotEqual(user.email_encrypted, "dra.gonzalez@farmacia.local")
            self.assertTrue(str(user.email_encrypted).startswith("gAAAAA"))
            self.assertIsNotNone(user.full_name_encrypted)
            self.assertNotEqual(user.full_name_encrypted, "Dra. Laura González")
            self.assertTrue(str(user.full_name_encrypted).startswith("gAAAAA"))
            self.assertIsNotNone(user.phone_encrypted)
            self.assertIsNotNone(user.document_id_encrypted)
            self.assertIsNotNone(user.address_encrypted)
            self.assertNotEqual(user.phone_encrypted, plain_phone)
            self.assertNotEqual(user.document_id_encrypted, plain_doc)
            self.assertNotEqual(user.address_encrypted, plain_addr)
            self.assertTrue(str(user.phone_encrypted).startswith("gAAAAA"))
            self.assertTrue(str(user.document_id_encrypted).startswith("gAAAAA"))
            self.assertTrue(str(user.address_encrypted).startswith("gAAAAA"))

            raw_row = (
                await db.execute(
                    text(
                        "SELECT email_encrypted, full_name_encrypted, phone_encrypted, document_id_encrypted, address_encrypted "
                        "FROM users WHERE email_hash = :email_hash"
                    ),
                    {"email_hash": compute_blind_index("dra.gonzalez@farmacia.local")},
                )
            ).fetchone()
            self.assertIsNotNone(raw_row)
            self.assertNotIn("dra.gonzalez@farmacia.local", raw_row[0])
            self.assertNotIn("Dra. Laura González", raw_row[1])
            self.assertNotIn(plain_phone, raw_row[2])
            self.assertNotIn(plain_doc, raw_row[3])
            self.assertNotIn(plain_addr, raw_row[4])

            self.assertEqual(user.email, "dra.gonzalez@farmacia.local")
            self.assertEqual(user.full_name, "Dra. Laura González")

            self.assertEqual(user.phone, plain_phone)
            self.assertEqual(user.document_id, plain_doc)
            self.assertEqual(user.address, plain_addr)

            user_read = UserRead.from_user(user)
            self.assertEqual(user_read.phone, plain_phone)
            self.assertEqual(user_read.document_id, plain_doc)
            self.assertEqual(user_read.address, plain_addr)

        valid_cipher = encrypt_pii("SecretoCritico")
        assert valid_cipher is not None
        tampered_cipher = valid_cipher[:-4] + ("AAAA" if valid_cipher[-4:] != "AAAA" else "BBBB")
        with self.assertRaises(ValueError):
            decrypt_pii(tampered_cipher)

    def test_hmac_sha256_blind_indexing_deterministic_and_normalized(self) -> None:
        hash_a = compute_blind_index("  Admin.Seguridad@Farmacia.COM  ")
        hash_b = compute_blind_index("admin.seguridad@farmacia.com")
        hash_c = compute_blind_index("otro.usuario@farmacia.com")

        self.assertEqual(len(hash_a), 64)
        self.assertEqual(
            hash_a,
            hash_b,
            "El Blind Index debe ser determinístico e insensible a mayúsculas y espacios.",
        )
        self.assertNotEqual(hash_a, hash_c)


class Test03JwtAndOneTimeTokens(unittest.IsolatedAsyncioTestCase):
    """4. Ciclo de JWT Access Token (30 min) y tokens de un solo uso SHA-256 (15 min)."""

    def test_jwt_access_token_30_minutes_and_claims(self) -> None:
        user_id = str(uuid.uuid4())
        token_str, jti, expires_at = create_access_token(
            subject=user_id,
            role=UserRole.ADMIN.value,
        )

        payload = decode_access_token(token_str)
        self.assertEqual(payload["sub"], user_id)
        self.assertEqual(payload["role"], "admin")
        self.assertEqual(payload["jti"], jti)
        self.assertEqual(payload["type"], "access")
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)
        self.assertEqual(
            payload["exp"] - payload["iat"],
            30 * 60,
            "El JWT Access Token debe tener una vigencia exacta de 30 minutos (1800 segundos).",
        )

        from app.core.config import settings

        forged_refresh_jwt = jwt.encode(
            {
                "sub": user_id,
                "role": "user",
                "jti": str(uuid.uuid4()),
                "iat": payload["iat"],
                "exp": payload["exp"],
                "type": "refresh",
            },
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        with self.assertRaises(jwt.InvalidTokenError):
            decode_access_token(forged_refresh_jwt)

    def test_one_time_token_sha256_and_15_minutes_window(self) -> None:
        before = datetime.now(timezone.utc)
        raw_token, token_sha256, expires_at = generate_one_time_token()
        after = datetime.now(timezone.utc)

        self.assertGreaterEqual(len(raw_token), 32)
        self.assertEqual(len(token_sha256), 64)
        self.assertNotEqual(raw_token, token_sha256)
        self.assertEqual(hash_token(raw_token), token_sha256)

        min_expected = before + timedelta(minutes=15) - timedelta(seconds=2)
        max_expected = after + timedelta(minutes=15) + timedelta(seconds=2)
        self.assertGreaterEqual(expires_at, min_expected)
        self.assertLessEqual(expires_at, max_expected)

    def test_csrf_double_submit_signature_verification(self) -> None:
        csrf_tok = generate_csrf_token(session_hint="user-session-123")
        self.assertTrue(verify_csrf_token_signature(csrf_tok))
        self.assertTrue(verify_csrf_double_submit(csrf_tok, csrf_tok))
        self.assertFalse(verify_csrf_double_submit(csrf_tok, csrf_tok + "x"))
        self.assertFalse(verify_csrf_double_submit(csrf_tok, None))


class Test04RegistrationVerificationLoginAndLockout(unittest.IsolatedAsyncioTestCase):
    """5. Registro, verificación de email, login exitoso y bloqueo tras 5 intentos fallidos."""

    async def test_register_verify_email_and_login_flow(self) -> None:
        async with isolated_db_session() as db:
            create_payload = UserCreate(
                email="Nuevo.Farmaceutico@Farmacia.com",
                password="PasswordSegura!2026",
                full_name="Lic. Martín Pérez",
                phone="+54 11 4000-1111",
                document_id="30111222",
                address="Av. Belgrano 900",
            )
            user, raw_verify_token, email_info = await register_user(
                db=db,
                payload=create_payload,
                ip_address="192.168.1.25",
                user_agent="Mozilla/5.0 QA-Test",
            )

            self.assertEqual(user.email, "nuevo.farmaceutico@farmacia.com")
            self.assertFalse(user.is_verified)
            self.assertEqual(user.phone, "+54 11 4000-1111")
            self.assertIsNotNone(raw_verify_token)
            self.assertEqual(email_info["type"], "email_verification")

            stored_ott = await db.scalar(
                select(OneTimeToken).where(OneTimeToken.user_id == user.id)
            )
            self.assertIsNotNone(stored_ott)
            assert stored_ott is not None
            self.assertEqual(stored_ott.token_hash, hash_token(raw_verify_token))
            self.assertNotEqual(stored_ott.token_hash, raw_verify_token)

            verified_user = await verify_email_token(
                db=db,
                raw_token=raw_verify_token,
                ip_address="192.168.1.25",
            )
            self.assertTrue(verified_user.is_verified)

            from fastapi import HTTPException

            with self.assertRaises(HTTPException) as ctx:
                await verify_email_token(db=db, raw_token=raw_verify_token)
            self.assertEqual(ctx.exception.status_code, 400)

            session_data = await authenticate_user(
                db=db,
                email="nuevo.farmaceutico@farmacia.com",
                password="PasswordSegura!2026",
                ip_address="192.168.1.25",
                user_agent="Mozilla/5.0 QA-Test",
            )
            self.assertIn("access_token", session_data)
            self.assertIn("refresh_token", session_data)
            self.assertIn("csrf_token", session_data)
            self.assertEqual(session_data["expires_in"], 1800)

    async def test_brute_force_account_lockout_after_5_failed_attempts(self) -> None:
        from fastapi import HTTPException

        async with isolated_db_session() as db:
            payload = UserCreate(
                email="bloqueo@farmacia.com",
                password="CorrectPassword#2026",
                full_name="Usuario Prueba Bloqueo",
            )
            user, _, _ = await register_user(db=db, payload=payload)

            for attempt in range(1, 5):
                with self.assertRaises(HTTPException) as err_ctx:
                    await authenticate_user(
                        db=db,
                        email="bloqueo@farmacia.com",
                        password=f"WrongPass#{attempt}",
                        ip_address="10.0.0.50",
                    )
                self.assertEqual(err_ctx.exception.status_code, 401)

            await db.refresh(user)
            self.assertEqual(user.failed_login_attempts, 4)
            self.assertFalse(user.is_locked)

            before_lock = datetime.now(timezone.utc)
            with self.assertRaises(HTTPException) as lock_ctx:
                await authenticate_user(
                    db=db,
                    email="bloqueo@farmacia.com",
                    password="WrongPass#5",
                    ip_address="10.0.0.50",
                )
            self.assertEqual(lock_ctx.exception.status_code, 403)

            await db.refresh(user)
            self.assertEqual(user.failed_login_attempts, 5)
            self.assertTrue(user.is_locked)
            self.assertIsNotNone(user.locked_until)
            assert user.locked_until is not None
            lock_until_utc = (
                user.locked_until
                if user.locked_until.tzinfo is not None
                else user.locked_until.replace(tzinfo=timezone.utc)
            )
            self.assertGreaterEqual(
                lock_until_utc,
                before_lock + timedelta(minutes=14, seconds=55),
            )

            lock_logs = await list_audit_logs(
                db=db,
                event_type=AuditEventType.ACCOUNT_LOCKED.value,
                user_id=user.id,
            )
            self.assertEqual(len(lock_logs), 1)
            self.assertEqual(lock_logs[0].details.get("failed_attempts"), 5)
            self.assertEqual(lock_logs[0].details.get("lockout_minutes"), 15)

            with self.assertRaises(HTTPException) as blocked_ctx:
                await authenticate_user(
                    db=db,
                    email="bloqueo@farmacia.com",
                    password="CorrectPassword#2026",
                    ip_address="10.0.0.50",
                )
            self.assertEqual(blocked_ctx.exception.status_code, 403)


class Test05RefreshTokenRotationAndReuseDetection(unittest.IsolatedAsyncioTestCase):
    """6. Rotación estricta de Refresh Token y Detección de Reúso con revocación total."""

    async def test_refresh_token_rotation_and_reuse_detection_revokes_all_user_sessions(
        self,
    ) -> None:
        from fastapi import HTTPException

        async with isolated_db_session() as db:
            payload = UserCreate(
                email="sesiones@farmacia.com",
                password="SessionKey#2026!",
                full_name="Analista de Sesiones",
            )
            user, verify_tok, _ = await register_user(db=db, payload=payload)
            await verify_email_token(db=db, raw_token=verify_tok)

            login_a = await authenticate_user(
                db=db,
                email="sesiones@farmacia.com",
                password="SessionKey#2026!",
                ip_address="172.16.0.10",
                user_agent="Laptop-Chrome",
            )
            refresh_a1 = login_a["refresh_token"]

            login_b = await authenticate_user(
                db=db,
                email="sesiones@farmacia.com",
                password="SessionKey#2026!",
                ip_address="172.16.0.11",
                user_agent="Mobile-Safari",
            )
            refresh_b1 = login_b["refresh_token"]

            rotated_a = await rotate_refresh_token(
                db=db,
                raw_refresh_token=refresh_a1,
                ip_address="172.16.0.10",
                user_agent="Laptop-Chrome",
            )
            refresh_a2 = rotated_a["refresh_token"]
            self.assertNotEqual(refresh_a1, refresh_a2)

            with self.assertRaises(HTTPException) as reuse_ctx:
                await rotate_refresh_token(
                    db=db,
                    raw_refresh_token=refresh_a1,
                    ip_address="203.0.113.99",
                    user_agent="Attacker-Client",
                )
            self.assertEqual(reuse_ctx.exception.status_code, 401)

            all_user_tokens = list(
                (
                    await db.scalars(
                        select(RefreshToken).where(RefreshToken.user_id == user.id)
                    )
                ).all()
            )
            self.assertGreaterEqual(len(all_user_tokens), 3)
            self.assertTrue(
                all(tok.is_revoked for tok in all_user_tokens),
                "Todos los RefreshTokens del usuario deben quedar revocados tras detectar reúso.",
            )

            reuse_logs = await list_audit_logs(
                db=db,
                event_type=AuditEventType.TOKEN_REUSE_DETECTED.value,
                user_id=user.id,
            )
            self.assertEqual(len(reuse_logs), 1)
            self.assertEqual(
                reuse_logs[0].details.get("action"),
                "revoked_all_user_sessions",
            )
            self.assertEqual(
                reuse_logs[0].details.get("revoked_active_sessions"),
                2,
            )

            for tok_candidate in (refresh_a2, refresh_b1):
                with self.assertRaises(HTTPException) as post_revoke_ctx:
                    await rotate_refresh_token(db=db, raw_refresh_token=tok_candidate)
                self.assertEqual(post_revoke_ctx.exception.status_code, 401)

    async def test_password_reset_flow_and_logout(self) -> None:
        async with isolated_db_session() as db:
            payload = UserCreate(
                email="recuperar@farmacia.com",
                password="ClaveOriginal#2026",
                full_name="Usuario Recuperación",
            )
            user, _, _ = await register_user(db=db, payload=payload)
            login_res = await authenticate_user(
                db=db,
                email="recuperar@farmacia.com",
                password="ClaveOriginal#2026",
            )

            reset_req = await request_password_reset(
                db=db,
                email="recuperar@farmacia.com",
                ip_address="127.0.0.1",
            )
            raw_reset_tok = reset_req["raw_token"]
            self.assertIsNotNone(raw_reset_tok)
            last_mail = get_last_sent_email(
                recipient="recuperar@farmacia.com",
                email_type="password_reset",
            )
            self.assertIsNotNone(last_mail)

            await reset_password_with_token(
                db=db,
                raw_token=raw_reset_tok,
                new_password="NuevaClaveFuerte$2027",
                ip_address="127.0.0.1",
            )

            tok_record = await db.scalar(
                select(RefreshToken).where(
                    RefreshToken.token_hash == hash_token(login_res["refresh_token"])
                )
            )
            self.assertIsNotNone(tok_record)
            assert tok_record is not None
            self.assertTrue(tok_record.is_revoked)

            new_session = await authenticate_user(
                db=db,
                email="recuperar@farmacia.com",
                password="NuevaClaveFuerte$2027",
            )
            await logout_session(
                db=db,
                raw_refresh_token=new_session["refresh_token"],
                user_id=user.id,
            )
            logout_logs = await list_audit_logs(
                db=db,
                event_type=AuditEventType.LOGOUT.value,
                user_id=user.id,
            )
            self.assertEqual(len(logout_logs), 1)


class Test06AntiIdorRbacAuditAndTemplates(unittest.IsolatedAsyncioTestCase):
    """7. Protección Anti-IDOR, RBAC, sanitización de `audit_logs` y plantillas HTML con CSRF."""

    async def test_anti_idor_protection_and_audit_details_sanitization(self) -> None:
        from fastapi import HTTPException

        async with isolated_db_session() as db:
            user_a, _, _ = await register_user(
                db=db,
                payload=UserCreate(
                    email="usuario.a@farmacia.com",
                    password="PasswordUserA#2026",
                    full_name="Usuario A",
                    phone="+54 11 1111-1111",
                    document_id="DNI-11111111",
                    address="Calle A 123",
                ),
            )
            user_b, _, _ = await register_user(
                db=db,
                payload=UserCreate(
                    email="usuario.b@farmacia.com",
                    password="PasswordUserB#2026",
                    full_name="Usuario B",
                ),
            )

            with self.assertRaises(HTTPException) as idor_ctx:
                await update_own_profile(
                    db=db,
                    current_user=user_a,
                    payload=UserProfileUpdate(full_name="Nombre Hackeado"),
                    target_user_id=user_b.id,
                    ip_address="192.0.2.88",
                )
            self.assertEqual(idor_ctx.exception.status_code, 403)

            with self.assertRaises(HTTPException):
                await enforce_anti_idor(
                    db=db,
                    current_user=user_a,
                    target_user_id=user_b.id,
                )

            secret_new_phone = "+54 9 11 9999-0000"
            secret_new_doc = "PASAPORTE-XYZ-987654"
            secret_new_addr = "Av. Reservada 7777, Depto 9B"

            updated_a = await update_own_profile(
                db=db,
                current_user=user_a,
                payload=UserProfileUpdate(
                    full_name="Usuario A Actualizado",
                    phone=secret_new_phone,
                    document_id=secret_new_doc,
                    address=secret_new_addr,
                ),
                target_user_id=user_a.id,
            )
            self.assertEqual(updated_a.phone, secret_new_phone)
            self.assertEqual(updated_a.document_id, secret_new_doc)
            self.assertEqual(updated_a.address, secret_new_addr)

            profile_logs = await list_audit_logs(
                db=db,
                event_type=AuditEventType.PROFILE_UPDATED.value,
                user_id=user_a.id,
            )
            self.assertEqual(len(profile_logs), 1)
            details_dict = profile_logs[0].details
            self.assertEqual(
                 sorted(details_dict.get("modified_fields", [])),
                ["address", "document_id", "full_name", "phone"],
            )
            serialized_details = json.dumps(details_dict)
            self.assertNotIn(secret_new_phone, serialized_details)
            self.assertNotIn(secret_new_doc, serialized_details)
            self.assertNotIn(secret_new_addr, serialized_details)

            dirty_payload = {
                "modified_fields": ["phone", "password"],
                "phone": secret_new_phone,
                "document_id": secret_new_doc,
                "address": secret_new_addr,
                "password": "PlaintextPassword!123",
                "access_token": "eyJhbGciOiJIUzI1Ni...",
                "refresh_token": "raw_refresh_secret",
                "ip_info": "ok",
            }
            cleaned = sanitize_audit_details(dirty_payload)
            self.assertIn("modified_fields", cleaned)
            self.assertIn("ip_info", cleaned)
            for forbidden in (
                "phone",
                "document_id",
                "address",
                "password",
                "access_token",
                "refresh_token",
            ):
                self.assertNotIn(forbidden, cleaned)

    async def test_rbac_admin_operations_and_password_change(self) -> None:
        from fastapi import HTTPException

        async with isolated_db_session() as db:
            standard_user, _, _ = await register_user(
                db=db,
                payload=UserCreate(
                    email="estandar@farmacia.com",
                    password="StandardUser#2026",
                    full_name="Usuario Estándar",
                ),
            )
            admin_user, _, _ = await register_user(
                db=db,
                payload=UserCreate(
                    email="admin@farmacia.com",
                    password="AdminMaster#2026",
                    full_name="Administrador General",
                ),
            )
            admin_user.role = UserRole.ADMIN.value
            await db.commit()
            await db.refresh(admin_user)

            with self.assertRaises(HTTPException) as rbac_ctx:
                await admin_update_user(
                    db=db,
                    admin_user=standard_user,
                    target_user_id=admin_user.id,
                    payload=AdminUserUpdate(is_active=False),
                )
            self.assertEqual(rbac_ctx.exception.status_code, 403)

            standard_user.failed_login_attempts = 5
            standard_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            await db.commit()

            updated_target = await admin_update_user(
                db=db,
                admin_user=admin_user,
                target_user_id=standard_user.id,
                payload=AdminUserUpdate(
                    role="admin",
                    is_active=True,
                    unlock_account=True,
                ),
            )
            self.assertEqual(updated_target.role, "admin")
            self.assertEqual(updated_target.failed_login_attempts, 0)
            self.assertIsNone(updated_target.locked_until)

            await change_own_password(
                db=db,
                current_user=standard_user,
                payload=PasswordChangeRequest(
                    current_password="StandardUser#2026",
                    new_password="NewStandardUser$2027",
                    confirm_password="NewStandardUser$2027",
                ),
            )
            recent = await get_user_recent_logins(db=db, user_id=standard_user.id)
            self.assertGreaterEqual(len(recent), 2)

    def test_jinja2_templates_render_with_csrf_and_xss_protection(self) -> None:
        csrf_tok = generate_csrf_token(session_hint="template-render-test")
        env = build_jinja_environment()
        self.assertTrue(env.autoescape)

        mock_user = {
            "id": uuid.uuid4(),
            "email": "auditor@farmacia.com",
            "full_name": "Auditor <script>alert('xss')</script>",
            "phone": "+54 11 5555-0000",
            "document_id": "29888777",
            "address": "Av. Cabildo 2040",
            "role": "admin",
            "is_active": True,
            "is_verified": True,
            "failed_login_attempts": 0,
            "locked_until": None,
        }
        mock_logs = [
            {
                "id": uuid.uuid4(),
                "user_id": mock_user["id"],
                "event_type": "LOGIN_SUCCESS",
                "ip_address": "127.0.0.1",
                "user_agent": "Pytest-Jinja2-Verify/1.0",
                "details": {"modified_fields": ["phone"]},
                "created_at": datetime.now(timezone.utc),
            }
        ]

        templates_to_verify = [
            ("login.html", {"csrf_token": csrf_tok, "dev_verification_link": "http://localhost:8000/auth/verify-email?token=abc"}),
            ("register.html", {"csrf_token": csrf_tok}),
            ("forgot_password.html", {"csrf_token": csrf_tok, "dev_reset_link": "http://localhost:8000/reset-password?token=xyz"}),
            ("reset_password.html", {"csrf_token": csrf_tok, "token": "tok_1234567890"}),
            ("profile.html", {"csrf_token": csrf_tok, "current_user": mock_user, "user": mock_user, "recent_logins": mock_logs}),
            ("admin_dashboard.html", {"csrf_token": csrf_tok, "current_user": mock_user, "users": [mock_user], "audit_logs": mock_logs}),
        ]

        for tpl_name, ctx in templates_to_verify:
            with self.subTest(template=tpl_name):
                rendered = render_template_to_string(tpl_name, **ctx)
                self.assertIn(f'<meta name="csrf-token" content="{csrf_tok}">', rendered)
                self.assertIn(f'name="csrf_token" value="{csrf_tok}"', rendered)
                self.assertIn('/static/js/auth_refresh.js', rendered)
                self.assertIn('/static/css/styles.css', rendered)
                self.assertNotIn("<script>alert('xss')</script>", rendered)
                self.assertNotRegex(rendered, r"<script(?![^>]*\bsrc=)")
                self.assertNotRegex(rendered, r"\bon(?:click|submit|load)=")

    async def test_csp_has_no_unsafe_inline_in_script_src(self) -> None:
        from fastapi.testclient import TestClient
        from app.main import app
        from app.middlewares.security_headers import DEFAULT_CSP_POLICY

        self.assertIn("script-src 'self';", DEFAULT_CSP_POLICY)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", DEFAULT_CSP_POLICY)

        client = TestClient(app, base_url="http://127.0.0.1:8480")
        resp = client.get("/login")
        csp = resp.headers.get("content-security-policy", "")
        self.assertIn("script-src 'self';", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)


class TestHardeningPhaseAAndB(unittest.IsolatedAsyncioTestCase):
    """8. Pruebas de hardening para Fase A (Cloudflare Tunnel) y Fase B (RPi Zero 2 W)."""

    async def test_trusted_proxies_and_cf_connecting_ip(self) -> None:
        from types import SimpleNamespace
        from app.services.audit_service import extract_client_ip

        trusted_req = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            headers={"cf-connecting-ip": "198.51.100.42", "x-forwarded-for": "203.0.113.9"},
            state=SimpleNamespace(),
        )
        self.assertEqual(extract_client_ip(trusted_req), "198.51.100.42")

        untrusted_req = SimpleNamespace(
            client=SimpleNamespace(host="203.0.113.55"),
            headers={"cf-connecting-ip": "198.51.100.42", "x-forwarded-for": "10.0.0.1"},
            state=SimpleNamespace(),
        )
        self.assertEqual(extract_client_ip(untrusted_req), "203.0.113.55")

    async def test_production_secrets_validation(self) -> None:
        from types import SimpleNamespace
        from app.core.config import DEFAULT_FERNET_KEY, validate_production_security

        bad_cfg = SimpleNamespace(
            ENVIRONMENT="production",
            SECRET_KEY="cambia-esta-clave-secreta-jwt-minimo-32-bytes-produccion-2026",
            FERNET_KEY=DEFAULT_FERNET_KEY,
            HMAC_SECRET="short",
            CSRF_SECRET="x" * 40,
            COOKIE_SECURE=True,
        )
        with self.assertRaises(ValueError):
            validate_production_security(bad_cfg)

        bad_cookie_cfg = SimpleNamespace(
            ENVIRONMENT="production",
            SECRET_KEY="A" * 48,
            FERNET_KEY="B" * 44,
            HMAC_SECRET="C" * 48,
            CSRF_SECRET="D" * 48,
            COOKIE_SECURE=False,
        )
        with self.assertRaises(ValueError):
            validate_production_security(bad_cookie_cfg)

        good_cfg = SimpleNamespace(
            ENVIRONMENT="production",
            SECRET_KEY="A" * 48,
            FERNET_KEY="B" * 44,
            HMAC_SECRET="C" * 48,
            CSRF_SECRET="D" * 48,
            COOKIE_SECURE=True,
        )
        validate_production_security(good_cfg)

    async def test_token_version_revocation_trusted_host_openapi_and_rate_limit(self) -> None:
        from types import SimpleNamespace
        from fastapi.testclient import TestClient
        from app.core.database import get_db
        from app.core.limiter import reset_rate_limiter
        from app.main import app, create_application
        from app.core.config import settings

        reset_rate_limiter()
        async with isolated_db_session() as db:
            user = User(
                email="hardening@farmacia.com",
                password_hash=hash_password("Hardening!Pass#2026"),
                full_name="Usuario Hardening",
                role=UserRole.USER.value,
                is_active=True,
                is_verified=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

            async def override_get_db():
                yield db

            app.dependency_overrides[get_db] = override_get_db
            try:
                client = TestClient(app, base_url="http://127.0.0.1:8480")

                r_bad_host = client.get("/health", headers={"Host": "evil.example.com"})
                self.assertEqual(r_bad_host.status_code, 400)

                orig_allowed_hosts = list(settings.ALLOWED_HOSTS)
                try:
                    settings.ALLOWED_HOSTS = ["tu-dominio.com", "localhost", "127.0.0.1"]
                    cf_client = TestClient(create_application(), base_url="http://127.0.0.1:8480")
                    r_cf_host = cf_client.get("/health", headers={"Host": "tu-dominio.com"})
                    self.assertEqual(r_cf_host.status_code, 200)
                finally:
                    settings.ALLOWED_HOSTS = orig_allowed_hosts

                r_login = client.post(
                    "/auth/login",
                    json={"email": "hardening@farmacia.com", "password": "Hardening!Pass#2026"},
                )
                self.assertEqual(r_login.status_code, 200)
                tok = r_login.json()
                hdrs = {"Authorization": f"Bearer {tok['access_token']}", "X-CSRF-Token": tok["csrf_token"]}

                r_me = client.get("/users/me", headers=hdrs)
                self.assertEqual(r_me.status_code, 200)

                # Logout increments token_version; clearing in-memory blacklist proves DB token_version enforces 401
                r_out = client.post("/auth/logout", headers=hdrs)
                self.assertEqual(r_out.status_code, 200)
                from app.core.security import _revoked_jtis
                _revoked_jtis.clear()
                self.assertEqual(client.get("/users/me", headers=hdrs).status_code, 401)

                # Re-login and test rate limit on password change (5/60s -> 6th returns 429)
                r_login2 = client.post(
                    "/auth/login",
                    json={"email": "hardening@farmacia.com", "password": "Hardening!Pass#2026"},
                )
                tok2 = r_login2.json()
                hdrs2 = {"Authorization": f"Bearer {tok2['access_token']}", "X-CSRF-Token": tok2["csrf_token"]}
                for _ in range(5):
                    client.post(
                        "/users/me/password",
                        headers=hdrs2,
                        json={"current_password": "Wrong!Password1", "new_password": "New!Password#2026", "confirm_password": "New!Password#2026"},
                    )
                r_rl = client.post(
                    "/users/me/password",
                    headers=hdrs2,
                    json={"current_password": "Wrong!Password1", "new_password": "New!Password#2026", "confirm_password": "New!Password#2026"},
                )
                self.assertEqual(r_rl.status_code, 429)
            finally:
                app.dependency_overrides.pop(get_db, None)

        # Verify openapi_url=None when is_production is True
        orig_env = settings.ENVIRONMENT
        try:
            settings.ENVIRONMENT = "production"
            prod_app = create_application()
            self.assertIsNone(prod_app.openapi_url)
            self.assertIsNone(prod_app.docs_url)
            self.assertIsNone(prod_app.redoc_url)
        finally:
            settings.ENVIRONMENT = orig_env


if __name__ == "__main__":
    unittest.main(verbosity=2)
