# Plataforma de Autenticación Segura (FastAPI) y Pipeline de Ingeniería de Datos Farmacéuticos

Repositorio integral que combina:
1. **Plataforma Web de Autenticación, Autorización (RBAC) y Auditoría Forense (`app/` y `deploy/`)**: Aplicación **FastAPI + SQLAlchemy 2.0 Asíncrono + SQLite (WAL)** con hashing **Argon2id**, cifrado de PII en reposo (**Fernet**), *Blind Indexing* determinístico (**HMAC-SHA256**), rotación estricta de *Refresh Tokens* con detección de reúso, cookies `HttpOnly`/`Secure`/`SameSite=Lax` y protección **CSRF Double Submit Cookie**.
2. **Pipeline ETL y Analítica BI de Catálogo e Historial de Compras (`scrap/`, `etl/`, `compras_etl/`, `archivo_final/`, `database/`)**: Extracción controlada, limpieza de codificación, validación de calidad, seudonimización criptográfica de comprobantes (`HMAC-SHA256`), consolidación en **Apache Parquet (Snappy)** (`31,084` SKUs y `77,774` líneas de compra) y modelado analítico.

---

## Estructura del Proyecto

```text
farmacia-resolucion/
├── .env.example                                       # Plantilla parametrizada de variables de entorno
├── .gitignore                                         # Exclusión de secretos (.env), bases SQLite, cachés y crudos
├── README.md                                          # Documentación general, arquitectura y despliegue
├── requirements.txt                                   # Dependencias del pipeline ETL y notebooks de datos
├── 03_auditoria_y_exploracion_bi.ipynb                # Auditoría contable y exploración comercial BI
├── app/                                               # Aplicación web FastAPI (Autenticación, RBAC y Auditoría)
│   ├── alembic.ini                                    # Configuración de migraciones Alembic
│   ├── main.py                                        # Punto de entrada ASGI (FastAPI + Middlewares OWASP/CSRF)
│   ├── requirements.txt                               # Dependencias de la aplicación web y suite de tests
│   ├── core/                                          # Configuración, motor SQLite WAL, rate limiter y criptografía
│   ├── middlewares/                                   # Cabeceras de seguridad (CSP/HSTS) y auditoría/CSRF
│   ├── migrations/                                    # Revisiones de esquema Alembic (001 a 004)
│   ├── models/                                        # Modelos ORM (User, RefreshToken, OneTimeToken, AuditLog)
│   ├── routers/                                       # Endpoints SSR Jinja2, /auth, /users y /admin
│   ├── schemas/                                       # Validación estricta con Pydantic v2
│   ├── scripts/                                       # Utilidades CLI (create_admin.py, migrate_pg_to_sqlite.py)
│   ├── services/                                      # Lógica de dominio, rotación de sesiones y SMTP
│   ├── static/                                        # Estilos CSS y cliente JS (renovación silenciosa y formularios)
│   ├── templates/                                     # Vistas HTML SSR (Jinja2 + Pico.css con autoescaping XSS)
│   └── tests/                                         # Suite automatizada de seguridad y flujos funcionales
├── deploy/                                            # Artefactos de aprovisionamiento y despliegue seguro
│   ├── authsec.service                                # Unidad systemd endurecida
│   ├── backup_sqlite.sh                               # Respaldo atómico diario de SQLite
│   ├── setup_rpi.sh                                   # Script de aprovisionamiento en servidor Linux / Raspberry Pi
│   └── cloudflare/
│       └── config.yml                                 # Plantilla de Cloudflare Tunnel (<TUNNEL_UUID>, tu-dominio.com)
├── scrap/                                             # Etapa 1 ETL: Extracción puntual de catálogo (CSV)
│   ├── data/catalogo_productos_raw.csv                # Catálogo base (30,326 SKUs x 7 columnas estructurales)
│   └── scripts/scrap.ipynb                            # Notebook de consulta puntual de SKUs
├── etl/                                               # Etapa 2 ETL: Limpieza y normalización del catálogo
│   ├── data/processed/catalogo.parquet                # Catálogo validado en Parquet (Snappy)
│   └── scripts/etl_catalogo_maestro.ipynb             # Limpieza de mojibake y control de calidad
├── compras_etl/                                       # Etapa 3 ETL: Procesamiento y seudonimización de compras
│   └── scripts/etl_compras.ipynb                      # Limpieza, HMAC-SHA256 de facturas y consolidación
├── archivo_final/                                     # Etapa 4 ETL: Datasets maestros consolidados (Parquet)
│   ├── maestro_compras.parquet                        # Historial de compras efectivas seudonimizadas (77,774 filas)
│   └── maestro_productos.parquet                      # Catálogo + SKUs históricos (31,084 filas, 100% integridad)
└── database/
    └── carga_postgresql_bi.ipynb                      # Carga relacional en PostgreSQL y vistas analíticas BI
```

---

## Puesta en Marcha de la Aplicación Web (`app/`)

1. **Crear entorno virtual e instalar dependencias:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r app/requirements.txt
   ```

2. **Configurar variables de entorno:**
   ```bash
   cp .env.example .env
   ```
   Edita `.env` reemplazando todos los placeholders (`SECRET_KEY`, `FERNET_KEY`, `HMAC_SECRET`, `CSRF_SECRET`, `APP_BASE_URL=https://tu-dominio.com`, `ALLOWED_HOSTS` y credenciales `SMTP_*`). En modo `production`, el arranque valida que ninguna clave use valores por defecto ni tenga menos de 32 caracteres.

3. **Ejecutar migraciones y aprovisionar un administrador (opcional):**
   ```bash
   alembic -c app/alembic.ini upgrade head
   python -m app.scripts.create_admin \
       --email admin@ejemplo.com \
       --password "<PASSWORD_SEGURO>" \
       --full-name "Administrador General"
   ```

4. **Iniciar el servidor de desarrollo o producción local:**
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8480 --workers 1
   ```

5. **Ejecutar la suite de pruebas automatizadas:**
   ```bash
   pytest app/tests/
   ```

---

## Despliegue con Systemd y Cloudflare Tunnel (`deploy/`)

- **Unidad `systemd` y permisos mínimos:** Revisar `deploy/authsec.service` y ejecutar `sudo bash deploy/setup_rpi.sh /opt/authsec` para crear el usuario de sistema sin shell, proteger `/var/lib/authsec` (`chmod 700`) y habilitar el servicio.
- **Cloudflare Tunnel:** Copiar `deploy/cloudflare/config.yml` a `/home/<TU_USUARIO>/.cloudflared/config.yml`, reemplazando `<TU_USUARIO>`, `<TUNNEL_UUID>` y `tu-dominio.com` por los valores propios del entorno.

---

## Ejecución del Pipeline de Datos y BI

1. Instalar dependencias de datos:
   ```bash
   pip install -r requirements.txt
   ```
2. Definir en `.env` las variables opcionales del bloque ETL/BI (`FACTURA_HASH_SALT`, `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`).
3. Ejecutar en orden:
   - [`etl/scripts/etl_catalogo_maestro.ipynb`](etl/scripts/etl_catalogo_maestro.ipynb) para normalizar `scrap/data/catalogo_productos_raw.csv` hacia `etl/data/processed/catalogo.parquet`.
   - [`compras_etl/scripts/etl_compras.ipynb`](compras_etl/scripts/etl_compras.ipynb) para procesar `compras/` (excluido de Git por privacidad) y generar `archivo_final/maestro_compras.parquet` y `archivo_final/maestro_productos.parquet`.
   - [`database/carga_postgresql_bi.ipynb`](database/carga_postgresql_bi.ipynb) y [`03_auditoria_y_exploracion_bi.ipynb`](03_auditoria_y_exploracion_bi.ipynb) para la carga relacional y análisis comercial.

> **Advertencia sobre `scrap/`:** [`scrap/scripts/scrap.ipynb`](scrap/scripts/scrap.ipynb) es un notebook aislado para consultas puntuales de SKUs faltantes; no debe ejecutarse de forma masiva.
