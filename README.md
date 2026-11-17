# Pipeline de Ingeniería de Datos — Catálogo Farmacéutico e Historial de Compras

Pipeline modular de **extracción, limpieza, validación de calidad, seudonimización y consolidación** de catálogo farmacéutico (`30,326` SKUs base) e historial de compras efectivas (`77,774` líneas entregadas), diseñado con separación por etapas (`scrap/`, `etl/`, `compras_etl/` y `archivo_final/`), persistencia columnar en **Apache Parquet (Snappy)** y gestión de secretos mediante `python-dotenv`.

## Decisiones de Arquitectura y Privacidad

- **Configuración desacoplada (`.env`)**: Las URLs, dominios y puertos del portal proveedor, así como la clave secreta `FACTURA_HASH_SALT`, se cargan mediante `python-dotenv` y nunca se exponen en el código fuente (`.env` está excluido en `.gitignore`; se provee `.env.example` como plantilla).
- **Aislamiento del módulo de extracción (`scrap/`)**: Es el único módulo que opera sobre CSV (`scrap/data/catalogo_productos_raw.csv`), capturando únicamente las **7 columnas estructurales** del catálogo (`codigo`, `producto`, `droga`, `tipo`, `accion`, `clasificacion`, `laboratorio`) sin precios comerciales, descuentos ni niveles de stock.
- **Estandarización en formato Parquet**: Todos los scripts de procesamiento (`etl/` y `compras_etl/`) exportan exclusivamente archivos `.parquet` (compresión Snappy) con nombres cortos y descriptivos (`limpio.parquet`, `catalogo.parquet`, `compras.parquet`) y el consolidado final en [`archivo_final/maestro_compras.parquet`](archivo_final/maestro_compras.parquet).
- **Privacidad de compras y rutas relativas**: Los archivos crudos de `compras/` y los datos intermedios de `etl/data/interim/` están excluidos en `.gitignore`. El pipeline de compras seudonimiza los comprobantes (`factura`) de forma determinística con `HMAC-SHA256` + `FACTURA_HASH_SALT` (`.env`) antes de exportar [`compras_etl/data/processed/compras.parquet`](compras_etl/data/processed/compras.parquet). Los notebooks e informes imprimen únicamente rutas relativas al repositorio (sin rutas absolutas del sistema ni nombres de usuario).
- **Integridad referencial consolidada**: El archivo final [`archivo_final/maestro_compras.parquet`](archivo_final/maestro_compras.parquet) combina el catálogo limpio (`30,326` SKUs, leído en modo solo lectura) con los `758` SKUs huérfanos detectados en compras históricas (`31,084` SKUs totales), garantizando un `100%` de integridad referencial.

## Estructura del Proyecto

```text
farmacia-resolucion/
├── .env.example                                       # Plantilla de variables de entorno
├── .gitignore                                         # Exclusión de .env, entornos, compras/ e intermedios
├── README.md                                          # Documentación técnica y guía de uso
├── requirements.txt                                   # Dependencias del proyecto
├── scrap/                                             # Etapa 1: Extracción (aislada, salida CSV)
│   ├── data/
│   │   └── catalogo_productos_raw.csv                 # Dataset crudo de entrada (30,326 filas x 7 columnas)
│   └── scripts/
│       └── scrap.ipynb                                # Notebook de extracción puntual de SKUs
├── etl/                                               # Etapa 2: Limpieza, calidad y catálogo en Parquet
│   ├── data/
│   │   ├── interim/
│   │   │   └── limpio.parquet                         # Dataset intermedio normalizado (excluido en git)
│   │   └── processed/
│   │       └── catalogo.parquet                       # Catálogo limpio (30,326 filas x 7 columnas, 0.76 MB)
│   ├── reports/
│   │   └── 01_auditoria_formato_maestro.md            # Informe técnico de auditoría y conversión a Parquet
│   └── scripts/
│       └── etl_catalogo_maestro.ipynb                 # Notebook ETL del catálogo (auditoría, limpieza y Parquet)
├── compras_etl/                                       # Etapa 3: ETL, seudonimización y compras en Parquet
│   ├── data/
│   │   └── processed/
│   │       └── compras.parquet                        # Compras efectivas seudonimizadas (77,774 filas x 9 cols, 1.69 MB)
│   ├── reports/
│   │   └── 02_auditoria_compras_y_maestro.md          # Informe técnico de compras, HMAC-SHA256 y maestro final
│   └── scripts/
│       └── etl_compras.ipynb                          # Notebook ETL de compras y consolidación del maestro
└── archivo_final/                                     # Etapa 4: Maestro consolidado definitivo
    └── maestro_compras.parquet                        # Catálogo + SKUs huérfanos de compras (31,084 filas x 7 cols, 0.78 MB)
```

## Advertencia sobre el Módulo de Extracción (`scrap/`)

> ⚠️ **ADVERTENCIA:** `scrap/scripts/scrap.ipynb` es un script de scraping aislado que no debe modificarse ni ejecutarse masivamente (deja huella en el servidor). Utilizar únicamente para consultas puntuales de SKUs faltantes.

## Instalación y Ejecución

1. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Configurar variables de entorno (requerido para `scrap/` y para `FACTURA_HASH_SALT` en `compras_etl/`):**
   ```bash
   cp .env.example .env
   ```
3. **Ejecutar el pipeline ETL del catálogo:**
   Abrir y ejecutar todas las celdas de [`etl/scripts/etl_catalogo_maestro.ipynb`](etl/scripts/etl_catalogo_maestro.ipynb):
   - Lee `scrap/data/catalogo_productos_raw.csv` en UTF-8 preservando `codigo` como `str`.
   - Corrige **12,747** ocurrencias de *mojibake* CP850, colapsa espacios múltiples y guarda el intermedio `etl/data/interim/limpio.parquet`.
   - Valida ausencia de caracteres de control, unicidad de clave primaria (`codigo`) y completitud de campos obligatorios.
   - Exporta y verifica mediante `assert` el archivo [`etl/data/processed/catalogo.parquet`](etl/data/processed/catalogo.parquet) (`30,326` filas x `7` columnas, `0.76 MB`).
4. **Ejecutar el pipeline ETL de compras y consolidación del maestro:**
   Con `FACTURA_HASH_SALT` definido en `.env`, abrir y ejecutar todas las celdas de [`compras_etl/scripts/etl_compras.ipynb`](compras_etl/scripts/etl_compras.ipynb):
   - Lee en orden natural los `70` archivos `.txt` de `compras/` (`375,256` filas brutas entre `2021-01-01` y `2026-10-31`) usando el delimitador `" , "` y validando 9 columnas.
   - Sanitiza caracteres invisibles Unicode/control, colapsa `79,304` espacios múltiples en `producto`, normaliza en mayúsculas y convierte `fecha_hora` (`datetime64`), cantidades (`int32`) y `precio` (`float64`).
   - Verifica `0` facturas cruzadas entre archivos distintos, conserva las `22` repeticiones válidas intra-factura por topes promocionales, elimina la columna redundante `medio` (`698` nulos 100% en circuito `O`), descarta `56` encabezados de combos sin EAN y filtra únicamente las líneas con entrega efectiva (`cant_entr > 0`, descartando `297,426` registros sin entrega para obtener `77,774` filas efectivas).
   - Seudonimiza los `19,068` comprobantes únicos mediante `HMAC-SHA256` (`<PREFIJO>-<HASH[:10]>`) usando `FACTURA_HASH_SALT`, calcula `precio_unitario` e `importe_facturado` sin doble redondeo (eliminando `precio`) y ordena cronológicamente.
   - Exporta [`compras_etl/data/processed/compras.parquet`](compras_etl/data/processed/compras.parquet) (Snappy, `1.69 MB`) y certifica su integridad tras recargarlo con `pd.read_parquet` mediante `assert`.
   - Lee [`etl/data/processed/catalogo.parquet`](etl/data/processed/catalogo.parquet) en modo solo lectura, incorpora los `758` SKUs huérfanos presentes en compras (`5,204` SKUs únicos comprados) y genera [`archivo_final/maestro_compras.parquet`](archivo_final/maestro_compras.parquet) (`31,084` filas x `7` columnas, `0.78 MB`) con `100%` de integridad referencial.
