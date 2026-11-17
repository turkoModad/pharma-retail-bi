# Pipeline de Ingeniería de Datos — Catálogo Maestro Farmacéutico

Pipeline modular de **extracción, limpieza, validación de calidad y normalización** de un catálogo de **30,326 productos** farmacéuticos, diseñado con separación por etapas (`scrap/` y `etl/`), gestión de secretos mediante `python-dotenv` y validaciones automáticas de integridad para carga directa en PostgreSQL (`COPY`).

## Decisiones de Arquitectura y Privacidad

- **Configuración desacoplada (`.env`)**: Las URLs, dominios y puertos del portal proveedor se cargan mediante `python-dotenv` y nunca se exponen en el código fuente (`.env` está excluido en `.gitignore`; se provee `.env.example` como plantilla).
- **Minimización de datos**: El módulo de extracción captura únicamente las **7 columnas estructurales** del catálogo (`codigo`, `producto`, `droga`, `tipo`, `accion`, `clasificacion`, `laboratorio`), omitiendo precios comerciales, descuentos y niveles de stock.
- **Privacidad de compras y rutas**: Los archivos crudos de `compras/` están excluidos en `.gitignore`. El pipeline de compras seudonimiza los comprobantes (`factura`) de forma determinística con `HMAC-SHA256` + `FACTURA_HASH_SALT` (`.env`) antes de exportar [`compras_etl/data/processed/compras_historico.parquet`](compras_etl/data/processed/compras_historico.parquet). Los notebooks y reportes imprimen únicamente rutas relativas al repositorio (sin rutas absolutas del sistema ni nombres de usuario).
- **Salida final anonimizada**: El dataset procesado del catálogo se exporta como `etl/data/processed/catalogo_productos_final.csv` sin referencias al proveedor de origen.

## Estructura del Proyecto

```text
farmacia-resolucion/
├── .env.example                                   # Plantilla de variables de entorno
├── .gitignore                                     # Exclusión de .env, entornos, compras y datos privados
├── README.md                                      # Documentación técnica y guía de uso
├── requirements.txt                               # Dependencias del proyecto
├── scrap/                                         # Etapa 1: Extracción (aislada)
│   ├── data/
│   │   └── catalogo_productos_raw.csv             # Dataset crudo de entrada
│   └── scripts/
│       └── scrap.ipynb                            # Notebook de extracción puntual de SKUs
├── etl/                                           # Etapa 2: Limpieza, calidad y catálogo final
│   ├── data/
│   │   ├── interim/
│   │   │   └── catalogo_productos_limpio.csv      # Dataset intermedio normalizado
│   │   └── processed/
│   │       └── catalogo_productos_final.csv       # Catálogo maestro final (7 columnas, 30,326 filas)
│   ├── reports/
│   │   └── 01_auditoria_formato_maestro.md        # Reporte de auditoría de formato y codificación
│   └── scripts/
│       └── etl_catalogo_maestro.ipynb             # Notebook ETL unificado (auditoría, limpieza y validación)
└── compras_etl/                                   # Etapa 3: ETL, seudonimización y exportación de compras
    ├── data/
    │   └── processed/
    │       └── compras_historico.parquet          # Histórico depurado y seudonimizado (9 columnas, 375,200 filas)
    └── scripts/
        └── etl_compras.ipynb                      # Notebook ETL unificado (ingesta, limpieza, HMAC-SHA256 y Parquet)
```

## Advertencia sobre el Módulo de Extracción (`scrap/`)

> ⚠️ **ADVERTENCIA:** `scrap/scripts/scrap.ipynb` es un script de scraping. **NO ejecutar masivamente** (deja huella en el servidor). Utilizar únicamente para consultas puntuales de SKUs faltantes.

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
   - Carga el CSV crudo en UTF-8 preservando `codigo` como `str`.
   - Corrige **12,747** ocurrencias de *mojibake* CP850 y colapsa espacios múltiples.
   - Valida ausencia de caracteres de control, unicidad de clave primaria (`codigo`) y completitud de campos críticos.
   - Exporta y verifica mediante `assert` el archivo final [`etl/data/processed/catalogo_productos_final.csv`](etl/data/processed/catalogo_productos_final.csv).
4. **Ejecutar el pipeline ETL de compras:**
   Con `FACTURA_HASH_SALT` definido en `.env`, abrir y ejecutar todas las celdas de [`compras_etl/scripts/etl_compras.ipynb`](compras_etl/scripts/etl_compras.ipynb):
   - Lee en orden natural los 70 archivos `.txt` de `compras/` (UTF-8 estricto con respaldo `cp1252`, `375,256` filas brutas) usando el delimitador `" , "` y validando 9 columnas.
   - Sanitiza caracteres invisibles Unicode/control, colapsa espacios múltiples, normaliza `producto` en mayúsculas y convierte `fecha_hora` (`datetime64`), cantidades (`int32`) y `precio` (`float64`).
   - Verifica `0` facturas cruzadas entre archivos distintos, conserva las `22` repeticiones válidas intra-factura por topes promocionales, elimina la columna redundante `medio` (nulos 100% en circuito `O`) y descarta `56` encabezados de combos sin EAN (`375,200` filas depuradas).
   - Seudonimiza los `19,707` comprobantes únicos mediante `HMAC-SHA256` (`<PREFIJO>-<HASH[:10]>`) usando `FACTURA_HASH_SALT`, calcula `precio_unitario` e `importe_facturado` (eliminando `precio`) y ordena cronológicamente.
   - Exporta a [`compras_etl/data/processed/compras_historico.parquet`](compras_etl/data/processed/compras_historico.parquet) (Snappy, `2.64 MB`) y certifica su integridad tras recargarlo con `pd.read_parquet` mediante `assert`.
