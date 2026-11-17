# Reporte de Fase 1: Auditoría de Formato y Perfilado

**Archivo auditado:** [`scrap/data/catalogo_productos_raw.csv`](../../scrap/data/catalogo_productos_raw.csv) (solo lectura, sin modificaciones)  
**Notebook asociado:** [`etl/scripts/etl_catalogo_maestro.ipynb`](../scripts/etl_catalogo_maestro.ipynb)  
**Fecha:** 2026-11-17  

---

## 1. Inspección en Crudo y Estructura Física

| Propiedad | Resultado observado |
| :--- | :--- |
| **Tamaño del archivo** | `2,801,726` bytes (`2.67 MB`) |
| **Encoding físico** | **UTF-8 sin BOM** (validación estricta UTF-8 en todo el archivo: `OK`, 0 errores de decodificación) |
| **Delimitador** | Coma (`,`) |
| **Saltos de línea** | `LF` (`\n`, estilo Unix). En todo el archivo: `30,327` LF, `0` CRLF (`\r\n`), `0` CR sueltos (`\r`). |
| **Encabezado** | Presente en la **línea 1** (`7` columnas estructurales). Sin filas de título ni metadatos basura previos. |
| **Pie de página** | **Ninguno.** La última línea (`30,327`) es un registro de datos válido de 7 columnas. |
| **Líneas vacías** | `0` |

### Anomalía de Texto Detectada: Mojibake Mixto (CP850/CP437 en UTF-8)

Aunque el archivo es físicamente **UTF-8 válido**, contiene caracteres mal transcodificados en las columnas de texto (`producto`, `droga`, `tipo`, `accion`, `clasificacion`, `laboratorio`). Específicamente, bytes originales en **CP850/CP437** fueron interpretados como Latin-1 y re-codificados a UTF-8, coexistiendo con caracteres UTF-8 válidos:

| Carácter observado (UTF-8) | Frecuencia | Interpretación real (CP850/CP437) | Estado |
| :--- | ---: | :--- | :--- |
| `U+00A2` (`¢`) | 4,341 | `ó` | Mojibake |
| `U+00A0` (NBSP `\xa0`) | 3,506 | `á` | Mojibake |
| `U+0082` (`\x82`) | 2,906 | `é` | Mojibake |
| `U+00A1` (`¡`) | 1,557 | `í` | Mojibake |
| `U+0081` (`\x81`) | 974 | `ü` | Mojibake |
| `U+00D1` (`Ñ`) | 826 | `Ñ` | UTF-8 válido (no alterar) |
| `U+00A4` (`¤`) | 64 | `ñ` | Mojibake |
| `U+00D3` (`Ó`) | 43 | `Ó` | UTF-8 válido (no alterar) |
| `U+00A3` (`£`) | 19 | `ú` | Mojibake |
| `U+00C1` (`Á`) | 15 | `Á` | UTF-8 válido (no alterar) |
| `U+00C9` (`É`) | 3 | `É` | UTF-8 válido (no alterar) |
| `U+00B4` (`´`) | 2 | `´` | UTF-8 válido (no alterar) |
| `U+00DA` (`Ú`) | 1 | `Ú` | UTF-8 válido (no alterar) |

> [!WARNING]
> Debido a que coexisten caracteres UTF-8 válidos (`Ñ`, `Ó`, `Á`, `É`, `Ú`, `´`) con mojibake CP850, **no** se debe aplicar una reconversión ciega global `.encode('latin1').decode('cp850')`, ya que corrompería los caracteres UTF-8 válidos. En la fase de limpieza del notebook se aplica un reemplazo dirigido de los 7 caracteres afectados.

---

## 2. Resultado de Carga y Auditoría de Parseo

La carga se realizó con **Pandas** especificando `encoding="utf-8"`, delimitador `,` y forzando `dtype={"codigo": str}` para preservar ceros iniciales y la semántica de identificador en códigos EAN.

| Métrica | Valor |
| :--- | ---: |
| **Líneas físicas totales** | `30,327` (1 encabezado + 30,326 datos) |
| **Total de filas leídas (Pandas)** | `30,326` |
| **Columnas estructurales** | `7` |
| **Filas con errores de parseo** | `0` |
| **Filas perdidas** | `0` |

---

## 3. Esquema, Tipos de Datos y Porcentaje de Nulos

| # | Columna | Tipo (Pandas) | Tipo SQL sugerido | Nulos | % Nulos |
|---:|:---|:---|:---|---:|---:|
| 1 | `codigo` | `str` (forzado) | `VARCHAR` (`PRIMARY KEY`) | 0 | 0.00% |
| 2 | `producto` | `str` | `VARCHAR` | 0 | 0.00% |
| 3 | `droga` | `str` | `VARCHAR` | 19,819 | 65.35% |
| 4 | `tipo` | `str` | `VARCHAR` | 0 | 0.00% |
| 5 | `accion` | `str` | `VARCHAR` | 19,816 | 65.34% |
| 6 | `clasificacion` | `str` | `VARCHAR` | 19,816 | 65.34% |
| 7 | `laboratorio` | `str` | `VARCHAR` | 0 | 0.00% |

---

## 4. Ejemplo de 5 Filas Representativas

*(Se verificó que el dataset contiene exclusivamente catálogo estructural de productos y códigos de barras, sin datos personales/PII ni variables comerciales. En la vista previa se aplicó la corrección de mojibake solo para legibilidad).*

| codigo | producto | droga | tipo | accion | clasificacion | laboratorio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `7791984001727` | 102 ANOS FOCUS COM X30 | MAGNESIO+ASOC. | MEDICAMENTOS | SUPLEMENTO DIETARIO | COMPRIMIDOS/PASTILLAS/TABLETAS | GRAMON MILLET ROFINA |
| `7791984001758` | 102 ANOS MAGNESIO CITRATO COM X30 | MAGNESIO CITRATO | MEDICAMENTOS | SUPLEMENTO DIETARIO | COMPRIMIDOS/PASTILLAS/TABLETAS | GRAMON MILLET ROFINA |
| `7791984001512` | 102 ANOS MAGNESIO COM X30 | VIT.+MINERALES+ASOC. | MEDICAMENTOS | SUPLEMENTO DIETARIO | COMPRIMIDOS/PASTILLAS/TABLETAS | GRAMON MILLET ROFINA |
| `7791984001529` | 102 ANOS MAGNESIO GUMMIES X90 | MAGNESIO+ASOC. | MEDICAMENTOS | SUPLEMENTO DIETARIO | COMPRIMIDOS/PASTILLAS/TABLETAS | GRAMON MILLET ROFINA |
| `7791984001154` | 102 ANOS MUJER CAPS X30 | VIT.+MINERALES | MEDICAMENTOS | SUPLEMENTO DIETARIO | CÁPSULAS/SOFTGELS | GRAMON MILLET ROFINA |
