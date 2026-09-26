# H810 — Borrador del informe del experimento

> Generado por `experiment/report.py` desde `results.json` (corrida `20260926T034334Z-b7e4f0`, commit `7c85e75666`, 2026-09-26 03:43:34 UTC) y `docs/effort_log.csv`. **No edites los números a mano:** vuelve a generarlo.

## Lámina 2 — Resumen del experimento

**Título:** Experimento de seguridad Solventa: confidencialidad del consentimiento Open Finance (SEG-02) e integridad de la emisión de pólizas (SEG-08).

**Propósito:** validar con evidencia medible que las tácticas de seguridad elegidas (tokens internos de vida corta, verificación del consentimiento en el servicio dueño del dato, HMAC sobre la emisión y auditoría con falla cerrada) cumplen las medidas de respuesta de SEG-02 y SEG-08, e identificar cómo la ubicación de la verificación del consentimiento y la vida del token (punto de sensibilidad) afectan la revocación.

**Resultados obtenidos** (corrida `20260926T034334Z-b7e4f0`):

| Métrica | Meta | Observado | Resultado |
|---|---|---|---|
| SEG-02 revocación — C1 (claim, TTL 60 s) · punto de sensibilidad | ≤ 300 s | mín 60.6 s · mediana 60.6 s · máx 60.8 s | ✅ cumple |
| SEG-02 revocación — C2 (claim, TTL 300 s) · punto de sensibilidad | ≤ 300 s | mín 301.0 s · mediana 301.0 s · máx 301.2 s | ❌ no cumple |
| SEG-02 revocación — C3 (claim, TTL 900 s) · punto de sensibilidad | ≤ 300 s | mín 900.8 s · mediana 901.0 s · máx 901.3 s | ❌ no cumple |
| SEG-02 revocación — C4 (lookup, TTL 900 s, caché 0 s) · diseño propuesto | ≤ 300 s | mín 0.05 s · mediana 0.08 s · máx 0.09 s | ✅ cumple |
| SEG-02 revocación — C5 (lookup, TTL 900 s, caché 60 s) · diseño propuesto | ≤ 300 s | mín 60.1 s · mediana 60.1 s · máx 60.2 s | ✅ cumple |
| Accesos auditados (permitidos y denegados) | 100 % | 1581 de 1581 (100.0 %) | ✅ cumple |
| Payloads alterados rechazados | 100 % | 35 de 35 | ✅ cumple |
| Pólizas alteradas persistidas | 0 | 0 | ✅ cumple |
| Emisiones persistidas con integridad verificada | 100 % | 100.0 % | ✅ cumple |

**Esfuerzo total invertido:** **PENDIENTE** — `docs/effort_log.csv` no tiene horas registradas. Cada integrante debe registrar sus horas reales y regenerar este borrador.

## Lámina 3 — Hipótesis y diseño del experimento

**Hipótesis de diseño:** Sse confirmó para las condiciones del laboratorio en modo lookup. La revocación máxima fue de 0,094 s sin caché y 60,219 s con caché de 60 s. Las 1.581 solicitudes medidas quedaron auditadas y las pruebas de mínimo privilegio aprobaron. En SEG-08 se rechazaron 35 de 35 solicitudes alteradas o inválidas, sin persistir pólizas alteradas, y se aceptó la emisión válida. C2 y C3 no cumplieron el umbral medido de revocación.

**Punto de sensibilidad:** dónde se verifica el consentimiento (`claim`: dentro del token; `lookup`: en consent-service en cada uso), la vida del token (`TOKEN_TTL`) y la caché de autorizaciones (`CONSENT_CACHE_TTL`). Configuraciones medidas:

| Config | CONSENT_MODE | TOKEN_TTL | CONSENT_CACHE_TTL |
|---|---|---|---|
| C1 | claim | 60 s | — |
| C2 | claim | 300 s | — |
| C3 | claim | 900 s | — |
| C4 | lookup | 900 s | 0 s |
| C5 | lookup | 900 s | 60 s |

**Historia de arquitectura SEG-02 — Consentimiento Open Finance (confidencialidad)**

| Elemento | Valor |
|---|---|
| Fuente | Socio de distribución o servicio interno que intenta usar datos financieros |
| Estímulo | Solicitud de cotización con datos financieros, incluida una posterior a la revocación del consentimiento |
| Artefacto | Datos financieros consentidos (consent-service, quote-service) |
| Entorno | Operación normal |
| Respuesta | Solo el socio autorizado, para el propósito aprobado, usa los datos; un consentimiento revocado deja de autorizar su uso; cada decisión se registra |
| Medida | Revocación efectiva ≤ 300 s; 0 accesos fuera de propósito o de socio; 100 % de accesos auditados |

**Historia de arquitectura SEG-08 — Emisión de póliza íntegra (integridad)**

| Elemento | Valor |
|---|---|
| Fuente | Socio de distribución, o intermediario comprometido entre el socio y Solventa |
| Estímulo | Solicitud de emisión con prima, cobertura o tomador alterados tras firmarse |
| Artefacto | policy-service y su base de datos |
| Entorno | Operación normal |
| Respuesta | Se detecta la alteración y se rechaza antes de persistir; queda auditado |
| Medida | 100 % de emisiones con validación de integridad; 0 pólizas alteradas persistidas |

**Nivel de incertidumbre:** medio. Quedan fuera del PoC: integración real con Open Finance, gestión productiva de claves (KMS y rotación), proveedor de identidad definitivo y TLS entre servicios.

## Lámina 4 — Análisis

### 1. ¿Se confirmó la hipótesis?

La hipótesis quedó **confirmada**.

| Sub-hipótesis | Resultado | Evidencia |
|---|---|---|
| (a) Revocación efectiva ≤ 300 s con verificación en el servicio dueño | ✅ cumple | Con la verificación en el servicio dueño, el consentimiento revocado dejó de autorizar dentro de la meta de 300 s en todas las repeticiones (C4 (lookup, TTL 900 s, caché 0 s): máx 0.09 s; C5 (lookup, TTL 900 s, caché 60 s): máx 60.2 s). |
| (b) 100 % de los accesos auditados | ✅ cumple | Todos los requests del experimento a servicios protegidos quedaron auditados: 1581 de 1581 (100.0 %), incluidos permitidos y denegados. Por servicio: auth-service 72/72, consent-service 79/79, policy-service 40/40, quote-service 1390/1390. |
| (c) 100 % de payloads alterados rechazados, 0 pólizas alteradas persistidas | ✅ cumple | Todos los payloads alterados se rechazaron antes de persistir: 35 de 35 rechazados, 0 pólizas alteradas nuevas y 100.0 % de las pólizas guardadas con integridad verificada. |

**Punto de sensibilidad (modo claim):** C1 (TTL 60 s): máx 60.8 s; C2 (TTL 300 s): máx 301.2 s; C3 (TTL 900 s): máx 901.3 s.
- C1 cumple porque su TTL (60 s) es menor que la meta: la revocación está acotada por la vida del token.
- C2 queda en el límite: el TTL es igual a la meta y el rechazo llega al vencer el token más la re-autenticación (301.2 s, 1.2 s sobre la meta). La medición tiene una resolución de ±5 s por el polling.
- C3 viola la meta, como se esperaba: con el consentimiento dentro del token, la revocación solo se nota cuando el token expira (hasta 900 s). Es evidencia del punto de sensibilidad, no un fallo del diseño propuesto.

### 2. Decisiones de arquitectura que favorecieron el resultado

Solo para las métricas cumplidas (táctica → componente → métrica):

| Táctica | Componente | Métrica |
|---|---|---|
| Revocar acceso | consent-service marca REVOKED; quote-service consulta al dueño en cada uso (lookup) | Revocación efectiva: C4 máx 0.09 s, C5 máx 60.2 s |
| Mantener auditoría | audit-service append-only; cada servicio audita ALLOW y DENY y falla cerrado si no puede auditar | audit_coverage 100.0 % (1581/1581) |
| Verificar integridad del mensaje | policy-service verifica HMAC-SHA256 del payload canónico antes de abrir la transacción | 35/35 alterados rechazados; 0 filas nuevas |
| Autorizar actores | la clave HMAC se elige por el partner_uuid del token, nunca por el del body | 10/10 intentos con firma de otro socio o partner_uuid cruzado rechazados (TC-I-06, TC-I-07) |

### 3. Métricas no cumplidas: por qué y qué se cambiaría

| Métrica | Por qué no se cumplió | Cambio propuesto | Costo |
|---|---|---|---|
| SEG-02 revocación — C2 (claim, TTL 300 s) (punto de sensibilidad) | el consentimiento viaja en el token y quote-service no consulta al dueño; la revocación se nota al expirar el token (máx 301.2 s) | mover la verificación al servicio dueño (lookup, como C4/C5) o bajar TOKEN_TTL por debajo de 300 s | lookup: una llamada extra a consent-service por cotización (más latencia, en tensión con el escenario de latencia p95 ≤ 250 ms) y dependencia de su disponibilidad; TTL corto: más emisiones de token y carga en auth-service |
| SEG-02 revocación — C3 (claim, TTL 900 s) (punto de sensibilidad) | el consentimiento viaja en el token y quote-service no consulta al dueño; la revocación se nota al expirar el token (máx 901.3 s) | mover la verificación al servicio dueño (lookup, como C4/C5) o bajar TOKEN_TTL por debajo de 300 s | lookup: una llamada extra a consent-service por cotización (más latencia, en tensión con el escenario de latencia p95 ≤ 250 ms) y dependencia de su disponibilidad; TTL corto: más emisiones de token y carga en auth-service |

## Lámina 5 — Evidencias

| Evidencia | Archivo o fuente | Cómo obtenerla |
|---|---|---|
| Tabla de propagación por repetición | `results/results.csv` | Abrir y capturar |
| Gráfica de propagación por configuración | `results/propagation.png` | Insertar |
| Resumen, parámetros, commit y veredicto | `results/results.json` | run `20260926T034334Z-b7e4f0`, commit `7c85e75666` |
| Log de la corrida | `results/run_20260926T034334Z.log` | Extracto de una repetición |
| Extracto de auditoría por correlation_id | audit-service `GET /events` | Ver URLs de ejemplo abajo (stack arriba) |
| Estadísticas de auditoría | `http://127.0.0.1:5005/stats` | Capturar el JSON |
| Conteo de pólizas antes/después (SEG-08) | `results/results.json` → `seg08`; `http://127.0.0.1:5004/policies/count` | Tabla de casos abajo |
| Salida de pytest (TC-AU, TC-C, TC-I, TC-AD) | `results/pytest_output.txt` | `python -m pytest -v > results/pytest_output.txt` |

Correlation_ids de ejemplo para el extracto de auditoría (un permitido y un denegado por servicio):

  - auth-service · HTTP 200: `http://127.0.0.1:5005/events?correlation_id=c1-r1-e902a8ed-d302-440c-a937-96baa97e34b7`
  - auth-service · HTTP 401: `http://127.0.0.1:5005/events?correlation_id=probe-cdbfa2f3-1cfc-4062-8199-7e7747223161`
  - consent-service · HTTP 200: `http://127.0.0.1:5005/events?correlation_id=c1-r1-4e19c540-bae8-4795-8dc7-9dfb0aaf6a55`
  - consent-service · HTTP 404: `http://127.0.0.1:5005/events?correlation_id=probe-cee5c8ac-9c1e-4c14-ad20-6890a19cc13c`
  - policy-service · HTTP 201: `http://127.0.0.1:5005/events?correlation_id=probe-4b1f4ed1-ff39-42a5-bc79-17907bd30d38`
  - policy-service · HTTP 422: `http://127.0.0.1:5005/events?correlation_id=probe-783a999a-2c05-4a82-8bb0-129f5de2f98c`
  - quote-service · HTTP 200: `http://127.0.0.1:5005/events?correlation_id=c1-r1-584d5d5e-1048-487f-af4b-7f6799ddd6ed`
  - quote-service · HTTP 401: `http://127.0.0.1:5005/events?correlation_id=c1-r1-f7ca60db-77fc-43bd-b18f-320b92e46eeb`

**Casos SEG-08** (cada alteración enviada 5 veces):

| Caso | Alteración | Respuesta | Rechazados |
|---|---|---|---|
| TC-I-02 | prima alterada | HTTP 422 integrity_failed | 5/5 |
| TC-I-03 | cobertura alterada | HTTP 422 integrity_failed | 5/5 |
| TC-I-04 | tomador alterado | HTTP 422 integrity_failed | 5/5 |
| TC-I-05 | sin X-Signature | HTTP 400 missing_signature | 5/5 |
| TC-I-06 | firmado con clave de B y token de A | HTTP 422 integrity_failed | 5/5 |
| TC-I-07 | partner_uuid del body distinto al del token | HTTP 403 partner_mismatch | 5/5 |
| TC-I-08 | campo extra inyectado | HTTP 400 unknown_field | 5/5 |

**Nota de resolución:** el polling de SEG-02 es cada 5 s, así que cada tiempo de propagación tiene un error de ±5 s.
