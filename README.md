# Experimento de seguridad Solventa — MISW4202 · Grupo 003

Experimento de arquitectura (no es un producto) que valida con evidencia medible dos escenarios de seguridad del caso Solventa:

- **SEG-02 — Consentimiento Open Finance (confidencialidad):** solo el socio autorizado, para el propósito aprobado, usa los datos financieros del cliente; un consentimiento revocado deja de autorizar su uso en **≤ 300 s**; el **100 %** de los accesos queda auditado.
- **SEG-08 — Emisión de póliza íntegra (integridad):** una emisión alterada después de firmada se rechaza **antes de persistir**; **0** pólizas alteradas guardadas.

Stack: Python + Flask, SQLite (una BD por servicio), Docker Compose.

## Estado

| Parte | Contenido | Estado |
|---|---|---|
| 1 | Esqueleto, `common/`, Docker Compose, `/health` | ✅ |
| 2 | auth-service, BFFs, núcleo de audit-service (TC-AU) | ✅ |
| 3 | consent-service y quote-service, modos claim/lookup y caché (TC-C) | ✅ |
| 4 | policy-service con HMAC y `partner_client.py` (TC-I) | ✅ |
| 5 | Falla cerrada de auditoría de punta a punta (TC-AD) | Pendiente |
| 6 | Arnés del experimento (`experiment/run.py`, C1–C5) | Pendiente |
| 7 | Generador del borrador H810 | Pendiente |
| 8 | Revisión crítica | Pendiente |

---

## 1. Qué necesitas

| Herramienta | Versión | Para qué | Cómo comprobarlo |
|---|---|---|---|
| Docker Desktop (o Docker Engine + Compose v2) | Compose 2.20 o superior | Levantar los 7 servicios | `docker compose version` |
| Python | 3.11 o superior | Correr las pruebas (y más adelante el arnés) | `python --version` |
| Git | cualquiera | Clonar el repo | `git --version` |

Además:

- **Puertos libres en tu máquina:** 8001, 8002, 5004 y 5005.
- **Docker Desktop abierto y en estado "Running"** antes de cualquier comando.
- `make` es **opcional**. En Windows se usa `scripts/tasks.ps1`, que hace lo mismo.

---

## 2. Paso a paso

Los comandos están para **Windows (PowerShell)** y **Mac/Linux (bash)**. Ejecútalos desde la carpeta raíz del repo.

### Paso 1 — Clonar

```bash
git clone <url-del-repo>
cd MISW4202-202614-Grupo003
```

### Paso 2 — Crear el entorno de Python e instalar dependencias

Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
```

Mac/Linux:
```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

### Paso 3 — Levantar los servicios

Este comando crea `.env` a partir de `.env.example` si no existe, construye las imágenes y espera a que los 7 servicios estén sanos. La primera vez tarda unos minutos.

Windows:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 up
```

Mac/Linux:
```bash
make up
```

### Paso 4 — Verificar que todo está arriba

Windows:
```powershell
.venv\Scripts\python scripts/check_health.py
```

Mac/Linux:
```bash
.venv/bin/python scripts/check_health.py
```

Resultado esperado:
```
OK   auth         compose=healthy
OK   consent      compose=healthy
OK   quote        compose=healthy
OK   policy       compose=healthy  http=200 (http://127.0.0.1:5004/health)
OK   audit        compose=healthy  http=200 (http://127.0.0.1:5005/health)
OK   bff-cliente  compose=healthy  http=200 (http://localhost:8001/health)
OK   bff-socio    compose=healthy  http=200 (http://localhost:8002/health)

Los 7 servicios están healthy.
```

### Paso 5 — Correr las pruebas

Windows:
```powershell
.venv\Scripts\python -m pytest -v
```

Mac/Linux:
```bash
.venv/bin/python -m pytest -v
```

Todas deben pasar. Hay dos tipos:

- **Unitarias** (`common/tests`, `services/*/tests`): no necesitan Docker.
- **End-to-end** (`tests/`): se ejecutan contra los contenedores. Si el stack no está arriba, pytest las marca como `skipped`; no fallan.

Para correr solo un grupo:
```bash
python -m pytest tests -v -k TC_AU     # autenticación y autorización
python -m pytest tests -v -k TC_C      # consentimiento
python -m pytest tests -v -k TC_I      # integridad de la emisión
```

### Paso 6 — Apagar

| Acción | Windows | Mac/Linux |
|---|---|---|
| Apagar y conservar los datos | `powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 down` | `make down` |
| Apagar y **borrar** BD y claves | `powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 reset` | `make reset` |

---

## 3. Probarlo a mano (flujo SEG-02 completo)

Este recorrido muestra la revocación en acción: el cliente da consentimiento, el socio cotiza, el cliente revoca y el socio queda bloqueado. Los secretos son los de desarrollo de `.env.example`.

### Windows (PowerShell)

```powershell
$A = "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11"   # partner_uuid del socio A

# 1. El cliente obtiene su token y crea un consentimiento para el socio A
$cli = (Invoke-RestMethod -Method Post http://localhost:8001/auth/token -ContentType "application/json" `
  -Body '{"client_id":"cliente-001","client_secret":"dev-c1"}').access_token
$consent = Invoke-RestMethod -Method Post http://localhost:8001/consents -ContentType "application/json" `
  -Headers @{Authorization="Bearer $cli"} -Body "{`"purpose`":`"quotation`",`"granted_to`":`"$A`"}"
$consent

# 2. El socio A obtiene su token y cotiza -> 200 con la prima
$soc = (Invoke-RestMethod -Method Post http://localhost:8002/auth/token -ContentType "application/json" `
  -Body '{"client_id":"socio-a","client_secret":"dev-sa"}').access_token
Invoke-RestMethod -Method Post http://localhost:8002/quotes -ContentType "application/json" `
  -Headers @{Authorization="Bearer $soc"} -Body '{"customer_id":"C-001","product":"auto"}'

# 3. El cliente revoca
Invoke-RestMethod -Method Post "http://localhost:8001/consents/$($consent.id)/revoke" -Headers @{Authorization="Bearer $cli"}

# 4. El socio vuelve a cotizar con el MISMO token -> 403 consent_revoked
try {
  Invoke-RestMethod -Method Post http://localhost:8002/quotes -ContentType "application/json" `
    -Headers @{Authorization="Bearer $soc"} -Body '{"customer_id":"C-001","product":"auto"}'
} catch { $_.ErrorDetails.Message }

# 5. Ver lo que quedó auditado
Invoke-RestMethod http://127.0.0.1:5005/stats | ConvertTo-Json -Depth 5
```

### Mac/Linux (bash + curl)

```bash
A=6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11

CLI=$(curl -s -X POST localhost:8001/auth/token -H 'Content-Type: application/json' \
  -d '{"client_id":"cliente-001","client_secret":"dev-c1"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
CONSENT_ID=$(curl -s -X POST localhost:8001/consents -H 'Content-Type: application/json' -H "Authorization: Bearer $CLI" \
  -d "{\"purpose\":\"quotation\",\"granted_to\":\"$A\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

SOC=$(curl -s -X POST localhost:8002/auth/token -H 'Content-Type: application/json' \
  -d '{"client_id":"socio-a","client_secret":"dev-sa"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:8002/quotes -H 'Content-Type: application/json' -H "Authorization: Bearer $SOC" \
  -d '{"customer_id":"C-001","product":"auto"}'; echo            # 200

curl -s -X POST localhost:8001/consents/$CONSENT_ID/revoke -H "Authorization: Bearer $CLI"; echo

curl -s -X POST localhost:8002/quotes -H 'Content-Type: application/json' -H "Authorization: Bearer $SOC" \
  -d '{"customer_id":"C-001","product":"auto"}'; echo            # 403 consent_revoked

curl -s 127.0.0.1:5005/stats; echo
```

### Ver el efecto del punto de sensibilidad (modo claim)

Cambia en `.env` la línea `CONSENT_MODE=lookup` por `CONSENT_MODE=claim` y vuelve a ejecutar `up` (Paso 3). Si repites el flujo, en el paso 4 el socio **sigue cotizando** con su token viejo: la revocación solo se nota cuando pide un token nuevo, que ya no incluye al cliente. Esa diferencia entre `lookup` y `claim` es lo que mide el experimento. Vuelve a `lookup` al terminar; las pruebas `TC_C` se omiten en otro modo.

---

## 4. Probar SEG-08 (integridad de la emisión)

`experiment/partner_client.py` actúa como el socio A: firma un payload con su clave HMAC y luego lo altera como lo haría un intermediario comprometido.

Windows:
```powershell
.venv\Scripts\python experiment/partner_client.py
```

Mac/Linux:
```bash
.venv/bin/python experiment/partner_client.py
```

Resultado esperado:
```
Payload íntegro: HTTP 201, filas nuevas 1
OK   TC-I-02 prima alterada                                HTTP 422 integrity_failed
OK   TC-I-03 cobertura alterada                            HTTP 422 integrity_failed
OK   TC-I-04 tomador alterado                              HTTP 422 integrity_failed
OK   TC-I-05 sin X-Signature                               HTTP 400 missing_signature
OK   TC-I-06 firmado con clave de B y token de A           HTTP 422 integrity_failed
OK   TC-I-07 partner_uuid del body distinto al del token   HTTP 403 partner_mismatch
OK   TC-I-08 campo extra inyectado                         HTTP 400 unknown_field

Alterados enviados: 7 · rechazados: 7 · filas nuevas por alterados: 0 · validation_rate: 1.00
```

Para ver el conteo de pólizas guardadas en cualquier momento: `http://127.0.0.1:5004/policies/count`.

## 5. Arquitectura

```
  Cliente ──▶ bff-cliente :8001          bff-socio :8002 ◀── Socio A / B
                    │                          │
      Bearer JWT + X-Correlation-ID (red interna, sin puertos al host)
     ┌──────────────┼──────────────┬───────────┼──────────────┐
     ▼              ▼              ▼           ▼              ▼
 auth :5001    consent :5002   quote :5003  policy :5004   audit :5005
 auth.db       consent.db      (sin BD)     policy.db      audit.db
```

| Servicio | Responsabilidad | Táctica principal |
|---|---|---|
| auth-service | Valida client_id + secreto (hash PBKDF2) y emite un JWT RS256 de vida corta con scopes mínimos | Autenticar actores, intercambio de tokens |
| consent-service | Crea, consulta y revoca consentimientos; decide si un uso está permitido | Revocar acceso, separar entidades |
| quote-service | Cotiza con datos financieros (mock) solo si el consentimiento lo permite | Autorizar actores |
| policy-service | Emite pólizas verificando HMAC antes de guardar; rechaza alteraciones, campos extra, firma ajena y nonce repetido | Verificar integridad del mensaje |
| audit-service | Registro append-only de cada decisión ALLOW/DENY | Mantener auditoría |
| bff-cliente / bff-socio | Única entrada de cada canal; reenvían sin lógica de negocio | Limitar exposición |

Reglas clave:

- Solo los BFF publican puertos. policy y audit se publican **solo en 127.0.0.1** (`docker-compose.experiment.yml`) para que las pruebas y el arnés lean `/policies/count`, `/events` y `/stats`.
- Cada servicio valida el JWT por sí mismo con la clave pública de auth-service; no confía en el BFF.
- **Falla cerrada:** si audit-service no responde en 2 s, la operación se rechaza con 503 y no se ejecuta.

---

## 6. Configuración (`.env`)

| Variable | Valor por defecto | Qué controla |
|---|---|---|
| `TOKEN_TTL` | 300 | Vida del JWT en segundos |
| `CONSENT_MODE` | lookup | `lookup`: quote pregunta a consent-service en cada uso. `claim`: usa la lista del token |
| `CONSENT_CACHE_TTL` | 0 | Segundos que quote-service cachea una autorización (solo en lookup) |
| `EXPERIMENT_MODE` | 1 | Habilita `/events`, `/stats` y `ttl` en `/token` para pruebas |
| `AUDIT_TIMEOUT_S` | 2 | Tiempo máximo para auditar antes de fallar cerrado |
| `PARTNER_A_UUID`, `PARTNER_B_UUID` | fijos | Identificador de cada socio |
| `PARTNER_HMAC_KEYS` | claves de desarrollo | Clave HMAC de cada socio (SEG-08) |
| `SEED_SECRETS` | secretos de desarrollo | Secretos de las 11 credenciales sembradas |

Credenciales de desarrollo (datos ficticios):

| client_id | Tipo | Identificador | Secreto |
|---|---|---|---|
| cliente-001 … cliente-005 | cliente | C-001 … C-005 | dev-c1 … dev-c5 |
| socio-a | socio | PARTNER_A_UUID | dev-sa |
| socio-b | socio | PARTNER_B_UUID | dev-sb |

`.env` no se versiona. **Nunca pongas secretos reales** en `.env.example` ni en el código.

---

## 7. Comandos disponibles

| Tarea | Windows (`scripts/tasks.ps1 <tarea>`) | Mac/Linux |
|---|---|---|
| Levantar | `up` | `make up` |
| Estado de salud | `health` | `make health` |
| Logs en vivo | `logs` | `make logs` |
| Apagar | `down` | `make down` |
| Apagar y borrar datos | `reset` | `make reset` |
| Linter (ruff) | `lint` | `make lint` |
| Pruebas unitarias | `test-unit` | `make test-unit` |
| Todas las pruebas | `test` | `make test` |
| Experimento *(Parte 6)* | `experiment` | `make experiment` |
| Borrador H810 *(Parte 7)* | `report` | `make report` |

En Windows la forma completa es `powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 <tarea>`. Las tareas `health`, `lint` y `test*` usan el `python` del sistema: activa antes el entorno con `.venv\Scripts\Activate.ps1`, o usa directamente `.venv\Scripts\python ...` como en los pasos anteriores.

---

## 8. Estructura del repo

```
.
├── docker-compose.yml             # 7 servicios; solo los BFF publican puertos
├── docker-compose.experiment.yml  # publica policy y audit en 127.0.0.1 (observación)
├── .env.example                   # configuración y secretos de DESARROLLO
├── Makefile · scripts/tasks.ps1   # tareas (Mac/Linux · Windows)
├── scripts/check_health.py        # verifica los 7 servicios
├── common/                        # librería compartida: JWT, scopes, auditoría, HMAC, errores
├── services/<servicio>/           # app.py, models.py, Dockerfile, requirements.txt, tests/
├── tests/                         # pruebas end-to-end contra Docker (TC-*)
├── experiment/                    # arnés del experimento (Parte 6)
├── results/                       # resultados generados por el arnés
└── docs/effort_log.csv            # horas REALES del equipo: fecha,integrante,tarea,horas
```

---

## 9. Problemas comunes

| Síntoma | Causa probable | Solución |
|---|---|---|
| `failed to connect to the docker API` / `cannot find the file specified` | Docker Desktop no está abierto | Abre Docker Desktop y espera a que diga "Running" |
| `Falta SEED_SECRETS. Copia .env.example a .env` | No existe `.env` | Usa `up` (lo crea solo) o copia `.env.example` a `.env` |
| `port is already allocated` | Otro programa usa 8001, 8002, 5004 o 5005 | Libera el puerto o apaga el otro contenedor (`docker ps`) |
| Las pruebas e2e salen como `skipped` | El stack no está arriba | Ejecuta el Paso 3 y verifica con el Paso 4 |
| Las pruebas `TC_C` salen como `skipped` | `.env` tiene `CONSENT_MODE=claim` o caché distinta de 0 | Vuelve a `CONSENT_MODE=lookup` y `CONSENT_CACHE_TTL=0` y ejecuta `up` |
| Un servicio queda `unhealthy` | Error al arrancar | Mira sus logs: `docker compose logs auth` (o el nombre del servicio) |
| Cambié código y no se refleja | La imagen es la anterior | `up` reconstruye las imágenes; si persiste, `reset` y `up` |
| `running scripts is disabled on this system` (Windows) | Política de ejecución de PowerShell | Usa siempre `powershell -ExecutionPolicy Bypass -File scripts/tasks.ps1 <tarea>` |

---

## 10. Cómo contribuir

- Una rama por integrante: `feat/<servicio>`. PR a `main` con las pruebas del servicio en verde.
- Commits con el formato `feat(policy): verificación HMAC antes de insertar`.
- Cada `app.py` empieza con un comentario que dice qué tácticas implementa y para qué ASR.
- Registra tus horas reales en `docs/effort_log.csv` el mismo día en que trabajas.
- Los resultados del informe salen solo de `results/results.json` y de `docs/effort_log.csv`; no se escriben a mano.
