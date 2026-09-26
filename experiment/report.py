"""Genera docs/H810_borrador.md desde results/results.json y docs/effort_log.csv (§16, parte 7).

Reglas: todo número sale de esos dos archivos; nada se escribe a mano. El análisis se elige
según los datos: si una métrica no se cumplió, el borrador lo dice, explica por qué y propone
el cambio con su costo. Si faltan horas, lo marca como pendiente en lugar de inventar.

Uso:
    python experiment/report.py
    python experiment/report.py --results <ruta>/results.json --out <ruta>/H810.md
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from experiment.envfile import ROOT  # noqa: E402

OFFICIAL_CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
OFFICIAL_REPS = 5

HYPOTHESIS = (
    "Si Solventa autentica a cada actor con un JWT interno de vida corta y scopes mínimos, "
    "valida el consentimiento en el servicio dueño del dato en cada uso (y no en claims del "
    "token), verifica HMAC-SHA256 del payload de emisión antes de persistir y registra toda "
    "decisión en un servicio de auditoría, entonces: **(a)** un consentimiento revocado deja de "
    "autorizar el uso de datos en ≤ 5 minutos, **(b)** el 100 % de los accesos —permitidos y "
    "denegados— queda auditado, y **(c)** el 100 % de los payloads de emisión alterados se "
    "rechaza sin generar registros en la base de pólizas."
)

SUBHYPOTHESES = {
    "a": "Revocación efectiva ≤ 300 s con verificación en el servicio dueño",
    "b": "100 % de los accesos auditados",
    "c": "100 % de payloads alterados rechazados, 0 pólizas alteradas persistidas",
}


# --- Utilidades de formato ------------------------------------------------------------------


def fmt_s(value: float | None) -> str:
    if value is None:
        return "sin rechazo"
    return f"{value:.2f} s" if value < 1 else f"{value:.1f} s"


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def fmt_pct(value: float) -> str:
    return f"{value * 100:.1f} %"


def mark(value: bool | None) -> str:
    if value is None:
        return "— no evaluado"
    return "✅ cumple" if value else "❌ no cumple"


def table(headers: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def config_label(cfg: dict) -> str:
    cache = f", caché {cfg['cache_ttl']} s" if cfg["mode"] == "lookup" else ""
    return f"{cfg['config']} ({cfg['mode']}, TTL {cfg['token_ttl']} s{cache})"


# --- Entradas -------------------------------------------------------------------------------


def load_effort(path: Path) -> dict:
    """Suma horas de effort_log.csv. Acepta coma o punto decimal; reporta filas inválidas."""
    result = {"total": 0.0, "by_member": {}, "rows": 0, "invalid": 0, "exists": path.exists()}
    if not path.exists():
        return result
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                hours = float(str(row.get("horas", "")).strip().replace(",", "."))
                member = (row.get("integrante") or "").strip()
                if hours < 0 or not member:
                    raise ValueError
            except ValueError:
                result["invalid"] += 1
                continue
            result["rows"] += 1
            result["total"] += hours
            result["by_member"][member] = result["by_member"].get(member, 0.0) + hours
    return result


def is_partial(results: dict) -> bool:
    params = results.get("parameters", {})
    return params.get("configs") != OFFICIAL_CONFIGS or params.get("reps") != OFFICIAL_REPS


def run_warnings(results: dict) -> list[str]:
    warnings = []
    params = results.get("parameters", {})
    if is_partial(results):
        configs = ", ".join(params.get("configs") or []) or "ninguna"
        reps = plural(params.get("reps") or 0, "repetición", "repeticiones")
        warnings.append(
            f"Corrida **parcial** ({configs}; {reps}): sirve para verificar el arnés, no es la "
            f"evidencia oficial (C1–C5 con {OFFICIAL_REPS} repeticiones)."
        )
    if results.get("git_dirty"):
        warnings.append(
            "La corrida se hizo con cambios sin subir (`git_dirty: true`): el commit registrado "
            "no reproduce exactamente el código medido."
        )
    return warnings


# --- Lámina 2 -------------------------------------------------------------------------------


def lamina2(r: dict, effort: dict) -> str:
    audit, seg08 = r["audit"], r["seg08"]
    rows = []
    for cfg in r["seg02"]:
        role = "diseño propuesto" if cfg["mode"] == "lookup" else "punto de sensibilidad"
        observed = (f"mín {fmt_s(cfg['min'])} · mediana {fmt_s(cfg['median'])} · "
                    f"máx {fmt_s(cfg['max'])}")
        if cfg["unobserved"]:
            observed += f" · {cfg['unobserved']} sin rechazo"
        rows.append([f"SEG-02 revocación — {config_label(cfg)} · {role}", "≤ 300 s", observed,
                     mark(cfg["meets_target"])])
    rows.append(["Accesos auditados (permitidos y denegados)", "100 %",
                 f"{audit['events']} de {audit['requests']} ({fmt_pct(audit['coverage'])})",
                 mark(audit["meets_target"])])
    if seg08:
        rows.append(["Payloads alterados rechazados", "100 %",
                     f"{seg08['rejected']} de {seg08['tampered_sent']}",
                     mark(seg08["rejected"] == seg08["tampered_sent"])])
        rows.append(["Pólizas alteradas persistidas", "0", str(seg08["rows_added"]),
                     mark(seg08["rows_added"] == 0)])
        rows.append(["Emisiones persistidas con integridad verificada", "100 %",
                     fmt_pct(seg08["validation_rate"]), mark(seg08["validation_rate"] == 1.0)])

    if effort["rows"]:
        members = ", ".join(f"{m}: {h:g} h" for m, h in sorted(effort["by_member"].items()))
        effort_text = (f"**{effort['total']:g} horas** ({effort['rows']} registros en "
                       f"`docs/effort_log.csv`). Por integrante: {members}.")
        if effort["invalid"]:
            effort_text += (f" ⚠️ {effort['invalid']} filas inválidas no se sumaron; "
                            "revisa el archivo.")
    else:
        effort_text = ("**PENDIENTE** — `docs/effort_log.csv` no tiene horas registradas. "
                       "Cada integrante debe registrar sus horas reales y regenerar este borrador.")

    return f"""## Lámina 2 — Resumen del experimento

**Título:** Experimento de seguridad Solventa: confidencialidad del consentimiento Open Finance \
(SEG-02) e integridad de la emisión de pólizas (SEG-08).

**Propósito:** validar con evidencia medible que las tácticas de seguridad elegidas (tokens \
internos de vida corta, verificación del consentimiento en el servicio dueño del dato, HMAC \
sobre la emisión y auditoría con falla cerrada) cumplen las medidas de respuesta de SEG-02 y \
SEG-08, e identificar cómo la ubicación de la verificación del consentimiento y la vida del \
token (punto de sensibilidad) afectan la revocación.

**Resultados obtenidos** (corrida `{r['run_id']}`):

{table(["Métrica", "Meta", "Observado", "Resultado"], rows)}

**Esfuerzo total invertido:** {effort_text}
"""


# --- Lámina 3 -------------------------------------------------------------------------------


def lamina3(r: dict) -> str:
    variables = table(
        ["Config", "CONSENT_MODE", "TOKEN_TTL", "CONSENT_CACHE_TTL"],
        [[c["config"], c["mode"], f"{c['token_ttl']} s",
          f"{c['cache_ttl']} s" if c["cache_ttl"] is not None else "—"] for c in r["seg02"]],
    )
    seg02 = table(["Elemento", "Valor"], [
        ["Fuente", "Socio de distribución o servicio interno que intenta usar datos financieros"],
        ["Estímulo", "Solicitud de cotización con datos financieros, incluida una posterior a la "
                     "revocación del consentimiento"],
        ["Artefacto", "Datos financieros consentidos (consent-service, quote-service)"],
        ["Entorno", "Operación normal"],
        ["Respuesta", "Solo el socio autorizado, para el propósito aprobado, usa los datos; "
                      "un consentimiento revocado deja de autorizar su uso; cada decisión se "
                      "registra"],
        ["Medida", "Revocación efectiva ≤ 300 s; 0 accesos fuera de propósito o de socio; "
                   "100 % de accesos auditados"],
    ])
    seg08 = table(["Elemento", "Valor"], [
        ["Fuente", "Socio de distribución, o intermediario comprometido entre el socio y Solventa"],
        ["Estímulo", "Solicitud de emisión con prima, cobertura o tomador alterados tras firmarse"],
        ["Artefacto", "policy-service y su base de datos"],
        ["Entorno", "Operación normal"],
        ["Respuesta", "Se detecta la alteración y se rechaza antes de persistir; queda auditado"],
        ["Medida", "100 % de emisiones con validación de integridad; 0 pólizas alteradas "
                   "persistidas"],
    ])
    return f"""## Lámina 3 — Hipótesis y diseño del experimento

**Hipótesis de diseño:** {HYPOTHESIS}

**Punto de sensibilidad:** dónde se verifica el consentimiento (`claim`: dentro del token; \
`lookup`: en consent-service en cada uso), la vida del token (`TOKEN_TTL`) y la caché de \
autorizaciones (`CONSENT_CACHE_TTL`). Configuraciones medidas:

{variables}

**Historia de arquitectura SEG-02 — Consentimiento Open Finance (confidencialidad)**

{seg02}

**Historia de arquitectura SEG-08 — Emisión de póliza íntegra (integridad)**

{seg08}

**Nivel de incertidumbre:** medio. Quedan fuera del PoC: integración real con Open Finance, \
gestión productiva de claves (KMS y rotación), proveedor de identidad definitivo y TLS entre \
servicios.
"""


# --- Lámina 4 -------------------------------------------------------------------------------


def _lookup(r):
    return [c for c in r["seg02"] if c["mode"] == "lookup"]


def _claim(r):
    return [c for c in r["seg02"] if c["mode"] == "claim"]


def _rep_errors(cfg: dict) -> list[str]:
    return sorted({e for rep in cfg["reps"] for e in rep.get("errors", [])})


def statement_a(r: dict) -> str:
    lookup = _lookup(r)
    if not lookup:
        return "No se midió ninguna configuración lookup en esta corrida."
    parts = [f"{config_label(c)}: máx {fmt_s(c['max'])}" for c in lookup]
    ok = r["verdict"]["a"]
    head = ("Con la verificación en el servicio dueño, el consentimiento revocado dejó de "
            "autorizar dentro de la meta de 300 s en todas las repeticiones"
            if ok else "La verificación en el servicio dueño NO cumplió la meta en todas las "
            "repeticiones")
    return f"{head} ({'; '.join(parts)})."


def statement_b(r: dict) -> str:
    audit = r["audit"]
    by_service = ", ".join(f"{s} {v['events']}/{v['requests']}"
                           for s, v in sorted(audit["by_service"].items()))
    head = ("Todos los requests del experimento a servicios protegidos quedaron auditados"
            if audit["meets_target"] else "Hubo requests a servicios protegidos sin evento")
    return (f"{head}: {audit['events']} de {audit['requests']} ({fmt_pct(audit['coverage'])}), "
            f"incluidos permitidos y denegados. Por servicio: {by_service}.")


def statement_c(r: dict) -> str:
    s = r["seg08"]
    if not s:
        return "No se ejecutó la suite de integridad."
    head = ("Todos los payloads alterados se rechazaron antes de persistir"
            if s["meets_target"] else "La integridad de la emisión NO se cumplió por completo")
    return (f"{head}: {s['rejected']} de {s['tampered_sent']} rechazados, {s['rows_added']} "
            f"pólizas alteradas nuevas y {fmt_pct(s['validation_rate'])} de las pólizas "
            f"guardadas con integridad verificada.")


def overall(verdict: dict) -> str:
    values = [verdict.get(k) for k in "abc"]
    evaluated = [v for v in values if v is not None]
    if not evaluated:
        return "no evaluada"
    if len(evaluated) < 3:
        return "evaluada solo en parte (corrida parcial)"
    if all(evaluated):
        return "**confirmada**"
    if any(evaluated):
        return "**confirmada parcialmente**"
    return "**no confirmada**"


def sensitivity_text(r: dict) -> str:
    claim = _claim(r)
    if not claim:
        return ""
    values = "; ".join(f"{c['config']} (TTL {c['token_ttl']} s): máx {fmt_s(c['max'])}"
                       + (f", {c['unobserved']} sin rechazo" if c["unobserved"] else "")
                       for c in claim)
    lines = [f"**Punto de sensibilidad (modo claim):** {values}."]
    for c in claim:
        exceeds = c["max"] is not None and c["max"] > c["target_s"]
        if c["token_ttl"] > c["target_s"] and not c["meets_target"]:
            lines.append(f"- {c['config']} viola la meta, como se esperaba: con el consentimiento "
                         f"dentro del token, la revocación solo se nota cuando el token expira "
                         f"(hasta {c['token_ttl']} s). Es evidencia del punto de sensibilidad, "
                         "no un fallo del diseño propuesto.")
        elif c["token_ttl"] > c["target_s"] and c["meets_target"]:
            lines.append(f"- {c['config']} cumplió pese a un TTL mayor que la meta; es inesperado "
                         "y debe revisarse en el log antes de sacar conclusiones.")
        elif c["token_ttl"] == c["target_s"] and exceeds:
            lines.append(f"- {c['config']} queda en el límite: el TTL es igual a la meta y el "
                         f"rechazo llega al vencer el token más la re-autenticación "
                         f"({fmt_s(c['max'])}, {c['max'] - c['target_s']:.1f} s sobre la meta). "
                         "La medición tiene una resolución de ±5 s por el polling.")
        elif c["meets_target"]:
            lines.append(f"- {c['config']} cumple porque su TTL ({c['token_ttl']} s) es menor que "
                         "la meta: la revocación está acotada por la vida del token.")
    return "\n".join(lines)


def favorable_decisions(r: dict) -> str:
    v, rows = r["verdict"], []
    if v.get("a"):
        best = ", ".join(f"{c['config']} máx {fmt_s(c['max'])}" for c in _lookup(r))
        rows.append(["Revocar acceso", "consent-service marca REVOKED; quote-service consulta al "
                     "dueño en cada uso (lookup)", f"Revocación efectiva: {best}"])
    if v.get("b"):
        audit = r["audit"]
        rows.append(["Mantener auditoría", "audit-service append-only; cada servicio audita "
                     "ALLOW y DENY y falla cerrado si no puede auditar",
                     f"audit_coverage {fmt_pct(audit['coverage'])} "
                     f"({audit['events']}/{audit['requests']})"])
    if v.get("c"):
        s = r["seg08"]
        rows.append(["Verificar integridad del mensaje", "policy-service verifica HMAC-SHA256 "
                     "del payload canónico antes de abrir la transacción",
                     f"{s['rejected']}/{s['tampered_sent']} alterados rechazados; "
                     f"{s['rows_added']} filas nuevas"])
        cross = [c for c in s["cases"] if c["case_id"] in ("TC-I-06", "TC-I-07")]
        if cross and all(c["as_expected"] for c in cross):
            metric = (f"{len(cross)}/{len(cross)} intentos con firma de otro socio o "
                      "partner_uuid cruzado rechazados (TC-I-06, TC-I-07)")
            rows.append(["Autorizar actores", "la clave HMAC se elige por el partner_uuid del "
                         "token, nunca por el del body", metric])
    if not rows:
        return "Ninguna métrica del diseño propuesto se cumplió en esta corrida."
    return table(["Táctica", "Componente", "Métrica"], rows)


def unmet_items(r: dict) -> list[dict]:
    items = []
    for c in _lookup(r):
        if c["meets_target"]:
            continue
        errors = _rep_errors(c)
        why = []
        if c["unobserved"]:
            why.append(f"{plural(c['unobserved'], 'repetición', 'repeticiones')} sin rechazo "
                       "dentro del tope de observación")
        if c["max"] is not None and c["max"] > c["target_s"]:
            why.append(f"máximo observado {fmt_s(c['max'])}")
        if errors:
            why.append(f"errores registrados: {', '.join(errors)}")
        if c["cache_ttl"]:
            change = ("reducir CONSENT_CACHE_TTL o invalidar la caché de quote-service cuando "
                      "consent-service revoca")
            cost = ("más consultas a consent-service por cotización, o un canal de eventos "
                    "adicional entre servicios")
        else:
            change = ("revisar las columnas errors de results.csv y el log antes de concluir: "
                      "con caché 0 el diseño no tiene demora esperada")
            cost = "tiempo de diagnóstico; ningún cambio de arquitectura hasta entender la causa"
        items.append({"metric": f"SEG-02 revocación — {config_label(c)}",
                      "why": "; ".join(why) or "no cumplió la meta", "change": change,
                      "cost": cost})
    audit = r["audit"]
    if not audit["meets_target"]:
        missing = {}
        for m in audit.get("missing", []):
            missing[m["service"]] = missing.get(m["service"], 0) + 1
        detail = ", ".join(f"{s}: {n}" for s, n in sorted(missing.items())) or "sin detalle"
        items.append({
            "metric": "Accesos auditados",
            "why": f"{audit['requests'] - audit['events']} requests sin evento (muestra por "
                   f"servicio: {detail})",
            "change": "identificar la ruta que no audita (correlation_ids en results.json → "
                      "audit.missing) y auditar su decisión conservando la falla cerrada",
            "cost": "una escritura de auditoría más por request en esa ruta",
        })
    s = r["seg08"]
    if s and not s["meets_target"]:
        unexpected = [f"{c['case_id']} (HTTP {c['status']})" for c in s["cases"]
                      if not c["as_expected"]]
        items.append({
            "metric": "Integridad de la emisión",
            "why": f"{s['rejected']}/{s['tampered_sent']} rechazados, {s['rows_added']} filas "
                   f"nuevas; casos fuera de lo esperado: {', '.join(unexpected) or 'ninguno'}",
            "change": "garantizar que la verificación HMAC ocurra antes de cualquier INSERT en "
                      "todas las rutas de emisión y cubrir el caso fallido con una prueba",
            "cost": "revisión del flujo de policy-service; sin impacto de rendimiento relevante",
        })
    for c in _claim(r):
        if c["meets_target"]:
            continue
        items.append({
            "metric": f"SEG-02 revocación — {config_label(c)} (punto de sensibilidad)",
            "why": f"el consentimiento viaja en el token y quote-service no consulta al dueño; la "
                   f"revocación se nota al expirar el token (máx {fmt_s(c['max'])})",
            "change": "mover la verificación al servicio dueño (lookup, como C4/C5) o bajar "
                      "TOKEN_TTL por debajo de 300 s",
            "cost": "lookup: una llamada extra a consent-service por cotización (más latencia, en "
                    "tensión con el escenario de latencia p95 ≤ 250 ms) y dependencia de su "
                    "disponibilidad; TTL corto: más emisiones de token y carga en auth-service",
        })
    return items


def lamina4(r: dict) -> str:
    v = r["verdict"]
    confirm = table(["Sub-hipótesis", "Resultado", "Evidencia"], [
        [f"({k}) {SUBHYPOTHESES[k]}", mark(v.get(k)), text]
        for k, text in (("a", statement_a(r)), ("b", statement_b(r)), ("c", statement_c(r)))
    ])
    unmet = unmet_items(r)
    if unmet:
        unmet_text = table(["Métrica", "Por qué no se cumplió", "Cambio propuesto", "Costo"],
                           [[u["metric"], u["why"], u["change"], u["cost"]] for u in unmet])
    else:
        unmet_text = "Todas las métricas medidas se cumplieron; no hay cambios que proponer."
    scope = (" en esta corrida parcial; la conclusión vale solo cuando se repita con la corrida "
             "oficial" if is_partial(r) else "")
    return f"""## Lámina 4 — Análisis

### 1. ¿Se confirmó la hipótesis?

La hipótesis quedó {overall(v)}{scope}.

{confirm}

{sensitivity_text(r)}

### 2. Decisiones de arquitectura que favorecieron el resultado

Solo para las métricas cumplidas (táctica → componente → métrica):

{favorable_decisions(r)}

### 3. Métricas no cumplidas: por qué y qué se cambiaría

{unmet_text}
"""


# --- Lámina 5 -------------------------------------------------------------------------------


def lamina5(r: dict, results_path: Path) -> str:
    folder = results_path.parent
    try:
        shown = folder.relative_to(ROOT).as_posix()
    except ValueError:
        shown = folder.as_posix()
    stamp = r["run_id"].split("-")[0]
    samples = r["audit"].get("samples", [])
    sample_lines = "\n".join(
        f"  - {s['service']} · HTTP {s['status']}: "
        f"`http://127.0.0.1:5005/events?correlation_id={s['correlation_id']}`"
        for s in samples
    ) or "  - (esta corrida no guardó correlation_ids de ejemplo)"
    rows = [
        ["Tabla de propagación por repetición", f"`{shown}/results.csv`", "Abrir y capturar"],
        ["Gráfica de propagación por configuración", f"`{shown}/propagation.png`", "Insertar"],
        ["Resumen, parámetros, commit y veredicto", f"`{shown}/results.json`",
         f"run `{r['run_id']}`, commit `{r['git_commit'][:10]}`"],
        ["Log de la corrida", f"`{shown}/run_{stamp}.log`", "Extracto de una repetición"],
        ["Extracto de auditoría por correlation_id", "audit-service `GET /events`",
         "Ver URLs de ejemplo abajo (stack arriba)"],
        ["Estadísticas de auditoría", "`http://127.0.0.1:5005/stats`", "Capturar el JSON"],
        ["Conteo de pólizas antes/después (SEG-08)", f"`{shown}/results.json` → `seg08`; "
         "`http://127.0.0.1:5004/policies/count`", "Tabla de casos abajo"],
        ["Salida de pytest (TC-AU, TC-C, TC-I, TC-AD)", "`results/pytest_output.txt`",
         "`python -m pytest -v > results/pytest_output.txt`"],
    ]
    cases = ""
    if r["seg08"]:
        seen, case_rows = set(), []
        for c in r["seg08"]["cases"]:
            if c["case_id"] in seen:
                continue
            seen.add(c["case_id"])
            same = [x for x in r["seg08"]["cases"] if x["case_id"] == c["case_id"]]
            case_rows.append([c["case_id"], c["name"], f"HTTP {c['status']} {c['error']}",
                              f"{sum(x['rejected'] for x in same)}/{len(same)}"])
        sent_each = len(r["seg08"]["cases"]) // max(len(case_rows), 1)
        cases = ("\n\n**Casos SEG-08** (cada alteración enviada "
                 f"{plural(sent_each, 'vez', 'veces')}):\n\n"
                 + table(["Caso", "Alteración", "Respuesta", "Rechazados"], case_rows))
    return f"""## Lámina 5 — Evidencias

{table(["Evidencia", "Archivo o fuente", "Cómo obtenerla"], rows)}

Correlation_ids de ejemplo para el extracto de auditoría (un permitido y un denegado por servicio):

{sample_lines}{cases}

**Nota de resolución:** el polling de SEG-02 es cada {r['parameters']['poll_s']:g} s, así que \
cada tiempo de propagación tiene un error de ±{r['parameters']['poll_s']:g} s.
"""


# --- Principal ------------------------------------------------------------------------------


def build_report(results: dict, effort: dict, results_path: Path) -> str:
    warnings = run_warnings(results)
    banner = "".join(f"> ⚠️ {w}\n" for w in warnings)
    header = f"""# H810 — Borrador del informe del experimento

> Generado por `experiment/report.py` desde `results.json` (corrida `{results['run_id']}`, \
commit `{results['git_commit'][:10]}`, {results['started_at'][:19].replace('T', ' ')} UTC) y \
`docs/effort_log.csv`. **No edites los números a mano:** vuelve a generarlo.
{banner}"""
    return "\n".join([header, lamina2(results, effort), lamina3(results), lamina4(results),
                      lamina5(results, results_path)])


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Genera el borrador H810")
    parser.add_argument("--results", type=Path, default=ROOT / "results" / "results.json")
    parser.add_argument("--effort", type=Path, default=ROOT / "docs" / "effort_log.csv")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "H810_borrador.md")
    args = parser.parse_args(argv)
    if not args.results.exists():
        print(f"No existe {args.results}. Corre primero el experimento (experiment/run.py).")
        return 1
    results = json.loads(args.results.read_text(encoding="utf-8"))
    effort = load_effort(args.effort)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_report(results, effort, args.results), encoding="utf-8")
    print(f"Borrador escrito en {args.out}")
    for warning in run_warnings(results):
        print(f"AVISO: {warning}")
    if not effort["rows"]:
        print("AVISO: docs/effort_log.csv no tiene horas registradas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
