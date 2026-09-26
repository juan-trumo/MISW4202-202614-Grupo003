"""Arnés del experimento de seguridad Solventa (§12). Genera la evidencia; nunca la inventa.

Fases:
  1. SEG-02, por configuración (C1..C5): recrea el stack con esa configuración y mide, en
     `reps` repeticiones en paralelo (un cliente distinto cada una), cuánto tarda un
     consentimiento revocado en dejar de autorizar la cotización del socio A.
  2. Con la configuración base (.env): sonda de auditoría (permitidos y denegados) y suite
     de integridad SEG-08 (payload íntegro + alterados), `reps` veces.
  3. audit_coverage sobre TODOS los requests que el arnés envió a servicios protegidos.

Salidas en --out-dir: results.json, results.csv, propagation.png y run_<ts>.log.
Los campos meets_target y verdict se calculan aquí; nunca se escriben a mano.

Uso:
    python experiment/run.py                                  # corrida oficial (~30 min)
    python experiment/run.py --configs C1,C4 --reps 1 --out-dir /tmp/prueba   # corrida corta
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from experiment.audit_probe import BFF_CLIENTE, audit_events, run_audit_coverage  # noqa: E402
from experiment.envfile import ROOT, load_env  # noqa: E402
from experiment.partner_client import (  # noqa: E402
    BFF_SOCIO,
    TIMEOUT,
    partners_from_env,
    run_integrity_suite,
)
from experiment.recording import RecordingSession  # noqa: E402
from experiment.stack import compose  # noqa: E402

TARGET_S = 300  # meta de SEG-02: revocación efectiva en <= 5 min
ALL_CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
CONFIG_DIR = ROOT / "experiment" / "configs"
DENIAL_ERRORS = {"consent_not_found", "consent_revoked", "purpose_mismatch", "partner_mismatch"}
MAX_REPS = 5  # un cliente sembrado por repetición (cliente-001..005)

log = logging.getLogger("experiment")


# --- Infraestructura ------------------------------------------------------------------------


def configure_logging(log_path: Path) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    log.handlers[:] = [file_handler, console]
    log.setLevel(logging.INFO)


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "desconocido"


def environment_info() -> dict:
    return {
        "git_commit": _run(["git", "rev-parse", "HEAD"]),
        "git_dirty": bool(_run(["git", "status", "--porcelain"]).strip()),
        "host": {
            "node": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "docker": _run(["docker", "version", "--format", "{{.Server.Version}}"]),
        },
    }


def deploy(overrides: dict[str, str], tmpdir: Path, label: str) -> dict[str, str]:
    """Recrea todos los contenedores con .env + overrides. Devuelve el entorno efectivo."""
    env = load_env()
    env.update(overrides)
    env_file = tmpdir / f"{label}.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    log.info("Desplegando %s con %s", label, overrides or "configuración base")
    try:
        compose("up", "-d", "--force-recreate", "--wait", env_file=env_file)
    except subprocess.CalledProcessError as exc:
        log.error("docker compose falló: %s", exc.stderr)
        raise
    return env


# --- SEG-02: propagación de la revocación ----------------------------------------------------


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _customer_token(session, client_id: str, secret: str) -> str:
    resp = session.post(f"{BFF_CLIENTE}/auth/token",
                        json={"client_id": client_id, "client_secret": secret}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()["access_token"]


def _quote(session, token: str, customer_id: str):
    return session.post(f"{BFF_SOCIO}/quotes", json={"customer_id": customer_id, "product": "auto"},
                        headers=_bearer(token), timeout=TIMEOUT)


def _error_of(resp) -> str | None:
    try:
        return resp.json().get("error")
    except ValueError:
        return None


def measure_revocation(rep: int, env: dict, poll_s: float, cap_s: float,
                       session: RecordingSession) -> dict:
    client_id, customer_id = f"cliente-{rep:03d}", f"C-{rep:03d}"
    secrets = json.loads(env["SEED_SECRETS"])
    partner_a = env["PARTNER_A_UUID"]
    result = {"rep": rep, "customer_id": customer_id, "propagation_s": None, "denied_code": None,
              "denied_error": None, "polls": 0, "reauths": 0, "errors": []}

    customer = _customer_token(session, client_id, secrets[client_id])
    # Limpieza: un consentimiento ACTIVE de una corrida interrumpida seguiría autorizando.
    for old in session.get(f"{BFF_CLIENTE}/consents", headers=_bearer(customer),
                           timeout=TIMEOUT).json():
        if old["status"] == "ACTIVE":
            session.post(f"{BFF_CLIENTE}/consents/{old['id']}/revoke", headers=_bearer(customer),
                         timeout=TIMEOUT)
    consent = session.post(f"{BFF_CLIENTE}/consents", headers=_bearer(customer), timeout=TIMEOUT,
                           json={"purpose": "quotation", "granted_to": partner_a})
    consent.raise_for_status()
    consent_id = consent.json()["id"]

    # El socio se autentica DESPUÉS del consentimiento (en modo claim, el token lo incluye).
    partner, _ = partners_from_env(env, session)
    token = partner.token(refresh=True)
    first = _quote(session, token, customer_id)
    if first.status_code != 200:
        result["errors"].append(f"cotización inicial {first.status_code}:{_error_of(first)}")
        return result

    revoke = session.post(f"{BFF_CLIENTE}/consents/{consent_id}/revoke",
                          headers=_bearer(customer), timeout=TIMEOUT)
    revoke.raise_for_status()
    # t_revoke: cuando el cliente recibe la confirmación de la revocación.
    t_revoke = time.monotonic()
    result["t_revoke"] = datetime.now(UTC).isoformat()

    k = 0
    while True:
        wait = t_revoke + k * poll_s - time.monotonic()  # rejilla fija: sin deriva acumulada
        if wait > 0:
            time.sleep(wait)
        k += 1
        if time.monotonic() - t_revoke > cap_s:
            log.warning("%s: sin rechazo tras %s s", customer_id, cap_s)
            return result
        resp = _quote(session, token, customer_id)
        result["polls"] += 1
        if resp.status_code == 401 and _error_of(resp) == "token_expired":
            # No es un rechazo: el socio re-autentica como un cliente real y reintenta ya.
            token = partner.token(refresh=True)
            result["reauths"] += 1
            resp = _quote(session, token, customer_id)
            result["polls"] += 1
        if resp.status_code == 200:
            continue
        error = _error_of(resp)
        if resp.status_code == 403 and error in DENIAL_ERRORS:
            result["propagation_s"] = round(time.monotonic() - t_revoke, 3)
            result["denied_code"] = resp.status_code
            result["denied_error"] = error
            result["t_denied"] = datetime.now(UTC).isoformat()
            return result
        result["errors"].append(f"{resp.status_code}:{error}")


def summarize_config(name: str, cfg: dict, reps: list[dict]) -> dict:
    values = [r["propagation_s"] for r in reps if r["propagation_s"] is not None]
    unobserved = len(reps) - len(values)
    meets = bool(reps) and unobserved == 0 and all(v <= TARGET_S for v in values)
    return {
        "config": name,
        "mode": cfg["CONSENT_MODE"],
        "token_ttl": int(cfg["TOKEN_TTL"]),
        "cache_ttl": int(cfg["CONSENT_CACHE_TTL"]) if cfg["CONSENT_MODE"] == "lookup" else None,
        "reps": reps,
        "min": min(values) if values else None,
        "median": statistics.median(values) if values else None,
        "max": max(values) if values else None,
        "unobserved": unobserved,
        "target_s": TARGET_S,
        "meets_target": meets,
    }


def run_seg02(configs: list[str], reps: int, poll_s: float, cap_s: float, tmpdir: Path,
              records: list[dict]) -> list[dict]:
    summaries = []
    for name in configs:
        cfg = load_env(CONFIG_DIR / f"{name}.env")
        env = deploy(cfg, tmpdir, name)
        sessions = [RecordingSession(prefix=f"{name.lower()}-r{i}") for i in range(1, reps + 1)]
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=reps) as pool:
            futures = [pool.submit(measure_revocation, i, env, poll_s, cap_s, sessions[i - 1])
                       for i in range(1, reps + 1)]
            rep_results = []
            for i, future in enumerate(futures, start=1):
                try:
                    rep_results.append(future.result())
                except Exception as exc:  # una repetición rota no tumba la corrida; queda anotada
                    log.exception("%s rep %d falló", name, i)
                    rep_results.append({"rep": i, "propagation_s": None, "denied_code": None,
                                        "denied_error": None, "errors": [repr(exc)]})
        for session in sessions:
            records.extend(session.records)
        summary = summarize_config(name, cfg, rep_results)
        log.info("%s listo en %.0f s: min=%s mediana=%s max=%s sin_rechazo=%d cumple=%s",
                 name, time.monotonic() - started, summary["min"], summary["median"],
                 summary["max"], summary["unobserved"], summary["meets_target"])
        summaries.append(summary)
    return summaries


# --- SEG-08 y auditoría -----------------------------------------------------------------------


def run_integrity(env: dict, reps: int, session: RecordingSession) -> dict:
    a, b = partners_from_env(env, session)
    suite = run_integrity_suite(a, b, repetitions=reps)
    meets = (suite["rejected"] == suite["tampered_sent"] and suite["rows_added"] == 0
             and suite["validation_rate"] == 1.0)
    log.info("SEG-08: alterados=%d rechazados=%d filas_nuevas=%d validation_rate=%.3f",
             suite["tampered_sent"], suite["rejected"], suite["rows_added"],
             suite["validation_rate"])
    return {
        "tampered_sent": suite["tampered_sent"],
        "rejected": suite["rejected"],
        "rows_added": suite["rows_added"],
        "validation_rate": suite["validation_rate"],
        "intact_accepted": suite["intact_status"] == 201 and suite["intact_rows_added"] == 1,
        "cases": suite["cases"],
        "meets_target": meets,
    }


def audit_coverage(records: list[dict]) -> dict:
    def audited(record: dict) -> bool:
        events = audit_events(record["correlation_id"])
        return any(e["service"] == record["service"] for e in events)

    with ThreadPoolExecutor(max_workers=16) as pool:
        flags = list(pool.map(audited, records))
    by_service: dict[str, dict] = {}
    for record, ok in zip(records, flags, strict=True):
        entry = by_service.setdefault(record["service"], {"requests": 0, "events": 0})
        entry["requests"] += 1
        entry["events"] += int(ok)
    matched = sum(flags)
    missing = [r for r, ok in zip(records, flags, strict=True) if not ok]
    # Un ALLOW y un DENY de ejemplo por servicio: correlation_ids para capturar la evidencia
    # con GET /events?correlation_id=... (lámina 5 del H810).
    samples: dict[tuple[str, bool], dict] = {}
    for record, ok in zip(records, flags, strict=True):
        key = (record["service"], record["status"] < 400)
        if ok and key not in samples:
            samples[key] = record
    log.info("Auditoría: %d de %d requests con evento", matched, len(records))
    return {
        "requests": len(records),
        "events": matched,
        "coverage": matched / len(records) if records else 0.0,
        "by_service": by_service,
        "missing": missing[:20],
        "samples": sorted(samples.values(), key=lambda r: (r["service"], r["status"])),
        "meets_target": bool(records) and matched == len(records),
    }


# --- Salidas ---------------------------------------------------------------------------------


def verdict(seg02: list[dict], audit: dict, seg08: dict | None) -> dict:
    # (a) evalúa el diseño propuesto: verificación en el servicio dueño (modo lookup).
    # Las configuraciones claim son evidencia del punto de sensibilidad, no del diseño.
    lookup = [c for c in seg02 if c["mode"] == "lookup"]
    return {
        "a": all(c["meets_target"] for c in lookup) if lookup else None,
        "b": audit["meets_target"],
        "c": seg08["meets_target"] if seg08 else None,
        "sensitivity_claim": {c["config"]: c["meets_target"] for c in seg02
                              if c["mode"] == "claim"},
    }


def write_csv(seg02: list[dict], path: Path) -> None:
    columns = ["config", "mode", "token_ttl", "cache_ttl", "rep", "customer_id", "propagation_s",
               "denied_code", "denied_error", "polls", "reauths", "rep_meets_target", "errors"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for cfg in seg02:
            for rep in cfg["reps"]:
                value = rep.get("propagation_s")
                writer.writerow({
                    "config": cfg["config"], "mode": cfg["mode"], "token_ttl": cfg["token_ttl"],
                    "cache_ttl": cfg["cache_ttl"], "rep": rep.get("rep"),
                    "customer_id": rep.get("customer_id"), "propagation_s": value,
                    "denied_code": rep.get("denied_code"), "denied_error": rep.get("denied_error"),
                    "polls": rep.get("polls"), "reauths": rep.get("reauths"),
                    "rep_meets_target": value is not None and value <= TARGET_S,
                    "errors": "; ".join(rep.get("errors", [])),
                })


# Paleta validada (skill dataviz): rampa ordinal azul, tokens de texto y superficie.
SURFACE, TEXT, TEXT_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
STEPS = {"min": "#86b6ef", "median": "#2a78d6", "max": "#104281"}


def plot_propagation(seg02: list[dict], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 5.2), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    width = 0.26
    labels_stat = {"min": "mínimo", "median": "mediana", "max": "máximo"}
    observed = [c[s] for c in seg02 for s in STEPS if c[s] is not None]
    top = max(observed + [TARGET_S]) * 1.18

    for i, cfg in enumerate(seg02):
        for j, stat in enumerate(STEPS):
            value = cfg[stat]
            if value is None:
                continue
            ax.bar(i + (j - 1) * width, value, width, color=STEPS[stat], edgecolor=SURFACE,
                   linewidth=1.5, label=labels_stat[stat] if i == 0 else None, zorder=3)
        if cfg["median"] is not None:  # etiqueta selectiva: solo la mediana
            median = cfg["median"]
            label = f"{median:.2f} s" if median < 1 else f"{median:.0f} s"
            ax.text(i, median + top * 0.015, label, ha="center",
                    va="bottom", fontsize=8, color=TEXT, zorder=4)
        if cfg["unobserved"]:
            ax.text(i, top * 0.05, f"{cfg['unobserved']} sin rechazo", ha="center", fontsize=8,
                    color=TEXT_2, zorder=4)

    ax.axhline(TARGET_S, color=TEXT_2, linewidth=1.2, linestyle=(0, (4, 3)), zorder=2)
    ax.text(len(seg02) - 0.5, TARGET_S + top * 0.012, "meta 300 s", ha="right", va="bottom",
            fontsize=8, color=TEXT_2)

    ticks = []
    for cfg in seg02:
        extra = f" · caché {cfg['cache_ttl']} s" if cfg["mode"] == "lookup" else ""
        ticks.append(f"{cfg['config']}\n{cfg['mode']} · TTL {cfg['token_ttl']} s{extra}")
    ax.set_xticks(range(len(seg02)), ticks, fontsize=8, color=TEXT)
    ax.set_ylim(0, top)
    ax.set_ylabel("segundos hasta el primer rechazo", fontsize=9, color=TEXT_2)
    ax.tick_params(axis="y", labelsize=8, colors=TEXT_2)
    ax.tick_params(axis="x", length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    reps = max((len(c["reps"]) for c in seg02), default=0)
    fig.suptitle("SEG-02 · Propagación de la revocación por configuración", x=0.07, ha="left",
                 fontsize=12, color=TEXT)
    reps_label = "1 repetición" if reps == 1 else f"{reps} repeticiones"
    ax.set_title(f"{reps_label} por configuración · resolución ±5 s (polling)",
                 loc="left", fontsize=9, color=TEXT_2)
    ax.legend(frameon=False, fontsize=8, loc="upper left", labelcolor=TEXT)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


# --- Principal -------------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--configs", default=",".join(ALL_CONFIGS),
                        help="configuraciones separadas por coma (por defecto C1..C5)")
    parser.add_argument("--reps", type=int, default=5, help="repeticiones por configuración")
    parser.add_argument("--poll-s", type=float, default=5.0, help="intervalo de polling")
    parser.add_argument("--cap-s", type=float, default=1200.0, help="tope de observación")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results")
    args = parser.parse_args(argv)
    args.configs = [c.strip().upper() for c in args.configs.split(",") if c.strip()]
    unknown = sorted(set(args.configs) - set(ALL_CONFIGS))
    if unknown:
        parser.error(f"configuraciones desconocidas: {unknown}")
    if not 1 <= args.reps <= MAX_REPS:
        parser.error(f"--reps debe estar entre 1 y {MAX_REPS} (un cliente sembrado por rep)")
    return args


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    configure_logging(args.out_dir / f"run_{stamp}.log")
    log.info("Corrida %s: configs=%s reps=%d poll=%ss tope=%ss", stamp, args.configs, args.reps,
             args.poll_s, args.cap_s)

    records: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        log.info("Construyendo imágenes")
        compose("build")
        seg02 = run_seg02(args.configs, args.reps, args.poll_s, args.cap_s, tmpdir, records)

        # Fase 2 con la configuración base; deja el stack como estaba al empezar.
        env = deploy({}, tmpdir, "base")
        session = RecordingSession(prefix="base")
        probe = run_audit_coverage(env, session)
        log.info("Sonda de auditoría: %d de %d con evento", probe["events"], probe["requests"])
        seg08 = run_integrity(env, args.reps, session)
        records.extend(session.records)

    audit = audit_coverage(records)
    results = {
        "run_id": f"{stamp}-{uuid.uuid4().hex[:6]}",
        **environment_info(),
        "started_at": started.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "parameters": {"configs": args.configs, "reps": args.reps, "poll_s": args.poll_s,
                       "cap_s": args.cap_s, "target_s": TARGET_S},
        "seg02": seg02,
        "audit": audit,
        "seg08": seg08,
        "verdict": verdict(seg02, audit, seg08),
    }
    (args.out_dir / "results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(seg02, args.out_dir / "results.csv")
    if seg02:
        plot_propagation(seg02, args.out_dir / "propagation.png")
    log.info("Veredicto: %s", results["verdict"])
    log.info("Resultados en %s", args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
