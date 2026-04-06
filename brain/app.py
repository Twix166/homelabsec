import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from brainlib.assets import NmapXmlError, get_or_create_asset, normalize_role, parse_nmap_xml
from brainlib.config import (
    CLASSIFICATION_FALLBACK_CONFIDENCE,
    CLASSIFICATION_FALLBACK_ROLE,
    FINGERPRINTS_LIST_LIMIT,
    OBSERVATIONS_LIST_LIMIT,
)
from brainlib.database import asset_exists, db
from brainlib.errors import bad_gateway, bad_request, not_found
from brainlib.fingerprints import (
    build_fingerprint,
    detect_and_persist_changes_for_asset,
    diff_fingerprints,
    fingerprint_hash,
    get_latest_fingerprint,
    get_previous_fingerprint,
    persist_changes,
    store_fingerprint_if_changed,
)
from brainlib.ollama import OllamaError, chat_json
from brainlib.reports import daily_report, summary_report

app = FastAPI(title="HomelabSec Brain")


class NmapXmlIngestRequest(BaseModel):
    xml_path: str



@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ollama/test")
def ollama_test() -> dict[str, Any]:
    try:
        data = chat_json(
            [
                {
                    "role": "system",
                    "content": "Return strict JSON only with keys role and confidence.",
                },
                {
                    "role": "user",
                    "content": "Classify a host with ports 22, 80, 443 and nginx detected.",
                },
            ]
        )
    except OllamaError as exc:
        raise bad_gateway(str(exc)) from exc

    content = data["message"]["content"]
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {"raw_content": content}
    return {"model": data.get("model"), "result": parsed}


@app.post("/ingest/nmap_xml")
def ingest_nmap_xml(req: NmapXmlIngestRequest):
    try:
        parsed_hosts = parse_nmap_xml(req.xml_path)
    except FileNotFoundError as exc:
        raise not_found("XML file not found") from exc
    except NmapXmlError as exc:
        raise bad_request(str(exc)) from exc
    inserted = 0

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_runs (scan_type, status)
                VALUES ('nmap_xml_ingest', 'completed')
                RETURNING scan_run_id
                """
            )
            scan_run_id = str(cur.fetchone()[0])
            conn.commit()

        for item in parsed_hosts:
            asset_id = get_or_create_asset(conn, item["ip"], item["mac"], item["hostname"])

            with conn.cursor() as cur:
                if item["ports"]:
                    for p in item["ports"]:
                        cur.execute(
                            """
                            INSERT INTO network_observations (
                                scan_run_id, asset_id, ip_address, mac_address, mac_vendor,
                                reachable, port, protocol, service_name, service_product, service_version,
                                os_guess, raw_json
                            )
                            VALUES (%s, %s, %s, %s, %s, true, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                scan_run_id,
                                asset_id,
                                item["ip"],
                                item["mac"],
                                item["vendor"],
                                p["port"],
                                p["protocol"],
                                p["service_name"],
                                p["service_product"],
                                p["service_version"],
                                item["os_guess"],
                                json.dumps(item),
                            ),
                        )
                        inserted += 1
                else:
                    cur.execute(
                        """
                        INSERT INTO network_observations (
                            scan_run_id, asset_id, ip_address, mac_address, mac_vendor,
                            reachable, os_guess, raw_json
                        )
                        VALUES (%s, %s, %s, %s, %s, true, %s, %s)
                        """,
                        (
                            scan_run_id,
                            asset_id,
                            item["ip"],
                            item["mac"],
                            item["vendor"],
                            item["os_guess"],
                            json.dumps(item),
                        ),
                    )
                    inserted += 1

                fp = build_fingerprint(conn, asset_id)
                store_fingerprint_if_changed(conn, asset_id, fp)

            conn.commit()

    return {
        "scan_run_id": scan_run_id,
        "hosts_parsed": len(parsed_hosts),
        "observations_inserted": inserted,
    }


@app.get("/assets")
def list_assets():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_id, preferred_name, role, role_confidence, first_seen, last_seen
                FROM assets
                ORDER BY last_seen DESC
                """
            )
            rows = cur.fetchall()

    return {
        "assets": [
            {
                "asset_id": str(r[0]),
                "preferred_name": r[1],
                "role": r[2],
                "role_confidence": float(r[3]) if r[3] is not None else None,
                "first_seen": r[4].isoformat(),
                "last_seen": r[5].isoformat(),
            }
            for r in rows
        ]
    }


@app.get("/observations")
def list_observations():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    o.observation_id,
                    o.asset_id,
                    a.preferred_name,
                    o.ip_address,
                    o.mac_address,
                    o.port,
                    o.protocol,
                    o.service_name,
                    o.service_product,
                    o.service_version,
                    o.os_guess,
                    o.observed_at
                FROM network_observations o
                LEFT JOIN assets a ON a.asset_id = o.asset_id
                ORDER BY o.observed_at DESC, o.observation_id DESC
                LIMIT %s
                """,
                (OBSERVATIONS_LIST_LIMIT,),
            )
            rows = cur.fetchall()

    return {
        "observations": [
            {
                "observation_id": str(r[0]),
                "asset_id": str(r[1]) if r[1] is not None else None,
                "preferred_name": r[2],
                "ip_address": str(r[3]) if r[3] is not None else None,
                "mac_address": str(r[4]) if r[4] is not None else None,
                "port": r[5],
                "protocol": r[6],
                "service_name": r[7],
                "service_product": r[8],
                "service_version": r[9],
                "os_guess": r[10],
                "observed_at": r[11].isoformat(),
            }
            for r in rows
        ]
    }


@app.get("/fingerprints")
def list_fingerprints():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    f.fingerprint_id,
                    f.asset_id,
                    a.preferred_name,
                    a.role,
                    f.fingerprint_hash,
                    f.created_at
                FROM fingerprints f
                JOIN assets a ON a.asset_id = f.asset_id
                ORDER BY f.created_at DESC, f.fingerprint_id DESC
                LIMIT %s
                """,
                (FINGERPRINTS_LIST_LIMIT,),
            )
            rows = cur.fetchall()

    return {
        "fingerprints": [
            {
                "fingerprint_id": str(r[0]),
                "asset_id": str(r[1]),
                "preferred_name": r[2],
                "role": r[3],
                "fingerprint_hash": r[4],
                "created_at": r[5].isoformat(),
            }
            for r in rows
        ]
    }


@app.post("/classify/{asset_id}")
def classify_asset(asset_id: str):
    with db() as conn:
        if not asset_exists(conn, asset_id):
            raise not_found("Asset not found")

        fp = build_fingerprint(conn, asset_id)
        try:
            data = chat_json(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are a homelab asset classifier. "
                            "Use only the provided fingerprint. "
                            "Return strict JSON with keys role and confidence. "
                            "Role must be a short snake_case label like gateway, nas, printer, web_server, server, switch, access_point, iot_device, workstation, unknown."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Fingerprint: {json.dumps(fp)}",
                    },
                ]
            )
        except OllamaError as exc:
            raise bad_gateway(str(exc)) from exc

        content = data.get("message", {}).get("content", "")
        parsed = None
        raw_error = None

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            raw_error = content
            parsed = {
                "role": CLASSIFICATION_FALLBACK_ROLE,
                "confidence": CLASSIFICATION_FALLBACK_CONFIDENCE,
                "raw_model_output": content,
            }

        role = normalize_role(parsed.get("role", CLASSIFICATION_FALLBACK_ROLE))
        confidence = parsed.get("confidence", CLASSIFICATION_FALLBACK_CONFIDENCE)

        # normalize confidence to float if possible
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = CLASSIFICATION_FALLBACK_CONFIDENCE

        # normalize role to string
        if not isinstance(role, str) or not role.strip():
            role = CLASSIFICATION_FALLBACK_ROLE

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE assets
                SET role = %s, role_confidence = %s
                WHERE asset_id = %s
                """,
                (role, confidence, asset_id),
            )
            conn.commit()

        # rebuild fingerprint so the latest fingerprint includes normalized role/confidence
        updated_fp = build_fingerprint(conn, asset_id)
        fingerprint_store_result = store_fingerprint_if_changed(conn, asset_id, updated_fp)

    return {
        "asset_id": asset_id,
        "classification": {
            "role": role,
            "confidence": confidence
        },
        "fingerprint": updated_fp,
        "fingerprint_store": fingerprint_store_result,
        "raw_model_output": raw_error
    }

@app.get("/fingerprint/{asset_id}")
def get_fingerprint(asset_id: str):
    with db() as conn:
        latest = get_latest_fingerprint(conn, asset_id)

        if latest is None:
            raise not_found("No fingerprint found for asset")

        return {
            "asset_id": asset_id,
            "fingerprint_hash": latest["fingerprint_hash"],
            "created_at": latest["created_at"],
            "fingerprint": latest["fingerprint"],
        }
    
@app.get("/detect_changes/{asset_id}")
def detect_changes_for_asset(asset_id: str):
    with db() as conn:
        if not asset_exists(conn, asset_id):
            raise not_found("Asset not found")

        latest = get_latest_fingerprint(conn, asset_id)

        if latest is None:
            raise not_found("No fingerprint found for asset")

        result = detect_and_persist_changes_for_asset(conn, asset_id)
        return result

@app.get("/detect_changes")
def detect_changes_all():
    all_results = []

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT asset_id
                FROM fingerprints
                ORDER BY asset_id
                """
            )
            asset_ids = [str(r[0]) for r in cur.fetchall()]

        for asset_id in asset_ids:
            result = detect_and_persist_changes_for_asset(conn, asset_id)
            if result["changes"]:
                all_results.append(result)

    return {
        "assets_with_changes": len(all_results),
        "results": all_results,
    }

@app.get("/report/daily")
def report_daily():
    with db() as conn:
        return daily_report(conn)

@app.get("/report/summary")
def report_summary():
    with db() as conn:
        return summary_report(conn)

@app.post("/classify_all")
def classify_all():
    ok = 0
    errors = 0
    failed = []

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT asset_id
                FROM assets
                ORDER BY last_seen DESC
                """
            )
            asset_ids = [str(r[0]) for r in cur.fetchall()]

    for asset_id in asset_ids:
        try:
            classify_asset(asset_id)
            ok += 1
        except Exception as exc:
            errors += 1
            failed.append(
                {
                    "asset_id": asset_id,
                    "error": str(exc),
                }
            )

    return {
        "total_assets": len(asset_ids),
        "classified_ok": ok,
        "errors": errors,
        "failed": failed,
    }
