from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request

app = FastAPI(title="OSINT Corroboration Engine")

VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": []
    }


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        text = value

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def valid_source(source):
    if not isinstance(source, dict):
        return False

    if not isinstance(source.get("id"), str):
        return False

    if not isinstance(source.get("origin"), str):
        return False

    if not isinstance(source.get("value"), str):
        return False

    if not isinstance(source.get("observedAt"), str):
        return False

    if source.get("type") not in VALID_TYPES:
        return False

    return True


def fresh(source, as_of, staleness_days):
    observed = parse_timestamp(source["observedAt"])

    if observed is None:
        return False

    age_seconds = (as_of - observed).total_seconds()

    # Future observations are not fresh.
    if age_seconds < 0:
        return False

    age_days = age_seconds / 86400

    return age_days <= staleness_days


@app.post("/corroborate")
async def corroborate(request: Request):

    # --------------------------------------------------
    # RULE 1: INVALID REQUEST
    # --------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return invalid_response()

    if not isinstance(body, dict):
        return invalid_response()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid_response()

    if not isinstance(claim.get("value"), str):
        return invalid_response()

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return invalid_response()

    staleness_days = body.get("stalenessDays")

    # bool must not count as a number.
    if isinstance(staleness_days, bool):
        return invalid_response()

    if not isinstance(staleness_days, (int, float)):
        return invalid_response()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid_response()

    claim_value = claim["value"]

    # --------------------------------------------------
    # KEEP ONLY VALID SOURCES
    # --------------------------------------------------

    valid_sources = [
        source
        for source in sources
        if valid_source(source)
    ]

    # --------------------------------------------------
    # KEEP ONLY FRESH SOURCES
    # --------------------------------------------------

    fresh_sources = [
        source
        for source in valid_sources
        if fresh(source, as_of, staleness_days)
    ]

    # --------------------------------------------------
    # RULE 2: CONTRADICTED
    # --------------------------------------------------

    contradicting = [
        source
        for source in fresh_sources
        if source.get("authoritative") is True
        and source["value"] != claim_value
    ]

    if contradicting:
        ids = sorted(
            source["id"]
            for source in contradicting
        )

        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": ids
        }

    # --------------------------------------------------
    # RULE 3: SUPPORT
    # --------------------------------------------------

    agreeing = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    # One representative per origin.
    representatives = {}

    for source in agreeing:
        origin = source["origin"]

        if origin not in representatives:
            representatives[origin] = source

        elif source["id"] < representatives[origin]["id"]:
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:

        types = {
            source["type"]
            for source in reps
        }

        if len(types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        ids = sorted(
            source["id"]
            for source in reps
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": ids
        }

    # --------------------------------------------------
    # RULE 4: UNVERIFIED
    # --------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }


@app.get("/")
def home():
    return {
        "service": "OSINT Corroboration Engine",
        "status": "running"
    }