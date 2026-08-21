from datetime import datetime, timezone
from fastapi import FastAPI
from typing import Any


app = FastAPI(title="OSINT Corroboration Engine")


VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def parse_timestamp(value: Any):
    """
    Convert an ISO timestamp into a timezone-aware datetime.
    Return None if it cannot be parsed.
    """
    if not isinstance(value, str):
        return None

    try:
        text = value

        # Convert trailing Z into UTC offset format.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        # Treat naive timestamps as UTC.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def is_valid_source(source):
    """
    Check whether a source satisfies the assignment's
    definition of a valid source.
    """

    if not isinstance(source, dict):
        return False

    required_strings = [
        "id",
        "origin",
        "value",
        "observedAt",
    ]

    for field in required_strings:
        if not isinstance(source.get(field), str):
            return False

    if source.get("type") not in VALID_TYPES:
        return False

    return True


def is_fresh(source, as_of, staleness_days):
    """
    A source is fresh when:

        asOf - observedAt <= stalenessDays

    Older observations are stale.
    """

    observed_at = parse_timestamp(source["observedAt"])

    if observed_at is None:
        return False

    age_seconds = (as_of - observed_at).total_seconds()

    # Future observations should not be considered fresh.
    if age_seconds < 0:
        return False

    age_days = age_seconds / 86400

    return age_days <= staleness_days


@app.post("/corroborate")
def corroborate(body: Any):

    # ---------------------------------------------------------
    # RULE 1: INVALID REQUEST
    # ---------------------------------------------------------

    if not isinstance(body, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    if not isinstance(claim.get("value"), str):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    staleness_days = body.get("stalenessDays")

    # bool is technically a subclass of int in Python,
    # so explicitly reject it.
    if (
        isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
    ):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    sources = body.get("sources")

    if not isinstance(sources, list):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim_value = claim["value"]

    # ---------------------------------------------------------
    # KEEP ONLY VALID SOURCES
    # ---------------------------------------------------------

    valid_sources = [
        source
        for source in sources
        if is_valid_source(source)
    ]

    # ---------------------------------------------------------
    # REMOVE STALE SOURCES
    # ---------------------------------------------------------

    fresh_sources = [
        source
        for source in valid_sources
        if is_fresh(source, as_of, staleness_days)
    ]

    # ---------------------------------------------------------
    # RULE 2: CONTRADICTED
    #
    # A fresh authoritative source with a different value
    # immediately means the claim is contradicted.
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # RULE 3: SUPPORTED
    #
    # Keep fresh sources whose value equals the claim.
    # Then keep only ONE source per origin.
    #
    # The representative is the source with the smallest ID.
    # ---------------------------------------------------------

    agreeing = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    representatives = {}

    for source in agreeing:
        origin = source["origin"]

        if (
            origin not in representatives
            or source["id"] < representatives[origin]["id"]
        ):
            representatives[origin] = source

    representative_sources = list(representatives.values())

    if len(representative_sources) >= 2:

        distinct_types = {
            source["type"]
            for source in representative_sources
        }

        if len(distinct_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        ids = sorted(
            source["id"]
            for source in representative_sources
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": ids
        }

    # ---------------------------------------------------------
    # RULE 4: UNVERIFIED
    # ---------------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }


@app.get("/")
def home():
    return {
        "service": "OSINT Corroboration Engine",
        "endpoint": "POST /corroborate"
    }