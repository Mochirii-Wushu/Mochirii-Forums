#!/usr/bin/env python3
"""Validate a protected live-pricing readback against the fixed authority."""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--maximum-age-minutes", type=int, default=15)
    args = parser.parse_args()
    document = json.loads(args.evidence.read_text(encoding="utf-8"))

    exact = {
        "region": "sgp1",
        "dropletPlan": "s-1vcpu-2gb",
        "dropletMonthlyUsd": "12.00",
        "weeklyBackupPercent": "20.00",
        "weeklyBackupMonthlyUsd": "2.40",
        "additionalBucketFixedMonthlyUsd": "0.00",
        "aggregateFixedMonthlyUsd": "14.40",
        "sizeApiPlanAvailableInRegion": True,
        "sizeApiMonthlyPriceConfirmed": True,
        "weeklyBackupPriceConfirmed": True,
        "existingSpacesSubscriptionActive": True,
        "additionalBucketWithinIncludedQuota": True,
        "aggregateUsageReviewed": True,
        "secondSubscriptionRequired": False,
        "additionalPaidResourceRequired": False,
    }
    for key, expected in exact.items():
        if document.get(key) != expected:
            raise RuntimeError(f"Live cost evidence failed exact field: {key}")
    if decimal.Decimal(document["aggregateFixedMonthlyUsd"]) > decimal.Decimal("14.40"):
        raise RuntimeError("Live fixed monthly cost exceeds authority.")
    observed = dt.datetime.fromisoformat(document["observedAt"].replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    age = now - observed.astimezone(dt.timezone.utc)
    if age < dt.timedelta(0) or age > dt.timedelta(minutes=args.maximum_age_minutes):
        raise RuntimeError("Live cost evidence is stale or future-dated.")
    print("Live cost evidence is within the exact authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
