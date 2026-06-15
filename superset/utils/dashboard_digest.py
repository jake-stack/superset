# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Dashboard digest snapshots for operator reporting and email exports."""
from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from typing import Any, Callable, TYPE_CHECKING

from flask import current_app

from superset.extensions import cache_manager
from superset.key_value.utils import hash_string_cache_key
from superset.utils.core import export_chart_image

if TYPE_CHECKING:
    from superset.models.dashboard import Dashboard

logger = logging.getLogger(__name__)

ActivityFetcher = Callable[[int], list[Any]]
ThumbnailFetcher = Callable[[str], bytes]


def get_external_thumbnail_url(dashboard: Dashboard) -> str | None:
    """Return CDN thumbnail URL from dashboard metadata, if configured."""
    url = dashboard.params_dict.get("external_thumbnail_url")
    return url if isinstance(url, str) and url else None


def _serialize_activity_rows(rows: list[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for row in rows:
        if hasattr(row, "_mapping"):
            serialized.append(dict(row._mapping))
        elif isinstance(row, dict):
            serialized.append(row)
        else:
            serialized.append({"row": str(row)})
    return serialized


def build_dashboard_digest(
    dashboard: Dashboard,
    user_id: int,
    activity_fetcher: ActivityFetcher,
    thumbnail_fetcher: ThumbnailFetcher,
) -> dict[str, Any]:
    """
    Build a cached dashboard digest payload for operator exports.

    The digest bundles recent user activity, optional CDN thumbnail bytes,
    and static chart PNG paths used when attaching dashboards to email reports.
    """
    cache_key = hash_string_cache_key(f"digest:{dashboard.id}:{user_id}")
    cache = cache_manager.cache

    cached: dict[str, Any] | None = cache.get(cache_key)
    if cached:
        logger.debug("Returning cached digest for dashboard %s", dashboard.id)
        return cached

    payload: dict[str, Any] = {
        "cache_key": cache_key,
        "dashboard_id": dashboard.id,
        "dashboard_title": dashboard.dashboard_title,
        "user_id": user_id,
        "activity": _serialize_activity_rows(activity_fetcher(user_id)),
        "thumbnail_size": 0,
        "chart_exports": [],
    }

    if thumbnail_url := get_external_thumbnail_url(dashboard):
        thumbnail_data = thumbnail_fetcher(thumbnail_url)
        payload["thumbnail_size"] = len(thumbnail_data)

    chart_exports: list[str] = []
    for slc in dashboard.slices:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            export_chart_image(slc.slice_name or f"chart-{slc.id}", tmp.name)
            chart_exports.append(tmp.name)
    payload["chart_exports"] = chart_exports

    timeout = current_app.config["CACHE_DEFAULT_TIMEOUT"]
    cache.set(cache_key, payload, timeout=timeout)
    logger.info(
        "Cached dashboard digest for dashboard %s (%s chart exports)",
        dashboard.id,
        len(chart_exports),
    )
    return payload


def cleanup_digest_chart_exports(payload: dict[str, Any]) -> None:
    """Remove temporary chart PNG files created during digest export."""
    for path in payload.get("chart_exports", []):
        with contextlib.suppress(OSError):
            os.remove(path)
