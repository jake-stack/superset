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

# pylint: disable=import-outside-toplevel

from pytest_mock import MockerFixture


def test_build_dashboard_digest_assembles_payload(mocker: MockerFixture) -> None:
    from superset.utils import dashboard_digest

    dashboard = mocker.MagicMock()
    dashboard.id = 7
    dashboard.dashboard_title = "Revenue"
    dashboard.params_dict = {"external_thumbnail_url": "https://cdn.example/thumb.png"}
    dashboard.slices = []

    cache = mocker.MagicMock()
    cache.get.return_value = None
    mocker.patch.object(dashboard_digest, "cache_manager")
    dashboard_digest.cache_manager.cache = cache

    app = mocker.MagicMock()
    app.config = {"CACHE_DEFAULT_TIMEOUT": 300}
    mocker.patch.object(dashboard_digest, "current_app", app)

    mocker.patch.object(
        dashboard_digest,
        "hash_string_cache_key",
        return_value="digest-cache-key",
    )
    mocker.patch.object(
        dashboard_digest,
        "export_chart_image",
    )

    activity_fetcher = mocker.Mock(return_value=[])
    thumbnail_fetcher = mocker.Mock(return_value=b"png-bytes")

    payload = dashboard_digest.build_dashboard_digest(
        dashboard,
        user_id=42,
        activity_fetcher=activity_fetcher,
        thumbnail_fetcher=thumbnail_fetcher,
    )

    assert payload["dashboard_id"] == 7
    assert payload["user_id"] == 42
    assert payload["cache_key"] == "digest-cache-key"
    assert payload["thumbnail_size"] == len(b"png-bytes")
    activity_fetcher.assert_called_once_with(42)
    thumbnail_fetcher.assert_called_once_with("https://cdn.example/thumb.png")
    cache.set.assert_called_once()


def test_build_dashboard_digest_returns_cached_payload(mocker: MockerFixture) -> None:
    from superset.utils import dashboard_digest

    dashboard = mocker.MagicMock()
    cached_payload = {"dashboard_id": 1, "cached": True}

    cache = mocker.MagicMock()
    cache.get.return_value = cached_payload
    mocker.patch.object(dashboard_digest, "cache_manager")
    dashboard_digest.cache_manager.cache = cache

    mocker.patch.object(
        dashboard_digest,
        "hash_string_cache_key",
        return_value="digest-cache-key",
    )
    activity_fetcher = mocker.Mock()
    thumbnail_fetcher = mocker.Mock()

    payload = dashboard_digest.build_dashboard_digest(
        dashboard,
        user_id=1,
        activity_fetcher=activity_fetcher,
        thumbnail_fetcher=thumbnail_fetcher,
    )

    assert payload == cached_payload
    activity_fetcher.assert_not_called()
    thumbnail_fetcher.assert_not_called()
