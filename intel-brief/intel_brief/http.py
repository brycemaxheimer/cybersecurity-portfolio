"""Small HTTP helper for the collectors: one session, timeouts, size caps."""

from __future__ import annotations

import logging
import time

import requests

from . import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"intel-brief/{__version__} (+https://intel.brycemaxheimer.com)"
_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"})


class FetchError(RuntimeError):
    pass


def get_bytes(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = 30,
    max_bytes: int = 25_000_000,
    retries: int = 2,
) -> bytes:
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with _session.get(
                url, params=params, headers=headers, timeout=timeout, stream=True
            ) as r:
                if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                    wait = min(int(r.headers.get("Retry-After", "5") or 5), 30)
                    time.sleep(wait)
                    continue
                if r.status_code == 404:
                    raise FetchError(f"404 {url}")
                r.raise_for_status()
                chunks, size = [], 0
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError(f"response over {max_bytes} bytes: {url}")
                    chunks.append(chunk)
                return b"".join(chunks)
        except FetchError:
            raise
        except requests.RequestException as e:
            last = e
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
    raise FetchError(f"{url}: {last}")


def get_json(url: str, **kw):
    import json

    return json.loads(get_bytes(url, **kw))
