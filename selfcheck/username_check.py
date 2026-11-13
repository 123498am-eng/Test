"""내 아이디가 255개 사이트에서 쓰이고 있는지 확인합니다.

사이트마다 판별 규칙을 따로 두지 않고, 내 아이디 요청과 존재하지 않을
무작위 아이디 요청의 응답을 비교해서 자동으로 판별합니다.
"""
from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import requests

from sites import SITES

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.8,ko;q=0.6",
}
MISSING = {404, 410}
BLOCKED = {401, 403, 429, 503}


@dataclass
class Result:
    site: str
    url: str
    status: str  # found / possible / not_found / blocked / error
    http: int | None = None
    note: str = ""
    avatar: str | None = None


def _rand_name() -> str:
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))


def _get(session: requests.Session, url: str, timeout: float):
    return session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)


def _og_image(html: str) -> str | None:
    import re
    m = re.search(
        r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)["\'][^>]+content=["\']([^"\']+)',
        html, re.I)
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\'](?:og:image|twitter:image)',
            html, re.I)
    return m.group(1) if m else None


def check_site(site: str, template: str, username: str, timeout: float = 15) -> Result:
    url = template.format(username)
    s = requests.Session()
    try:
        real = _get(s, url, timeout)
    except requests.RequestException as e:
        return Result(site, url, "error", note=type(e).__name__)

    code = real.status_code
    if code in MISSING:
        return Result(site, url, "not_found", code)
    if code in BLOCKED:
        return Result(site, url, "blocked", code, "봇 차단 또는 로그인 필요")
    if code >= 400:
        return Result(site, url, "error", code)

    # 2xx: 무작위 아이디와 비교해서 판별
    fake_name = _rand_name()
    try:
        fake = _get(s, template.format(fake_name), timeout)
    except requests.RequestException:
        fake = None

    avatar = _og_image(real.text[:200_000])
    if fake is None:
        return Result(site, url, "possible", code, "비교 요청 실패", avatar)
    if fake.status_code in MISSING or fake.status_code >= 400:
        return Result(site, url, "found", code, "", avatar)

    real_path = urlparse(real.url).path.rstrip("/").lower()
    fake_path = urlparse(fake.url).path.rstrip("/").lower()
    name_in_real = username.lower() in real_path or username.lower() in urlparse(real.url).netloc.lower()
    name_in_fake = fake_name in fake_path or fake_name in urlparse(fake.url).netloc.lower()
    if name_in_real and not name_in_fake:
        return Result(site, url, "found", code, "없는 아이디는 다른 페이지로 이동", avatar)
    if not name_in_real:
        return Result(site, url, "not_found", code, "다른 페이지로 이동됨")

    body_real = username.lower() in real.text.lower()
    body_fake = fake_name in fake.text.lower()
    len_r, len_f = len(real.text), len(fake.text)
    differ = abs(len_r - len_f) > max(500, 0.15 * max(len_r, len_f, 1))
    if body_real and not body_fake:
        return Result(site, url, "found", code, "본문에 아이디 있음", avatar)
    if differ:
        return Result(site, url, "possible", code, "응답 내용이 다름", avatar)
    return Result(site, url, "not_found", code, "없는 아이디와 응답이 같음")


def check_username(username: str, workers: int = 24, timeout: float = 15,
                   progress=None) -> list[Result]:
    results: list[Result] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_site, n, t, username, timeout): n for n, t in SITES.items()}
        for i, fut in enumerate(as_completed(futs), 1):
            r = fut.result()
            results.append(r)
            if progress:
                progress(i, len(futs), r)
    order = {"found": 0, "possible": 1, "blocked": 2, "error": 3, "not_found": 4}
    results.sort(key=lambda r: (order[r.status], r.site.lower()))
    return results


def to_dicts(results):
    return [asdict(r) for r in results]
