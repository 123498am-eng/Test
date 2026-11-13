"""셀프 점검 무인(AFK) 실행기.

    python selfcheck/run.py --username myid --username myid2 --my-photos ./me

1) 내 아이디가 쓰이는 계정을 255개 사이트에서 찾고
2) 찾은 계정의 프로필 사진을 받아 내 얼굴과 비교해서 (사칭 의심 표시)
3) --check-folder 로 준 폴더(직접 모은 스크린샷 등)도 내 얼굴과 비교한 뒤
4) reports/<시각>/ 에 report.html, results.json, results.csv 를 남깁니다.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from username_check import HEADERS, check_username, to_dicts  # noqa: E402

LABEL = {"found": "있음", "possible": "있을 수도", "blocked": "확인 불가(차단)",
         "error": "오류", "not_found": "없음"}


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def main():
    ap = argparse.ArgumentParser(description="내 아이디/사진 도용 셀프 점검")
    ap.add_argument("--username", action="append", required=True, help="내 아이디 (여러 번 가능)")
    ap.add_argument("--my-photos", type=Path, help="내 얼굴 사진 폴더 (사칭 프로필 사진 판별용)")
    ap.add_argument("--check-folder", type=Path, help="내 얼굴이 있는지 확인할 이미지 폴더")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--repeat-hours", type=float, default=0,
                    help="0보다 크면 이 간격(시간)으로 계속 반복 실행")
    ap.add_argument("--out", type=Path, default=Path("reports"))
    args = ap.parse_args()

    while True:
        run_once(args)
        if args.repeat_hours <= 0:
            break
        log(f"{args.repeat_hours}시간 후 다시 실행합니다 (Ctrl+C로 종료)")
        time.sleep(args.repeat_hours * 3600)


def run_once(args):
    out = args.out / datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    matcher = None
    if args.my_photos:
        from face_match import FaceMatcher, SAME_PERSON
        matcher = FaceMatcher()
        n = matcher.add_reference_dir(args.my_photos)
        log(f"기준 얼굴 {n}개 등록")
        if n == 0:
            matcher = None

    all_rows = []
    for name in args.username:
        log(f"아이디 '{name}' 점검 시작")

        def prog(i, total, r):
            if r.status in ("found", "possible") or i % 25 == 0 or i == total:
                log(f"  {i}/{total}  {r.site}: {LABEL[r.status]}")

        rows = to_dicts(check_username(name, args.workers, args.timeout, prog))
        for row in rows:
            row["username"] = name
            row["face_score"] = None
            if matcher and row["avatar"] and row["status"] in ("found", "possible"):
                try:
                    img = requests.get(row["avatar"], headers=HEADERS, timeout=args.timeout).content
                    row["face_score"] = matcher.best_score(matcher.load(img))
                except Exception:
                    pass
        all_rows += rows

    folder_rows = []
    if matcher and args.check_folder:
        from face_match import IMG_EXT
        log(f"폴더 '{args.check_folder}' 이미지 비교")
        for p in sorted(args.check_folder.rglob("*")):
            if p.suffix.lower() in IMG_EXT:
                s = matcher.best_score(matcher.load(p))
                folder_rows.append({"file": str(p), "face_score": s})
        folder_rows.sort(key=lambda r: -(r["face_score"] or -1))

    threshold = SAME_PERSON if matcher else None
    (out / "results.json").write_text(json.dumps(
        {"accounts": all_rows, "folder": folder_rows, "threshold": threshold},
        ensure_ascii=False, indent=2), encoding="utf-8")
    with open(out / "results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["username", "site", "status", "url", "http",
                                          "face_score", "note", "avatar"])
        w.writeheader()
        for r in all_rows:
            w.writerow({k: r.get(k) for k in w.fieldnames})
    write_html(out / "report.html", all_rows, folder_rows, threshold)

    found = sum(r["status"] == "found" for r in all_rows)
    maybe = sum(r["status"] == "possible" for r in all_rows)
    log(f"완료: 있음 {found}, 있을 수도 {maybe}  ->  {out / 'report.html'}")


def write_html(path, rows, folder_rows, threshold):
    e = html.escape

    def face_cell(s):
        if s is None:
            return "<td>-</td>"
        hit = threshold is not None and s >= threshold
        return f'<td class="{"hit" if hit else ""}">{s:.2f}{" 내 얼굴과 비슷함" if hit else ""}</td>'

    acc = "".join(
        f'<tr class="{r["status"]}"><td>{e(r["username"])}</td><td>{e(r["site"])}</td>'
        f'<td>{LABEL[r["status"]]}</td><td><a href="{e(r["url"])}" target="_blank" rel="noopener">{e(r["url"])}</a></td>'
        f'{face_cell(r["face_score"])}<td>{e(r["note"])}</td></tr>'
        for r in rows if r["status"] != "not_found")
    fold = "".join(
        f'<tr><td>{e(r["file"])}</td>{face_cell(r["face_score"])}</tr>' for r in folder_rows)
    missing = sum(r["status"] == "not_found" for r in rows)
    path.write_text(f"""<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>셀프 점검 결과</title>
<style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#fff;color:#222}}
table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;word-break:break-all}}
tr.found td:nth-child(3){{color:#0a7d2c;font-weight:600}}tr.possible td:nth-child(3){{color:#b26b00}}
tr.blocked td:nth-child(3),tr.error td:nth-child(3){{color:#888}}td.hit{{background:#ffe1e1;font-weight:600}}
@media (prefers-color-scheme:dark){{body{{background:#161616;color:#ddd}}td,th{{border-color:#333}}td.hit{{background:#5a1f1f}}a{{color:#8ab4ff}}}}
</style>
<h1>셀프 점검 결과</h1><p>생성: {datetime.now():%Y-%m-%d %H:%M}. "없음" {missing}개는 숨겼습니다 (results.csv에 전체 있음).</p>
<h2>내 아이디를 쓰는 계정</h2>
<table><tr><th>아이디</th><th>사이트</th><th>결과</th><th>주소</th><th>얼굴 유사도</th><th>메모</th></tr>{acc}</table>
{"<h2>폴더 이미지 비교</h2><table><tr><th>파일</th><th>얼굴 유사도</th></tr>" + fold + "</table>" if folder_rows else ""}
<p>얼굴 유사도는 기준값 {threshold if threshold is not None else "-"} 이상이면 같은 사람일 가능성이 높다는 뜻입니다. 결과는 참고용이니 직접 확인하세요.</p>
</html>""", encoding="utf-8")


if __name__ == "__main__":
    main()
