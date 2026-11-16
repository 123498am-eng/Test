"""셀프 점검 데스크톱 (Windows EXE).

실행하면 이 PC 안에서만 동작하는 작은 서버가 켜지고 브라우저에 앱 화면이 열립니다.
사진과 웹캠 영상은 PC 밖으로 나가지 않습니다 (아이디 점검만 각 사이트에 접속합니다).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import cv2
import numpy as np

import core

# 아이디 점검(셀프 점검) 모듈
sys.path.insert(0, core.resource("selfcheck"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "selfcheck"))  # 개발 중
import username_check  # noqa: E402
import face_match  # noqa: E402

APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "SelfCheck"
OUT_DIR = Path.home() / "Documents" / "SelfCheck"
face_match.MODEL_DIR = APP_DIR / "models"  # 얼굴 비교 모델은 한 번만 내려받아 여기 보관


def decode_image(data_url: str) -> np.ndarray:
    b = base64.b64decode(data_url.split(",", 1)[-1])
    img = cv2.imdecode(np.frombuffer(b, np.uint8), cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError("이미지를 열 수 없습니다")
    if img.ndim == 2:
        img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    if img.shape[2] == 4:
        img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    return img


def encode_png(img: np.ndarray) -> str:
    ok, buf = cv2.imencode(".png", img)
    return "data:image/png;base64," + base64.b64encode(buf.tobytes()).decode()


def save_png(img: np.ndarray, prefix: str) -> str:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    p = OUT_DIR / f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}.png"
    ok, buf = cv2.imencode(".png", img)
    p.write_bytes(buf.tobytes())
    return str(p)


# ---------------------------------------------------------------- 웹캠

class Camera:
    """웹캠을 읽고 최신 프레임을 사람/얼굴 인식으로 분석해 둡니다."""

    def __init__(self):
        self.lock = threading.Lock()
        self.mode = None
        self.running = False
        self.result = None
        self.jpeg = None
        self.cam_index = 0
        self.trackers = {}
        self.error = None
        self.fps = 0.0

    def start(self, mode: str, index: int):
        self.stop()
        self.mode, self.cam_index, self.running, self.error = mode, index, True, None
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        time.sleep(0.2)

    def reset(self):
        t = self.trackers.get(self.mode)
        if t:
            t.reset()

    def _loop(self):
        src = os.environ.get("SELFCHECK_CAMERA")  # 시험용: 동영상 파일 경로
        cap = cv2.VideoCapture(src) if src else cv2.VideoCapture(self.cam_index, cv2.CAP_DSHOW if os.name == "nt" else cv2.CAP_ANY)
        if not src:
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1920); cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)
        if not cap.isOpened():
            self.error = "웹캠을 열 수 없습니다. 다른 프로그램이 쓰고 있거나 연결되지 않았습니다."
            self.running = False
            return
        try:
            while self.running:
                ok, frame = cap.read()
                if not ok:
                    if src:
                        cap.set(cv2.CAP_PROP_POS_FRAMES, 0); continue
                    self.error = "웹캠에서 영상을 받을 수 없습니다"; break
                if self.mode == "person":
                    tr = self.trackers.get("person") or self.trackers.setdefault("person", core.PersonTracker())
                else:
                    tr = self.trackers.get("face") or self.trackers.setdefault("face", core.FaceTracker())
                t0 = time.time()
                res = tr.process(frame)
                self.fps = 0.8 * self.fps + 0.2 / max(1e-3, time.time() - t0)
                sc = min(1.0, 1280 / max(frame.shape[:2]))
                show = cv2.resize(frame, (int(frame.shape[1] * sc), int(frame.shape[0] * sc))) if sc < 1 else frame
                ok, buf = cv2.imencode(".jpg", show, [cv2.IMWRITE_JPEG_QUALITY, 80])
                with self.lock:
                    self.jpeg = buf.tobytes(); self.result = res
        except Exception as e:  # noqa: BLE001
            self.error = f"오류: {e}"
            traceback.print_exc()
        finally:
            cap.release()
            self.running = False


camera = Camera()

# ---------------------------------------------------------------- 셀프 점검

job = {"running": False, "log": [], "rows": [], "report": None}


def run_selfcheck(usernames, photos):
    job.update(running=True, log=[], rows=[], report=None)

    def log(m):
        job["log"].append(f"[{datetime.now():%H:%M:%S}] {m}")
    try:
        matcher = None
        if photos:
            log("얼굴 비교 모델 준비 (처음 한 번 약 39MB 내려받음)")
            matcher = face_match.FaceMatcher()
            d = Path(tempfile.mkdtemp())
            for i, p in enumerate(photos):
                cv2.imwrite(str(d / f"me_{i}.png"), decode_image(p))
            n = matcher.add_reference_dir(d)
            log(f"기준 얼굴 {n}개 등록")
            if n == 0:
                matcher = None
        for name in usernames:
            log(f"아이디 '{name}' 점검 시작 (사이트 {len(username_check.SITES)}개)")

            def prog(i, total, r):
                if r.status in ("found", "possible"):
                    log(f"  {r.site}: {'있음' if r.status == 'found' else '있을 수도'}")
                if i % 50 == 0 or i == total:
                    log(f"  {i}/{total}")
            for r in username_check.check_username(name, progress=prog):
                row = {"username": name, "site": r.site, "url": r.url, "status": r.status, "note": r.note, "face": None}
                if matcher and r.avatar and r.status in ("found", "possible"):
                    try:
                        import requests
                        b = requests.get(r.avatar, headers=username_check.HEADERS, timeout=15).content
                        img = cv2.imdecode(np.frombuffer(b, np.uint8), cv2.IMREAD_COLOR)
                        s = matcher.best_score(img) if img is not None else None
                        row["face"] = None if s is None else round(float(s), 3)
                    except Exception:  # noqa: BLE001
                        pass
                job["rows"].append(row)
        found = sum(r["status"] == "found" for r in job["rows"])
        log(f"완료: 있음 {found}개")
    except Exception as e:  # noqa: BLE001
        log(f"오류: {e}")
    finally:
        job["running"] = False


# ---------------------------------------------------------------- 서버

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body: bytes, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, Path(core.resource("index.html")).read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/frame":
            with camera.lock:
                j, r = camera.jpeg, camera.result
            return self._json({"running": camera.running, "error": camera.error, "fps": round(camera.fps, 1),
                               "jpeg": base64.b64encode(j).decode() if j else None, "result": r})
        if u.path == "/api/selfcheck":
            return self._json(job)
        if u.path == "/api/folder":
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                os.startfile(str(OUT_DIR))  # noqa
            return self._json({"path": str(OUT_DIR)})
        self._send(404, b"{}")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n) or b"{}")
        try:
            p = urlparse(self.path).path
            if p == "/api/bgremove":
                img = decode_image(data["image"])
                x, y, w, h = data["rect"]
                alpha = core.bg_mask(img, (x, y, w, h))
                back = decode_image(data["backImage"]) if data.get("backImage") else None
                out = core.compose(img, alpha, data.get("backdrop", "transparent"), back)
                res = {"image": encode_png(out)}
                if data.get("save"):
                    res["saved"] = save_png(out, "bg_removed")
                return self._json(res)
            if p == "/api/chroma/key":
                return self._json({"key": core.auto_key(decode_image(data["image"]))})
            if p == "/api/chroma":
                img = decode_image(data["image"])
                back = decode_image(data["backImage"]) if data.get("backImage") else None
                out = core.chroma_compose(img, tuple(data["key"]), float(data["tol"]), float(data["soft"]),
                                          float(data["spill"]), int(data["choke"]), data.get("backdrop", "transparent"), back)
                res = {"image": encode_png(out)}
                if data.get("save"):
                    res["saved"] = save_png(out, "chroma")
                return self._json(res)
            if p == "/api/camera/start":
                camera.start(data.get("mode", "person"), int(data.get("index", 0)))
                return self._json({"ok": True})
            if p == "/api/camera/stop":
                camera.stop(); return self._json({"ok": True})
            if p == "/api/camera/reset":
                camera.reset(); return self._json({"ok": True})
            if p == "/api/selfcheck":
                if job["running"]:
                    return self._json({"error": "이미 점검 중입니다"}, 409)
                names = [s.strip().lstrip("@") for s in data.get("usernames", "").replace(",", " ").split() if s.strip()]
                if not names:
                    return self._json({"error": "아이디를 입력하세요"}, 400)
                threading.Thread(target=run_selfcheck, args=(names, data.get("photos", [])), daemon=True).start()
                return self._json({"ok": True})
            self._json({"error": "없는 주소"}, 404)
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._json({"error": str(e)}, 500)


def selftest():
    """빌드 확인용: 시험 이미지로 각 기능을 한 번씩 돌림"""
    img = np.full((480, 640, 3), (60, 170, 40), np.uint8)
    cv2.circle(img, (320, 240), 120, (40, 60, 200), -1)
    a = core.bg_mask(img, (180, 100, 280, 280)); print("bg_mask", a.shape, int(a.mean()))
    o = core.chroma_compose(img, core.auto_key(img), 40, 30, 0.6, 1, "white"); print("chroma", o.shape)
    p = core.PersonTracker().process(img); print("person", p["now"])
    f = core.FaceTracker().process(img); print("face", f["now"])
    print("SELFTEST OK")


def main():
    # 콘솔이 한글을 못 쓰는 인코딩이어도 죽지 않게
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    if "--selftest" in sys.argv:
        return selftest()
    srv = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("SELFCHECK_PORT", "0"))), Handler)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print("셀프 점검 데스크톱이 실행 중입니다:", url)
    print("이 창을 닫으면 프로그램이 종료됩니다.")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    srv.serve_forever()


if __name__ == "__main__":
    main()
