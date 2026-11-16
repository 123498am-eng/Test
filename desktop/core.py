"""셀프 점검 데스크톱: 처리 기능 (배경 제거, 크로마키, 사람·얼굴 인식).

안드로이드 앱과 같은 방식을 파이썬으로 옮겼습니다. 모든 처리는 이 PC 안에서만 합니다.
"""
from __future__ import annotations

import os
import sys
import threading
import time

import cv2
import numpy as np
import mediapipe as mp
from mediapipe.tasks.python import BaseOptions, vision
from mediapipe.tasks.python.components import containers

if os.environ.get("SELFCHECK_SINGLE_THREAD"):  # Wine 에서 시험할 때만 (Wine 에 없는 Windows 병렬 함수 회피)
    cv2.setNumThreads(0)


def resource(*parts: str) -> str:
    """PyInstaller 로 묶었을 때도 동작하는 파일 경로"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def model(name: str) -> str:
    return resource("models", name)


def mp_image(rgb: np.ndarray) -> mp.Image:
    return mp.Image(image_format=mp.ImageFormat.SRGB, data=np.ascontiguousarray(rgb))


_lock = threading.RLock()  # 같은 스레드에서 다시 잡아도 멈추지 않게
_cache: dict = {}


def _get(name, factory):
    with _lock:
        if name not in _cache:
            _cache[name] = factory()
        return _cache[name]


# ---------------------------------------------------------------- 배경 제거

def _magic():
    return _get("magic", lambda: vision.InteractiveSegmenter.create_from_options(vision.InteractiveSegmenterOptions(
        base_options=BaseOptions(model_asset_path=model("magic_touch.tflite")),
        output_confidence_masks=True, output_category_mask=False)))


def _person_seg():
    return _get("person_seg", lambda: vision.ImageSegmenter.create_from_options(vision.ImageSegmenterOptions(
        base_options=BaseOptions(model_asset_path=model("selfie_multiclass_256x256.tflite")),
        output_confidence_masks=True, output_category_mask=False)))


def _masks(result):
    ms = result.confidence_masks if hasattr(result, "confidence_masks") else result
    out = []
    for m in ms:
        a = m.numpy_view().copy()
        out.append(a[..., 0] if a.ndim == 3 else a)
    return out


def ai_conf(rgb: np.ndarray, nx: float, ny: float) -> np.ndarray:
    roi = vision.InteractiveSegmenterRegionOfInterest(
        format=vision.InteractiveSegmenterRegionOfInterest.Format.KEYPOINT,
        keypoint=containers.keypoint.NormalizedKeypoint(x=float(np.clip(nx, 0, 1)), y=float(np.clip(ny, 0, 1))))
    with _lock:
        r = _magic().segment(mp_image(rgb), roi)
    return _masks(r)[0].astype(np.float32)


def person_conf(rgb: np.ndarray) -> np.ndarray:
    with _lock:
        r = _person_seg().segment(mp_image(rgb))
    bg = _masks(r)[0]
    p = 1.0 - bg
    if p.shape[:2] != rgb.shape[:2]:
        p = cv2.resize(p, (rgb.shape[1], rgb.shape[0]))
    return p.astype(np.float32)


def _keep_touching(m: np.ndarray, rect) -> np.ndarray:
    """가장 큰 덩어리와, 넓이의 30% 이상이 사각형 안에 있는 덩어리만"""
    x, y, w, h = rect
    n, lab, st, _ = cv2.connectedComponentsWithStats(m)
    if n <= 1:
        return m
    largest = 1 + int(np.argmax(st[1:, cv2.CC_STAT_AREA]))
    keep = np.zeros_like(m)
    inr = np.zeros_like(m, bool); inr[max(0, y):y + h, max(0, x):x + w] = True
    for i in range(1, n):
        comp = lab == i
        if i == largest or (comp & inr).sum() >= 0.3 * comp.sum():
            keep[comp] = 255
    return keep


def _fill_holes(m: np.ndarray, probable: np.ndarray) -> np.ndarray:
    orig = m.copy()
    m = cv2.morphologyEx(m, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (7, 7)))
    cnts, hier = cv2.findContours(m.copy(), cv2.RETR_CCOMP, cv2.CHAIN_APPROX_SIMPLE)
    total = (m > 0).sum()
    if hier is not None:
        for i, c in enumerate(cnts):
            if hier[0][i][3] >= 0 and cv2.contourArea(c) <= total * 0.15:
                cv2.drawContours(m, cnts, i, 255, -1)
    added = cv2.subtract(m, orig) & probable
    return orig | added


def _guided(I, p, r, eps):
    box = lambda x: cv2.boxFilter(x, -1, (2 * r + 1, 2 * r + 1))
    mI, mp_ = box(I), box(p)
    a = (box(I * p) - mI * mp_) / (box(I * I) - mI * mI + eps)
    b = mp_ - a * mI
    return box(a) * I + box(b)


def refine(bgr: np.ndarray, small_mask: np.ndarray) -> np.ndarray:
    """작은 마스크를 원본 사진의 실제 경계에 맞춰 다듬기 (가이디드 필터)"""
    H, W = bgr.shape[:2]
    sc = min(1.0, 1600.0 / max(W, H))
    gw, gh = max(1, int(W * sc)), max(1, int(H * sc))
    g = cv2.cvtColor(cv2.resize(bgr, (gw, gh), interpolation=cv2.INTER_AREA), cv2.COLOR_BGR2GRAY).astype(np.float32) / 255
    p = cv2.resize(small_mask, (gw, gh)).astype(np.float32) / 255
    q = _guided(g, p, max(2, max(gw, gh) // 150), 1e-3)
    a = np.clip((q - 0.15) / 0.7, 0, 1)
    a = (a * 255).astype(np.uint8)
    return cv2.resize(a, (W, H)) if (gw, gh) != (W, H) else a


def decontaminate(bgr: np.ndarray, alpha: np.ndarray) -> np.ndarray:
    """경계 화소의 색을 안쪽 물체 색으로 (배경색 번짐 제거)"""
    f = bgr.astype(np.float32)
    hard = (alpha > 242).astype(np.float32)
    s = max(2.0, max(bgr.shape[:2]) / 300)
    num = cv2.GaussianBlur(f * hard[..., None], (0, 0), s)
    den = cv2.GaussianBlur(hard, (0, 0), s)
    est = num / np.maximum(den, 1e-4)[..., None]
    edge = (alpha > 2) & (alpha <= 242) & (den > 0.02)
    f[edge] = est[edge]
    return f


def compose(bgr: np.ndarray, alpha: np.ndarray, backdrop: str, back_img: np.ndarray | None = None) -> np.ndarray:
    """backdrop: transparent / white / black / green / blur / image → BGRA(투명) 또는 BGR"""
    fg = decontaminate(bgr, alpha)
    if backdrop == "transparent":
        out = np.dstack([np.clip(fg, 0, 255).astype(np.uint8), alpha])
        return out
    H, W = bgr.shape[:2]
    if backdrop == "blur":
        bg = cv2.GaussianBlur(bgr, (0, 0), max(W, H) / 50).astype(np.float32)
    elif backdrop == "image" and back_img is not None:
        sc = max(W / back_img.shape[1], H / back_img.shape[0])
        r = cv2.resize(back_img, (int(back_img.shape[1] * sc) + 1, int(back_img.shape[0] * sc) + 1))
        ox, oy = (r.shape[1] - W) // 2, (r.shape[0] - H) // 2
        bg = r[oy:oy + H, ox:ox + W].astype(np.float32)
    else:
        col = {"white": (255, 255, 255), "black": (0, 0, 0), "green": (64, 177, 0)}.get(backdrop, (255, 255, 255))
        bg = np.empty_like(fg); bg[:] = col
    a = (alpha.astype(np.float32) / 255)[..., None]
    return np.clip(fg * a + bg * (1 - a), 0, 255).astype(np.uint8)


def bg_mask(bgr: np.ndarray, rect) -> np.ndarray:
    """사각형(x, y, w, h)의 물체만 남기는 알파 마스크 (원래 크기, 0~255)"""
    H, W = bgr.shape[:2]
    sc = min(1.0, 1024.0 / max(W, H))
    small = cv2.resize(bgr, (int(W * sc), int(H * sc)), interpolation=cv2.INTER_AREA) if sc < 1 else bgr
    rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
    h, w = small.shape[:2]
    x, y, rw, rh = [v * sc for v in rect]
    R = (int(x), int(y), max(1, int(rw)), max(1, int(rh)))
    lim = np.zeros((h, w), np.uint8)
    cv2.rectangle(lim, (int(x - rw * .25), int(y - rh * .25)), (int(x + rw * 1.25), int(y + rh * 1.25)), 255, -1)
    union = np.zeros((h, w), np.uint8); cmax = np.zeros((h, w), np.float32)
    cx, cy = x + rw / 2, y + rh / 2
    # 1) 사각형 안 7곳을 가리켜 물체 모양을 찾고 합침
    for ox, oy in [(0, 0), (-.22, -.22), (.22, -.22), (-.22, .22), (.22, .22), (0, -.3), (0, .3)]:
        c = ai_conf(rgb, (cx + ox * rw) / w, (cy + oy * rh) / h)
        b = (c > 0.5).astype(np.uint8) * 255
        area = (b > 0).sum()
        if area < w * h / 500:
            continue
        if ((b > 0) & (lim > 0)).sum() >= area * 0.7:
            union |= b; cmax = np.maximum(cmax, c)
    big = np.zeros_like(union)
    cv2.rectangle(big, (int(x - rw * .6), int(y - rh * .6)), (int(x + rw * 1.6), int(y + rh * 1.6)), 255, -1)
    union &= big
    union = _keep_touching(union, R)
    # 2) 사람이면 사람 분할로 보강 (사각형 주변만 잘라서 → 작은 사람도 자세히)
    ex, ey = rw * .25, rh * .25
    x0, y0 = max(0, int(x - ex)), max(0, int(y - ey)); x1, y1 = min(w, int(x + rw + ex)), min(h, int(y + rh + ey))
    P = np.zeros((h, w), np.float32)
    if x1 - x0 > 8 and y1 - y0 > 8:
        P[y0:y1, x0:x1] = person_conf(rgb[y0:y1, x0:x1])
    strong = (P > 0.75).astype(np.uint8) * 255
    rmask = np.zeros_like(union); cv2.rectangle(rmask, (R[0], R[1]), (R[0] + R[2], R[1] + R[3]), 255, -1)
    if ((strong > 0) & (rmask > 0)).sum() >= 0.15 * (rmask > 0).sum():
        half = (P > 0.5)
        n, lab, st, _ = cv2.connectedComponentsWithStats(union)
        for i in range(1, n):
            comp = lab == i
            if (comp & half).sum() < 0.1 * comp.sum() and (comp & (rmask > 0)).sum() < 0.5 * comp.sum():
                union[comp] = 0
        n, lab, st, _ = cv2.connectedComponentsWithStats(half.astype(np.uint8))
        for i in range(1, n):
            comp = lab == i
            ov = (comp & (union > 0)).sum()
            if ov >= 50 or ov >= 0.05 * comp.sum():
                union[comp] = 255
        pts = cv2.findNonZero(union)
        if pts is not None and len(pts) > 2:
            hull = np.zeros_like(union); cv2.fillConvexPoly(hull, cv2.convexHull(pts), 255)
            union |= (strong & hull)
        else:
            union = strong.copy()
    if (union > 0).sum() < w * h / 400:
        # AI 가 못 찾으면 GrabCut
        mask = np.zeros((h, w), np.uint8); bgd = np.zeros((1, 65)); fgd = np.zeros((1, 65))
        cv2.grabCut(small, mask, R, bgd, fgd, 5, cv2.GC_INIT_WITH_RECT)
        union = np.where((mask == 1) | (mask == 3), 255, 0).astype(np.uint8)
    union = _keep_touching(union, R)
    probable = ((cmax > 0.3) | (P > 0.4)).astype(np.uint8) * 255
    union = _fill_holes(union, probable)
    return refine(bgr, union)


# ---------------------------------------------------------------- 크로마키

def auto_key(bgr: np.ndarray):
    """가장자리 띠에서 채도 높은 색들의 평균 = 배경색 (없으면 초록). BGR"""
    h, w = bgr.shape[:2]
    band = np.concatenate([bgr[:h // 12].reshape(-1, 3), bgr[:, :w // 12].reshape(-1, 3), bgr[:, -w // 12:].reshape(-1, 3)])
    sat = band.max(1).astype(int) - band.min(1).astype(int)
    sel = band[sat > 50]
    return tuple(int(v) for v in (sel.mean(0) if len(sel) > 10 else (64, 177, 0)))


def chroma(bgr, key_bgr, tol=40, soft=30, spill=0.6, choke=1):
    """→ (색 번짐을 줄인 전경 BGR float, 알파 0~255)"""
    ycc = cv2.cvtColor(bgr, cv2.COLOR_BGR2YCrCb).astype(np.float32)
    k = cv2.cvtColor(np.uint8([[key_bgr]]), cv2.COLOR_BGR2YCrCb)[0, 0].astype(np.float32)
    d = np.sqrt((ycc[..., 1] - k[1]) ** 2 + (ycc[..., 2] - k[2]) ** 2)
    a = np.clip((d - tol) * 255 / max(1, soft), 0, 255).astype(np.uint8)
    if choke > 0:
        a = cv2.erode(a, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (2 * choke + 1, 2 * choke + 1)))
        a = cv2.GaussianBlur(a, (0, 0), max(0.6, choke * .5))
    f = bgr.astype(np.float32)
    b, g, r = key_bgr
    t, o1, o2 = (1, 0, 2) if g >= r and g >= b else ((0, 1, 2) if b >= r and b >= g else (2, 0, 1))
    lim = np.maximum(f[..., o1], f[..., o2])
    f[..., t] -= np.maximum(f[..., t] - lim, 0) * spill
    return f, a


def chroma_compose(bgr, key_bgr, tol, soft, spill, choke, backdrop, back_img=None):
    f, a = chroma(bgr, key_bgr, tol, soft, spill, choke)
    if backdrop == "transparent":
        return np.dstack([np.clip(f, 0, 255).astype(np.uint8), a])
    H, W = bgr.shape[:2]
    if backdrop == "image" and back_img is not None:
        sc = max(W / back_img.shape[1], H / back_img.shape[0])
        r = cv2.resize(back_img, (int(back_img.shape[1] * sc) + 1, int(back_img.shape[0] * sc) + 1))
        ox, oy = (r.shape[1] - W) // 2, (r.shape[0] - H) // 2
        bg = r[oy:oy + H, ox:ox + W].astype(np.float32)
    else:
        bg = np.empty_like(f); bg[:] = {"white": (255, 255, 255), "black": (0, 0, 0)}.get(backdrop, (0, 0, 0))
    al = (a.astype(np.float32) / 255)[..., None]
    return np.clip(f * al + bg * (1 - al), 0, 255).astype(np.uint8)


# ---------------------------------------------------------------- 사람 인식

POSE_EDGES = [(11, 12), (11, 13), (13, 15), (12, 14), (14, 16), (11, 23), (12, 24), (23, 24), (23, 25), (25, 27),
              (24, 26), (26, 28), (27, 31), (28, 32), (27, 29), (28, 30), (0, 11), (0, 12), (15, 19), (16, 20)]


def _tiles(w, h, frac):
    s = min(w, h) * frac

    def starts(L):
        if s >= L:
            return [0.0]
        out, x = [], 0.0
        while x + s < L:
            out.append(x); x += s * .75
        out.append(L - s)
        return out
    t = [(x, y, s, s) for y in starts(h) for x in starts(w)]
    return sorted(t, key=lambda r: (r[0] + s / 2 - w / 2) ** 2 + (r[1] + s / 2 - h / 2) ** 2)


def _iou(a, b):
    l, t = max(a[0], b[0]), max(a[1], b[1]); r, bt = min(a[2], b[2]), min(a[3], b[3])
    if r <= l or bt <= t:
        return 0.0
    i = (r - l) * (bt - t)
    return i / ((a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - i)


def posture(p, ok):
    x = lambda i: p[i][0]; y = lambda i: p[i][1]
    if not (ok[11] and ok[12]):
        return "사람"
    shw = abs(x(11) - x(12)) + 1e-3
    hand = (ok[15] and ok[13] and y(15) < y(11) - 0.6 * shw) or (ok[16] and ok[14] and y(16) < y(12) - 0.6 * shw)
    extra = " · 손 듦" if hand else ""
    if not (ok[23] and ok[24]):
        return "상반신" + extra
    sx, sy = (x(11) + x(12)) / 2, (y(11) + y(12)) / 2; hx, hy = (x(23) + x(24)) / 2, (y(23) + y(24)) / 2
    torso = np.hypot(sx - hx, sy - hy) + 1e-3
    if abs(sx - hx) > abs(sy - hy) * 1.2:
        return "누움" + extra
    if not (ok[25] and ok[26]):
        return "서 있음" + extra
    t1, t2 = y(25) - y(23), y(26) - y(24)
    if t1 < 0.35 * torso and t2 < 0.35 * torso:
        return "앉음" + extra
    if min(t1, t2) < 0.35 * torso or (ok[27] and ok[28] and abs(y(27) - y(28)) > 0.5 * torso):
        return "움직임" + extra
    return "서 있음" + extra


class PersonTracker:
    """사람 찾기: 관절(뼈대) + 번호 + 자세 + 인원. 먼 사람은 물체 인식 조각 + 확대 관절 (자동 확대)"""

    def __init__(self):
        self.pose = vision.PoseLandmarker.create_from_options(vision.PoseLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=model("pose_landmarker_full.task")),
            running_mode=vision.RunningMode.VIDEO, num_poses=5, min_pose_detection_confidence=0.45))
        self.crop_pose = vision.PoseLandmarker.create_from_options(vision.PoseLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=model("pose_landmarker_lite.task")), num_poses=1))
        self.det = vision.ObjectDetector.create_from_options(vision.ObjectDetectorOptions(
            base_options=BaseOptions(model_asset_path=model("efficientdet_lite2.tflite")),
            score_threshold=0.35, category_allowlist=["person"], max_results=10))
        self.tracks = []; self.next_id = 1; self.total = 0; self.frame_no = 0; self.tile_i = 0; self.ts = 0

    def reset(self):
        self.tracks = []; self.total = 0

    @staticmethod
    def _conv(lms, ox, oy, sw, sh):
        pts = [(ox + l.x * sw, oy + l.y * sh) for l in lms[:33]]
        ok = [(l.visibility or 0) > 0.6 and (l.presence or 0) > 0.5 for l in lms[:33]]
        return pts, ok

    @staticmethod
    def _box(pts, ok):
        xs = [p[0] for p, o in zip(pts, ok) if o]; ys = [p[1] for p, o in zip(pts, ok) if o]
        if len(xs) < 4:
            return None
        pw, ph = (max(xs) - min(xs)) * .12, (max(ys) - min(ys)) * .08
        return [min(xs) - pw, min(ys) - ph * 2, max(xs) + pw, max(ys) + ph]

    def _crop_pose(self, rgb, r):
        H, W = rgb.shape[:2]
        ex, ey = (r[2] - r[0]) * .3, (r[3] - r[1]) * .15
        l, t = int(max(0, r[0] - ex)), int(max(0, r[1] - ey)); rr, bb = int(min(W, r[2] + ex)), int(min(H, r[3] + ey))
        if rr - l < 16 or bb - t < 24:
            return None
        res = self.crop_pose.detect(mp_image(rgb[t:bb, l:rr])).pose_landmarks
        if not res:
            return None
        pts, ok = self._conv(res[0], l, t, rr - l, bb - t)
        return (pts, ok) if self._box(pts, ok) else None

    def process(self, bgr):
        H, W = bgr.shape[:2]
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        ds = min(1.0, 960 / max(W, H))
        small = cv2.resize(rgb, (int(W * ds), int(H * ds))) if ds < 1 else rgb
        self.ts = max(int(time.monotonic() * 1000), self.ts + 1)
        found = []
        for lm in self.pose.detect_for_video(mp_image(small), self.ts).pose_landmarks:
            pts, ok = self._conv(lm, 0, 0, W, H)
            b = self._box(pts, ok)
            if b:
                found.append((b, pts, ok))
        boxes = []
        if self.frame_no % 2 == 0:
            d2 = min(1.0, 640 / max(W, H))  # 물체 인식은 더 작게 (빠르게)
            tiny = cv2.resize(rgb, (int(W * d2), int(H * d2))) if d2 < 1 else rgb
            for d in self.det.detect(mp_image(tiny)).detections:
                bb = d.bounding_box
                boxes.append([bb.origin_x / d2, bb.origin_y / d2, (bb.origin_x + bb.width) / d2, (bb.origin_y + bb.height) / d2])
        else:
            tl = _tiles(W, H, 0.5); x, y, s, _ = tl[self.tile_i % len(tl)]; self.tile_i += 1
            x, y, s = int(x), int(y), int(s)
            for d in self.det.detect(mp_image(rgb[y:y + s, x:x + s])).detections:
                bb = d.bounding_box
                boxes.append([bb.origin_x + x, bb.origin_y + y, bb.origin_x + bb.width + x, bb.origin_y + bb.height + y])
        self.frame_no += 1
        cropped = 0
        for r in sorted(boxes, key=lambda b: -(b[3] - b[1])):
            if any(_iou(f[0], r) > 0.3 for f in found):
                continue
            res = None
            if cropped < 2:  # 빠르게: 프레임당 확대 관절 찾기는 2명까지
                cropped += 1; res = self._crop_pose(rgb, r)
            found.append((r, res[0], res[1]) if res else (r, None, None))
        for t in self.tracks:
            if cropped >= 4 or (t["rect"][3] - t["rect"][1]) > H * .5 or any(_iou(f[0], t["rect"]) > 0.3 for f in found):
                continue
            cropped += 1
            res = self._crop_pose(rgb, t["rect"])
            if res:
                b = self._box(*res)
                if b:
                    found.append((b, res[0], res[1]))
        now = time.monotonic(); used = set(); people = []
        for r, pts, ok in sorted(found, key=lambda f: -(f[0][3] - f[0][1])):
            cands = [t for t in self.tracks if id(t) not in used]
            t = max(cands, key=lambda t: _iou(t["rect"], r), default=None)
            if t is None or _iou(t["rect"], r) <= 0.25:
                t = {"id": self.next_id, "rect": list(r), "seen": now, "frames": 0, "counted": False}
                self.next_id += 1; self.tracks.append(t)
            used.add(id(t))
            t["rect"] = [a + (b - a) * 0.6 for a, b in zip(t["rect"], r)]
            t["seen"] = now; t["frames"] += 1
            if not t["counted"] and t["frames"] >= 3:
                t["counted"] = True; self.total += 1
            people.append({"id": t["id"], "rect": [round(v, 1) for v in t["rect"]],
                           "pts": [[round(a, 1), round(b, 1)] for a, b in pts] if pts else None,
                           "ok": ok, "posture": posture(pts, ok) if pts else "사람 (멀리)"})
        self.tracks = [t for t in self.tracks if now - t["seen"] < 1.5]
        return {"w": W, "h": H, "people": people, "now": len(people), "total": self.total, "edges": POSE_EDGES}


class FaceTracker:
    """얼굴 찾기: 얼굴 점 + 번호 (누구인지 알아내지 않음). 먼 얼굴은 조각을 원래 해상도로 (자동 확대)"""

    def __init__(self):
        self.full = vision.FaceLandmarker.create_from_options(vision.FaceLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=model("face_landmarker.task")),
            running_mode=vision.RunningMode.VIDEO, num_faces=5))
        self.crop = vision.FaceLandmarker.create_from_options(vision.FaceLandmarkerOptions(
            base_options=BaseOptions(model_asset_path=model("face_landmarker.task")), num_faces=3, min_face_detection_confidence=0.4))
        self.tracks = []; self.next_id = 1; self.total = 0; self.ts = 0; self.ta = 0; self.tb = 0

    def reset(self):
        self.tracks = []; self.total = 0

    def process(self, bgr):
        H, W = bgr.shape[:2]
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        ds = min(1.0, 960 / max(W, H))
        small = cv2.resize(rgb, (int(W * ds), int(H * ds))) if ds < 1 else rgb
        self.ts = max(int(time.monotonic() * 1000), self.ts + 1)

        def conv(lms, ox, oy, sw, sh, src):
            pts = [(ox + l.x * sw, oy + l.y * sh) for l in lms[:468]]
            xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
            return {"rect": [min(xs), min(ys), max(xs), max(ys)], "pts": pts, "src": src}
        dets = [conv(f, 0, 0, W, H, 0) for f in self.full.detect_for_video(mp_image(small), self.ts).face_landmarks]
        # 조각 2개 (짧은 변의 45%, 25%) 를 원래 해상도로
        for frac, attr in ((0.45, "ta"), (0.25, "tb")):
            tl = _tiles(W, H, frac); i = getattr(self, attr); setattr(self, attr, i + 1)
            x, y, s, _ = [int(v) for v in tl[i % len(tl)]]
            for f in self.crop.detect(mp_image(rgb[y:y + s, x:x + s])).face_landmarks:
                dets.append(conv(f, x, y, s, s, 1))
        # 이미 찾은 작은 얼굴은 주변만 잘라 정밀 추적
        for t in self.tracks:
            r = t["rect"]; fh = r[3] - r[1]
            if fh > H * 0.3:
                continue
            side = max(r[2] - r[0], fh) * 2.4
            x0 = int(np.clip((r[0] + r[2]) / 2 - side / 2, 0, max(0, W - side))); y0 = int(np.clip((r[1] + r[3]) / 2 - side / 2, 0, max(0, H - side)))
            s = int(min(side, W, H))
            if s < 32:
                continue
            fs = self.crop.detect(mp_image(rgb[y0:y0 + s, x0:x0 + s])).face_landmarks
            if fs:
                dets.append(conv(fs[0], x0, y0, s, s, 2))
        dets.sort(key=lambda d: -d["src"])
        uniq = []
        for d in dets:
            if all(_iou(u["rect"], d["rect"]) <= 0.35 for u in uniq):
                uniq.append(d)
        now = time.monotonic(); used = set(); faces = []
        for d in uniq:
            cands = [t for t in self.tracks if id(t) not in used]
            t = max(cands, key=lambda t: _iou(t["rect"], d["rect"]), default=None)
            if t is None or _iou(t["rect"], d["rect"]) <= 0.2:
                t = {"id": self.next_id, "rect": list(d["rect"]), "seen": now, "frames": 0, "counted": False}
                self.next_id += 1; self.tracks.append(t)
            used.add(id(t))
            t["rect"] = [a + (b - a) * 0.6 for a, b in zip(t["rect"], d["rect"])]
            t["seen"] = now; t["frames"] += 1
            if not t["counted"] and t["frames"] >= 3:
                t["counted"] = True; self.total += 1
            faces.append({"id": t["id"], "rect": [round(v, 1) for v in t["rect"]],
                          "pts": [[round(a, 1), round(b, 1)] for a, b in d["pts"][::3]], "far": d["src"] > 0})
        self.tracks = [t for t in self.tracks if now - t["seen"] < 1.2]
        return {"w": W, "h": H, "faces": faces, "now": len(faces), "total": self.total}
