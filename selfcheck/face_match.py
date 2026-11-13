"""내 기준 사진과 다른 이미지들의 얼굴을 비교합니다 (모두 로컬에서 처리).

OpenCV의 YuNet(얼굴 검출) + SFace(얼굴 특징) 모델을 씁니다.
모델 파일은 처음 실행할 때 models/ 폴더로 받습니다.
"""
from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
import requests

MODEL_DIR = Path(__file__).resolve().parent / "models"
ZOO = "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/"
DET = "face_detection_yunet/face_detection_yunet_2023mar.onnx"
REC = "face_recognition_sface/face_recognition_sface_2021dec.onnx"
# SFace 코사인 유사도 기준 (OpenCV 권장값 0.363)
SAME_PERSON = 0.363
IMG_EXT = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}


def _ensure(rel: str) -> str:
    MODEL_DIR.mkdir(exist_ok=True)
    p = MODEL_DIR / Path(rel).name
    if not p.exists():
        print(f"[모델 다운로드] {p.name}")
        r = requests.get(ZOO + rel, timeout=120)
        r.raise_for_status()
        p.write_bytes(r.content)
    return str(p)


class FaceMatcher:
    def __init__(self):
        self.det = cv2.FaceDetectorYN.create(_ensure(DET), "", (320, 320), 0.8)
        self.rec = cv2.FaceRecognizerSF.create(_ensure(REC), "")
        self.refs: list[np.ndarray] = []

    def _features(self, img: np.ndarray) -> list[np.ndarray]:
        if img is None:
            return []
        h, w = img.shape[:2]
        scale = 1024 / max(h, w) if max(h, w) > 1024 else 1.0
        if scale != 1.0:
            img = cv2.resize(img, (int(w * scale), int(h * scale)))
            h, w = img.shape[:2]
        self.det.setInputSize((w, h))
        _, faces = self.det.detect(img)
        if faces is None:
            return []
        return [self.rec.feature(self.rec.alignCrop(img, f)) for f in faces]

    @staticmethod
    def load(path_or_bytes) -> np.ndarray | None:
        if isinstance(path_or_bytes, (bytes, bytearray)):
            arr = np.frombuffer(path_or_bytes, np.uint8)
        else:
            arr = np.fromfile(str(path_or_bytes), np.uint8)
        return cv2.imdecode(arr, cv2.IMREAD_COLOR) if arr.size else None

    def add_reference_dir(self, folder: Path) -> int:
        """내 사진 폴더. 사진마다 가장 큰(첫 번째) 얼굴 하나만 기준으로 씁니다."""
        for p in sorted(Path(folder).iterdir()):
            if p.suffix.lower() in IMG_EXT:
                feats = self._features(self.load(p))
                if feats:
                    self.refs.append(feats[0])
                else:
                    print(f"  [경고] 얼굴을 못 찾음: {p.name}")
        return len(self.refs)

    def best_score(self, img: np.ndarray) -> float | None:
        """이미지 속 얼굴 중 내 얼굴과 가장 비슷한 점수. 얼굴이 없으면 None."""
        if not self.refs:
            raise RuntimeError("기준 사진이 없습니다")
        feats = self._features(img)
        if not feats:
            return None
        return max(
            float(self.rec.match(r, f, cv2.FaceRecognizerSF_FR_COSINE))
            for r in self.refs for f in feats
        )
