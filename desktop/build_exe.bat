@echo off
rem Windows 에서 직접 빌드: 파이썬 3.11 (64비트) 설치 후 이 폴더에서 실행하세요.
if not exist models mkdir models
for %%f in (magic_touch.tflite selfie_multiclass_256x256.tflite efficientdet_lite2.tflite pose_landmarker_full.task pose_landmarker_lite.task face_landmarker.task) do copy /Y ..\android\app\src\main\assets\%%f models\ >nul
python -m pip install -r requirements-desktop.txt
python -m PyInstaller --noconfirm --onefile --name SelfCheck --paths ..\selfcheck --add-data "models;models" --add-data "index.html;." --collect-data mediapipe --collect-binaries mediapipe --collect-submodules mediapipe.tasks --exclude-module jax --exclude-module jaxlib --exclude-module scipy --exclude-module tensorflow --exclude-module IPython app.py
echo 결과: dist\SelfCheck.exe
