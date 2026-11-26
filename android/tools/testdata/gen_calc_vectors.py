#!/usr/bin/env python3
"""용량·전력·품질 계산 도구 시험용 기준값. 파이썬의 다른 계산 방식(Newton 반복·Fraction 정확한 분수·numpy)으로 구해서 Kotlin 의 닫힌 식과 대조해요.
사용: gen_calc_vectors.py <출력폴더>"""
import sys, os, json, math, random
from fractions import Fraction
import numpy as np

OUT = sys.argv[1]; os.makedirs(OUT, exist_ok=True); random.seed(20240301)
res = {}

# ---- RAID: 정의대로 센 용량, 복구 시간, 복구 중 읽기 오류 확률
def raid_usable(lv, n, g):
    return {"RAID 0": n, "RAID 1": 1, "RAID 5": n - 1, "RAID 6": n - 2, "RAID 10": n // 2, "RAID 50": n - g, "RAID 60": n - 2 * g, "JBOD": n}[lv]
def raid_rebuild_disks(lv, n, g):
    return {"RAID 0": 0, "RAID 1": 1, "RAID 5": n - 1, "RAID 6": n - 1, "RAID 10": 1, "RAID 50": n // g - 1 if g else 0, "RAID 60": n // g - 1 if g else 0, "JBOD": 0}[lv]
names = {"RAID 0": "RAID 0 (줄 세우기)", "RAID 1": "RAID 1 (미러)", "RAID 5": "RAID 5", "RAID 6": "RAID 6", "RAID 10": "RAID 10", "RAID 50": "RAID 50", "RAID 60": "RAID 60", "JBOD": "JBOD (이어 붙이기)"}
raid = []
for lv, n, g, size in [("RAID 0", 4, 2, 4), ("RAID 1", 2, 2, 4), ("RAID 1", 3, 2, 4), ("RAID 5", 4, 2, 8), ("RAID 5", 8, 2, 4), ("RAID 5", 3, 2, 1), ("RAID 6", 6, 2, 4), ("RAID 6", 4, 2, 16), ("RAID 10", 8, 2, 4), ("RAID 10", 4, 2, 2),
                       ("RAID 50", 12, 3, 4), ("RAID 50", 6, 2, 10), ("RAID 60", 12, 3, 4), ("RAID 60", 8, 2, 6), ("JBOD", 5, 2, 2), ("RAID 5", 16, 2, 20)]:
    for p, label in ((1e-14, "1 / 10^14 (일반 하드디스크)"), (1e-15, "1 / 10^15 (고급 하드디스크)"), (1e-16, "1 / 10^16 (SSD·엔터프라이즈)")):
        rd = raid_rebuild_disks(lv, n, g); bits = rd * size * 1e12 * 8
        raid.append({"lv": names[lv], "n": n, "g": g, "size": size, "ure": label, "usable_tb": raid_usable(lv, n, g) * size, "rebuild_h": size * 1e12 / (100 * 1e6) / 3600, "ure_prob": -math.expm1(-bits * p) if rd else None})
res["raid"] = raid

# ---- PoE: 뉴턴 반복으로 푼 스위치 공급 전력 (V·I − I²R = P)
def pse_newton(pd, v, r):
    i = pd / v
    for _ in range(200):
        f = v * i - i * i * r - pd; df = v - 2 * i * r
        i2 = i - f / df
        if abs(i2 - i) < 1e-15: i = i2; break
        i = i2
    return v * i
stds = [("IEEE 802.3af (PoE, 15.4W)", 44.0, 20.0, 15.4, 12.95), ("IEEE 802.3at (PoE+, 30W)", 50.0, 12.5, 30.0, 25.5), ("IEEE 802.3bt Type 3 (PoE++, 60W)", 50.0, 6.25, 60.0, 51.0), ("IEEE 802.3bt Type 4 (PoE++, 90W)", 52.5, 6.25, 90.0, 71.3)]
poe = []
for name, v, r100, pse_port, pd_max in stds:
    for meters in (1, 10, 50, 100):
        r = r100 * meters / 100
        for pd in (0.5, 3.5, 7, 12.5, 12.95, 25.5, 30, 51, 60, 71.3):
            if pd <= pd_max + 1e-9 and (v * v - 4 * r * pd) >= 0: poe.append({"std": name, "m": meters, "pd": pd, "pse": pse_newton(pd, v, r)})
res["poe"] = poe
res["poe_spec"] = [{"std": n, "pse_at_pdmax_100m": pse_newton(pd, v, r100)} for n, v, r100, pp, pd in stds]

# ---- UPS
ups = []
for (bv, bah, bs, bp, load, eff, dod, age, k) in [(12, 9, 2, 1, 300, 0.9, 0.8, 1.0, 1.2), (12, 7, 1, 2, 100, 0.85, 0.8, 0.7, 1.2), (12.8, 100, 4, 1, 1000, 0.92, 0.9, 1.0, 1.05), (12, 100, 4, 1, 2000, 0.9, 0.5, 0.8, 1.2), (24, 5, 1, 1, 60, 0.9, 0.8, 1.0, 1.2)]:
    v = bv * bs; ah = bah * bp; wh = v * ah; simple = wh * dod * age * eff / load; cur = load / (v * eff); peuk = 20 * (ah * dod * age / (cur * 20)) ** k
    ups.append({"bv": bv, "bah": bah, "bs": bs, "bp": bp, "load": load, "eff": eff * 100, "dod": dod * 100, "age": age * 100, "k": k, "simple_h": simple, "peukert_h": peuk, "wh": wh})
res["ups"] = ups

# ---- VoIP E-model (G.107 단순화)
def idelay(d): return 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
def mos_of(r): return 1.0 if r < 0 else 4.5 if r > 100 else 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
codecs = {"G.711 (PLC 없음)": (0, 4.3, 20), "G.711 (PLC 있음)": (0, 25.1, 20), "G.729A": (11, 19.0, 35), "G.723.1 (6.3k)": (15, 16.1, 67.5)}
voip = []
for cname, (ie, bpl, cd) in codecs.items():
    for net, jit, loss, burst in [(20, 20, 0, 1), (60, 40, 1, 1), (100, 40, 2, 1), (150, 60, 0.5, 1), (200, 80, 5, 1), (300, 100, 3, 2), (500, 100, 10, 1), (40, 10, 0, 1), (80, 30, 0.1, 1.5)]:
        d = net + jit + cd; ieff = ie + (95 - ie) * loss / (loss / burst + bpl) if loss > 0 else ie; r = 93.2 - idelay(d) - ieff
        voip.append({"codec": cname, "net": net, "jit": jit, "loss": loss, "burst": burst, "d": d, "id": idelay(d), "ie_eff": ieff, "r": r, "mos": mos_of(r)})
res["voip"] = voip; res["mos_table"] = [{"r": r, "mos": mos_of(r)} for r in (0, 20, 40, 50, 60, 70, 80, 90, 93.2, 100)]

# ---- CGNAT: 정수 계산
cg = []
for (pub, block, p0, p1, idx) in [(16, 1024, 1024, 65535, 0), (16, 1024, 1024, 65535, 1), (16, 1024, 1024, 65535, 62), (16, 1024, 1024, 65535, 63), (16, 1024, 1024, 65535, 64), (16, 1024, 1024, 65535, 1000), (4, 2048, 1024, 65535, 500), (256, 512, 1024, 65535, 12345), (1, 4096, 1, 65535, 15), (8, 1000, 2000, 60000, 777)]:
    per = (p1 - p0 + 1) // block; out = idx // per; slot = idx % per; first = p0 + slot * block
    cg.append({"pub": pub, "block": block, "p0": p0, "p1": p1, "idx": idx, "per": per, "capacity": pub * per, "out": out, "slot": slot, "first": first, "last": first + block - 1})
res["cgnat"] = cg

# ---- 광링크 손실 예산
fib = []
for (tx, sens, att, km, conn, cdb, spl, sdb, safe) in [(-5, -14.4, 0.35, 10, 4, 0.5, 2, 0.1, 3), (-8.2, -14.4, 0.4, 10, 2, 0.5, 0, 0.1, 3), (-3, -18, 0.22, 40, 6, 0.3, 10, 0.05, 2), (-7.3, -9.9, 3.0, 0.3, 2, 0.75, 0, 0.1, 3), (0, -20, 0.35, 80, 4, 0.5, 20, 0.1, 3)]:
    fl = att * km; cl = conn * cdb; sl = spl * sdb; tot = fl + cl + sl; rx = tx - tot; margin = rx - sens; maxkm = (tx - sens - safe - cl - sl) / att
    fib.append({"tx": tx, "rx_sens": sens, "att": att, "km": km, "conn": conn, "cdb": cdb, "spl": spl, "sdb": sdb, "safe": safe, "fiber_loss": fl, "total": tot, "rx": rx, "margin": margin, "margin_safe": margin - safe, "max_km": maxkm})
res["fiber"] = fib

# ---- 와이어 스피드
ws = []
for bps in (10e6, 100e6, 1e9, 2.5e9, 10e9, 25e9, 40e9, 100e9, 400e9):
    for frame in (64, 65, 128, 512, 1024, 1518, 9018):
        ws.append({"bps": bps, "frame": frame, "pps": bps / ((frame + 20) * 8), "eff": frame / (frame + 20)})
res["wire"] = ws

# ---- Erlang B/C: 정확한 분수(Fraction)로 B, 그 위에서 C·서비스 수준
def erlang_b(n, a):
    a = Fraction(a).limit_denominator(10**9)
    num = a ** n / math.factorial(n); den = sum(a ** k / math.factorial(k) for k in range(n + 1))
    return float(num / den)
def erlang_c(n, a):
    b = erlang_b(n, a); return b / (1 - a / n * (1 - b))
er = []
for a in (0.5, 2.0, 5.0, 12.0, 15.0, 30.0, 100.0, 7.25):
    for n in sorted({max(1, int(a) - 1), int(a) + 1, int(a) + 3, int(a) * 2 + 2}):
        if n > a:
            c = erlang_c(n, a); aht = 180.0; t = 20.0
            er.append({"a": a, "n": n, "b": erlang_b(n, a), "c": c, "sl": 1 - c * math.exp(-(n - a) * t / aht), "asa": c * aht / (n - a)})
        else:
            er.append({"a": a, "n": n, "b": erlang_b(n, a), "c": None, "sl": None, "asa": None})
res["erlang"] = er
lines = []
for a, target in [(5, 0.01), (2, 0.05), (10, 0.02), (20, 0.001), (50, 0.01), (0.5, 0.001), (100, 0.01), (15, 0.01)]:
    n = 1
    while erlang_b(n, a) > target: n += 1
    lines.append({"a": a, "target": target, "lines": n, "b_at": erlang_b(n, a), "b_below": erlang_b(n - 1, a) if n > 1 else 1.0})
res["erlang_lines"] = lines
agents = []
for a, target, t, aht in [(15.0, 0.8, 20, 180.0), (5.0, 0.9, 10, 120.0), (40.0, 0.8, 30, 300.0), (1.5, 0.95, 20, 60.0)]:
    n = int(a) + 1
    while True:
        c = erlang_c(n, a); sl = 1 - c * math.exp(-(n - a) * t / aht)
        if sl >= target: break
        n += 1
    agents.append({"a": a, "target": target, "t": t, "aht": aht, "agents": n, "sl": sl, "c": c, "asa": c * aht / (n - a)})
res["erlang_agents"] = agents

# ---- 95% 요금: numpy 의 inverted_cdf(= 가장 가까운 순위) 와 Fraction 으로 정확히 올림
pc = []
for trial in range(14):
    n = random.choice([10, 19, 20, 21, 99, 100, 101, 288, 1000, 2016, 8640, 4321]) if trial < 12 else random.randrange(5, 3000)
    xs = [round(random.uniform(0, 500) * (random.random() ** 2), 2) for _ in range(n)]
    for p in ("95", "90", "99", "99.9"):
        k = math.ceil(Fraction(p) * n / 100); exact = sorted(xs)[k - 1]
        ref = float(np.percentile(xs, float(p), method="inverted_cdf")) if (Fraction(p) * n / 100).denominator != 1 else exact          # 경계(정확히 정수)는 부동소수 오차 때문에 numpy 가 한 칸 어긋날 수 있어 분수 계산을 기준으로
        assert abs(ref - exact) < 1e-9, (n, p, ref, exact)
        pc.append({"xs": xs if n <= 120 else None, "n": n, "p": p, "k": k, "value": exact, "avg": sum(xs) / n, "max": max(xs), "seed_idx": trial})
res["p95"] = pc
# 큰 표본은 파일 크기를 줄이려고 값 대신 만드는 규칙(씨앗)만 남기지 않고, 시험에서 쓸 몇 개만 통째로 저장
big = []
for n in (288, 2016, 8640):
    xs = [round(random.uniform(0, 900) * (random.random() ** 3), 3) for _ in range(n)]
    big.append({"xs": xs, "answers": {p: sorted(xs)[math.ceil(Fraction(p) * n / 100) - 1] for p in ("95", "90", "99", "99.9")}, "n": n})
res["p95_big"] = big
json.dump(res, open(os.path.join(OUT, "calc_cases.json"), "w"), indent=1)
print({k: len(v) for k, v in res.items()})
