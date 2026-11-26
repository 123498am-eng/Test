#!/usr/bin/env python3
"""DB-IP Lite(국가·ASN) CSV → 앱에 넣을 작은 이진 파일(gzip). 사용: build_ipdb.py <입력폴더> <출력폴더>

형식(압축 풀면): 모든 수는 LEB128 가변 길이 정수.
 c4/c6 : "C4"|"C6", K(국가 수), K×2글자, n, n×(시작 주소 차이), n×(국가 번호 u8, 0=자료 없음)
 a4/a6 : "A4"|"A6", n, n×(시작 주소 차이), n×(ASN 번호표 위치+1, 0=자료 없음)
 asn   : "AS", m, m×(ASN 번호 차이, 이름 길이, 이름 UTF-8)
IPv6 는 앞 64비트만 씀 (/64 보다 잘게 나뉜 줄은 앞 줄에 합침).
"""
import csv, gzip, ipaddress, sys, os, collections

src, dst = sys.argv[1], sys.argv[2]
os.makedirs(dst, exist_ok=True)


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_rows(path, v6, ncols):
    rows = []
    conv = ipaddress.IPv6Address if v6 else ipaddress.IPv4Address
    with open(path, newline='', encoding='utf-8') as f:
        for r in csv.reader(f):
            if len(r) < ncols:
                continue
            s = int(conv(r[0]))
            e = int(conv(r[1]))
            if v6:
                s >>= 64
                e >>= 64
            rows.append((s, e, r[2:]))
    rows.sort(key=lambda x: (x[0], x[1]))
    return rows


def build_ranges(rows, key_fn, bits):
    """겹치지 않게 정리 + 빈 구간 표시 + 같은 값 이어 붙이기 → [(start, value)] (value None = 자료 없음)"""
    top = (1 << bits) - 1
    out = []
    pos = 0  # 다음에 채울 시작 위치
    for s, e, rest in rows:
        v = key_fn(rest)
        if s < pos:           # 앞 줄과 겹침: 겹친 부분은 앞 줄을 따름
            s = pos
            if s > e:
                continue
        if s > pos:
            if not out or out[-1][1] is not None:
                out.append((pos, None))
        if not out or out[-1][1] != v:
            out.append((s, v))
        pos = e + 1
        if pos > top:
            pos = top + 1
    if pos <= top and (not out or out[-1][1] is not None):
        out.append((pos, None))
    # 첫 줄이 0 에서 시작하지 않으면 앞에 빈 구간
    if out and out[0][0] != 0:
        out.insert(0, (0, None))
    return out


def write_gz(name, payload: bytes):
    with gzip.GzipFile(os.path.join(dst, name), 'wb', compresslevel=9, mtime=0) as g:
        g.write(payload)
    print(name, len(payload), '->', os.path.getsize(os.path.join(dst, name)))


# ---------------- 국가
codes = set()
c_rows = {}
for tag, v6 in (('4', False), ('6', True)):
    rows = read_rows(os.path.join(src, f'dbip-country_dbip-country-ipv{tag}.csv'), v6, 3)
    c_rows[tag] = rows
    codes.update(r[2][0] for r in rows)
codes = sorted(c for c in codes if len(c) == 2)
cidx = {c: i + 1 for i, c in enumerate(codes)}
for tag, v6 in (('4', False), ('6', True)):
    bits = 64 if v6 else 32
    rr = build_ranges(c_rows[tag], lambda rest: cidx.get(rest[0]), bits)
    buf = bytearray(b'C' + tag.encode())
    buf += varint(len(codes)) + ''.join(codes).encode('ascii')
    buf += varint(len(rr))
    prev = 0
    for s, v in rr:
        buf += varint(s - prev)
        prev = s
    for s, v in rr:
        buf.append(v or 0)
    write_gz(f'c{tag}.bin', bytes(buf))

# ---------------- ASN
names = collections.defaultdict(collections.Counter)
a_rows = {}
for tag, v6 in (('4', False), ('6', True)):
    rows = read_rows(os.path.join(src, f'dbip-asn_dbip-asn-ipv{tag}.csv'), v6, 4)
    parsed = []
    for s, e, rest in rows:
        try:
            asn = int(rest[0])
        except ValueError:
            asn = 0
        name = rest[1].strip() if len(rest) > 1 else ''
        if asn:
            names[asn][name] += 1
        parsed.append((s, e, [asn]))
    a_rows[tag] = parsed
asns = sorted(names)
aidx = {a: i + 1 for i, a in enumerate(asns)}
buf = bytearray(b'AS')
buf += varint(len(asns))
prev = 0
for a in asns:
    nm = names[a].most_common(1)[0][0].encode('utf-8')[:120]
    buf += varint(a - prev) + varint(len(nm)) + nm
    prev = a
write_gz('asn.bin', bytes(buf))
for tag, v6 in (('4', False), ('6', True)):
    bits = 64 if v6 else 32
    rr = build_ranges(a_rows[tag], lambda rest: aidx.get(rest[0]) if rest[0] else None, bits)
    buf = bytearray(b'A' + tag.encode())
    buf += varint(len(rr))
    prev = 0
    for s, v in rr:
        buf += varint(s - prev)
        prev = s
    for s, v in rr:
        buf += varint(v or 0)
    write_gz(f'a{tag}.bin', bytes(buf))

print('countries', len(codes), 'asns', len(asns))
