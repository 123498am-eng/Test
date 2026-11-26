import os
import json, re
def kt(s):
    out = []
    for ch in s:
        if ch == '\\': out.append('\\\\')
        elif ch == '"': out.append('\\"')
        elif ch == '$': out.append('\\$')
        elif ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ord(ch) < 32: out.append('\\u%04x' % ord(ch))
        else: out.append(ch)
    return '"' + ''.join(out) + '"'
def lst(rows): return "listOf(\n" + ",\n".join("        listOf(" + ", ".join(kt(str(c)) for c in r) + ")" for r in rows) + ",\n    )"
groups = {}; consts = {}
for line in open('sec_vectors.txt', encoding='utf-8'):
    line = line.rstrip('\n')
    if line.startswith('['):
        a = json.loads(line); groups.setdefault(a[0], []).append(a[1:])
    elif line.startswith('=='): continue
    else:
        parts = line.split(' '); consts[parts[0]] = parts[1:]
o = ["package com.selfcheck.app", "", "/* 자동으로 만든 시험 기준값: openssl 3.0 · 파이썬 cryptography · hashlib 로 계산한 값 (직접 만든 구현과 비교용) */", "object SecVectors {"]
o.append("    /** (종류, 비밀번호, 솔트, openssl passwd 결과) */"); o.append("    val crypt = " + lst(groups['apr1'] and [[k] + r for k in ['apr1','1','5','6'] for r in []] or []))
# crypt rows come from lines starting with the kind names
rows = []
for line in open('sec_vectors.txt', encoding='utf-8'):
    if re.match(r'^\["(apr1|1|5|6)"', line): rows.append(json.loads(line))
o[-1] = "    val crypt = " + lst(rows)
o.append("    /** (개인키, 상대 공개값, 공유 비밀, 내 공개키) */"); o.append("    val x25519 = " + lst(groups['x25519']))
o.append("    /** (시드, 공개키) */"); o.append("    val ed25519 = " + lst(groups['ed25519']))
o.append("    /** (이름, 공개키 한 줄, SHA256 지문, MD5 지문) */"); o.append("    val ssh = " + lst(groups['ssh']))
o.append("    /** (비밀번호, 반복, 암호문) */"); o.append("    val gcm = " + lst(groups['gcm']))
o.append("    /** (비밀번호, 반복, 솔트 16진수, 암호문 Base64) */"); o.append("    val cbc = " + lst(groups['cbc']))
o.append("    /** (해시, 비밀번호 16진수, 솔트 16진수, 반복, 길이, 결과 16진수) */"); o.append("    val pbkdf2 = " + lst(groups['pbkdf2']))
o.append("    /** (알고리즘, 비밀키, 토큰) */"); o.append("    val jwtHs = " + lst(groups['jwt']))
o.append("    /** (알고리즘, 토큰) */"); o.append("    val jwtRs = " + lst(groups['jwt-rsa']))
o.append("    val rsaPem = " + kt(groups['rsa-pem'][0][0])); o.append("    val rsaJwk = " + kt(groups['rsa-jwk'][0][0]))
o.append("    /** (알고리즘, 토큰, JWK, PEM) */"); o.append("    val jwtEs = " + lst(groups['jwt-ec']))
o.append("    const val RFC7748_SCALAR = " + kt("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")); o.append("    const val RFC7748_U = " + kt("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")); o.append("    const val RFC7748_OUT = " + kt(consts['rfc7748-1'][0]))
o.append("    const val ALICE_PRIV = " + kt("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")); o.append("    const val BOB_PRIV = " + kt("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
o.append("    const val ALICE_PUB = " + kt(consts['rfc7748-dh'][0])); o.append("    const val BOB_PUB = " + kt(consts['rfc7748-dh'][1])); o.append("    const val DH_SHARED = " + kt(consts['rfc7748-dh'][2]))
o.append("    const val RFC8032_SEED = " + kt("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")); o.append("    const val RFC8032_PUB = " + kt(consts['rfc8032-1'][0]))
o.append("    const val WPA_IEEE = " + kt(consts['wpa'][0])); o.append("    const val WPA_IEEE2 = " + kt(consts['wpa'][1])); o.append("    const val WPA_LONG = " + kt(consts['wpa3'][0]))
o.append("}")
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../app/src/test/java/com/selfcheck/app/NetSecVectors.kt'),'w',encoding='utf-8').write("\n".join(o)+"\n")
print("ok", len(rows))
