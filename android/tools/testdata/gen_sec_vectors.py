import hashlib, hmac, subprocess, base64, json, os
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, rsa, ec, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def sh(args, inp=None):
    return subprocess.run(args, input=inp, capture_output=True, text=True, check=True).stdout.strip()

print("== openssl passwd")
for pw in ["", "a", "secret", "0123456789abcdef", "0123456789abcdefg", "x"*31, "y"*32, "z"*33, "pässwörd한글", "The quick brown fox jumps over the lazy dog"]:
    if pw == "": continue
    for kind, salt in [("apr1","abcdefgh"),("1","12345678"),("5","saltsaltsaltsalt"),("6","0123456789abcdef"),("6","shortsal")]:
        flag = {"apr1":"-apr1","1":"-1","5":"-5","6":"-6"}[kind]
        out = sh(["openssl","passwd",flag,"-salt",salt,"-stdin"], pw+"\n")
        print(json.dumps([kind, pw, salt, out], ensure_ascii=False))
print("== openssl passwd rounds")
out = sh(["openssl","passwd","-6","-salt","rounds=10000$abcdefghijklmnop".split('$')[0] if False else "abcdefghijklmnop","-stdin"], "custom\n")
# rounds=… must be part of salt string for openssl: '-salt' accepts only the salt; use crypt via python? skip

print("== x25519")
for i in range(5):
    k = hashlib.sha256(b"k%d"%i).digest(); u = hashlib.sha256(b"u%d"%i).digest()
    priv = x25519.X25519PrivateKey.from_private_bytes(k)
    # exchange with arbitrary u
    try:
        shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(u)).hex()
    except Exception as e: shared = "ERR"
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    print(json.dumps(["x25519", k.hex(), u.hex(), shared, pub]))
# RFC 7748 vectors via python
k=bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"); u=bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
print("rfc7748-1", x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u)).hex())
a=bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"); b=bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
A=x25519.X25519PrivateKey.from_private_bytes(a); B=x25519.X25519PrivateKey.from_private_bytes(b)
pubA=A.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw); pubB=B.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("rfc7748-dh", pubA.hex(), pubB.hex(), A.exchange(x25519.X25519PublicKey.from_public_bytes(pubB)).hex())

print("== ed25519 public keys")
for i in range(6):
    seed = hashlib.sha256(b"seed%d"%i).digest()
    pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    print(json.dumps(["ed25519", seed.hex(), pub]))
seed=bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
print("rfc8032-1", ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())

print("== ssh keys")
def line(pub): return pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
def fps(l):
    blob = base64.b64decode(l.split()[1]); return "SHA256:"+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="), "MD5:"+":".join("%02x"%b for b in hashlib.md5(blob).digest())
ed = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"sshed").digest()).public_key()
rsa2048 = rsa.generate_private_key(65537, 2048).public_key(); rsa1024 = rsa.generate_private_key(65537, 1024).public_key(); rsa4096 = None
p256 = ec.generate_private_key(ec.SECP256R1()).public_key(); p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
for name, k in [("ed25519",ed),("rsa2048",rsa2048),("rsa1024",rsa1024),("p256",p256),("p384",p384)]:
    l = line(k); a, b = fps(l); print(json.dumps(["ssh", name, l+" me@host", a, b]))

print("== AES")
pw = "correct horse"; salt = bytes(range(16)); nonce = bytes(range(100,112)); it = 1000
key = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it, 32)
pt = "비밀 메모 secret note 🙂".encode()
ct = AESGCM(key).encrypt(nonce, pt, None)
b = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
print(json.dumps(["gcm", pw, it, "scbox1.%d.%s.%s.%s" % (it, b(salt), b(nonce), b(ct))], ensure_ascii=False))
salt8 = bytes.fromhex("0102030405060708")
enc = sh(["openssl","enc","-aes-256-cbc","-pbkdf2","-iter","1234","-S",salt8.hex(),"-pass","pass:"+pw,"-a","-A"], "비밀 메모 secret note 🙂")
print(json.dumps(["cbc", pw, 1234, salt8.hex(), enc], ensure_ascii=False))

print("== pbkdf2")
for alg, p, s, c, n in [("sha256", b"password", b"salt", 1, 32), ("sha256", b"password", b"salt", 4096, 32), ("sha512", b"password", b"salt", 2, 64), ("sha1", b"", b"salt", 3, 20), ("sha256", "한글 비번".encode(), bytes.fromhex("00ff10"), 777, 40)]:
    print(json.dumps(["pbkdf2", alg, p.hex(), s.hex(), c, n, hashlib.pbkdf2_hmac(alg, p, s, c, n).hex()]))
print("wpa", hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32).hex(), hashlib.pbkdf2_hmac("sha1", b"ThisIsAPassword", b"ThisIsASSID", 4096, 32).hex())
print("wpa3", hashlib.pbkdf2_hmac("sha1", b"a"*63, b"Z"*32, 4096, 32).hex())

print("== JWT")
def b64u(x): return base64.urlsafe_b64encode(x).decode().rstrip("=")
def mk(alg, signer):
    h = b64u(json.dumps({"alg":alg,"typ":"JWT"},separators=(",",":")).encode()); p = b64u(json.dumps({"sub":"1234567890","name":"Test","iat":1516239022,"exp":4102444800},separators=(",",":")).encode())
    return h+"."+p+"."+b64u(signer((h+"."+p).encode()))
for alg, h in [("HS256","sha256"),("HS384","sha384"),("HS512","sha512")]:
    t = mk(alg, lambda m: hmac.new(b"super-secret-key", m, h).digest()); print(json.dumps(["jwt", alg, "super-secret-key", t]))
rk = rsa.generate_private_key(65537, 2048)
pubpem = rk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
nums = rk.public_key().public_numbers()
jwk_rsa = json.dumps({"kty":"RSA","n":b64u(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big")),"e":b64u(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))})
for alg, h in [("RS256",hashes.SHA256()),("RS384",hashes.SHA384())]:
    t = mk(alg, lambda m: rk.sign(m, padding.PKCS1v15(), h)); print(json.dumps(["jwt-rsa", alg, t]))
print(json.dumps(["rsa-pem", pubpem])); print(json.dumps(["rsa-jwk", jwk_rsa]))
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
for alg, curve, h, n in [("ES256", ec.SECP256R1(), hashes.SHA256(), 32), ("ES384", ec.SECP384R1(), hashes.SHA384(), 48), ("ES512", ec.SECP521R1(), hashes.SHA512(), 66)]:
    ek = ec.generate_private_key(curve)
    def signer(m, ek=ek, h=h, n=n):
        r, s = decode_dss_signature(ek.sign(m, ec.ECDSA(h))); return r.to_bytes(n,"big")+s.to_bytes(n,"big")
    t = mk(alg, signer); nums = ek.public_key().public_numbers()
    jwk = json.dumps({"kty":"EC","crv":{"ES256":"P-256","ES384":"P-384","ES512":"P-521"}[alg],"x":b64u(nums.x.to_bytes(n,"big")),"y":b64u(nums.y.to_bytes(n,"big"))})
    pem = ek.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    print(json.dumps(["jwt-ec", alg, t, jwk, pem]))
