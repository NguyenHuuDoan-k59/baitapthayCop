"""Đối chiếu bằng Python (thư viện `cryptography`) cùng thuật toán với hai app C#.

Chạy:  pip install cryptography
       python reference_check.py            # 100, 1000, 3000 MB
       python reference_check.py 100 500    # kích thước tùy chọn (MB)
Số liệu là THAM CHIẾU, không thay cho số đo bằng app C# trên máy của bạn.
"""
import hashlib, hmac, os, secrets, struct, sys, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK = 1 << 20


def chacha_big(sizes_mb):
    print("=== ChaCha20-Poly1305, file lớn (khối 1 MB, xử lý theo dòng) ===")
    print(f"{'MB':>6} {'enc s':>8} {'dec s':>8} {'enc MB/s':>9} {'dec MB/s':>9} identical")
    aead = ChaCha20Poly1305(os.urandom(32))
    prefix = os.urandom(4)
    for mb in sizes_mb:
        enc_t = dec_t = 0.0
        same = True
        for i in range(mb):
            block = os.urandom(CHUNK)
            nonce = prefix + struct.pack(">q", i)
            aad = struct.pack(">q", i) + bytes([1 if i == mb - 1 else 0])
            t = time.perf_counter(); ct = aead.encrypt(nonce, block, aad); enc_t += time.perf_counter() - t
            t = time.perf_counter(); pt = aead.decrypt(nonce, ct, aad); dec_t += time.perf_counter() - t
            same &= pt == block
        print(f"{mb:>6} {enc_t:>8.2f} {dec_t:>8.2f} {mb/enc_t:>9.0f} {mb/dec_t:>9.0f} {same}")


def ecc_speed(iters=200):
    print("\n=== ECC / RSA, ms mỗi lần ===")
    data = os.urandom(64)
    print(f"{'':<10}{'keygen':>10}{'ECDH':>10}{'sign':>10}{'verify':>10}")

    def ms(n, f):
        f(); t = time.perf_counter()
        for _ in range(n): f()
        return (time.perf_counter() - t) / n * 1000

    for name, curve in (("P-256", ec.SECP256R1()), ("P-384", ec.SECP384R1()), ("P-521", ec.SECP521R1())):
        a, b = ec.generate_private_key(curve), ec.generate_private_key(curve)
        sig = a.sign(data, ec.ECDSA(hashes.SHA512()))
        print(f"{'ECC '+name:<10}{ms(iters, lambda: ec.generate_private_key(curve)):>10.4f}"
              f"{ms(iters, lambda: a.exchange(ec.ECDH(), b.public_key())):>10.4f}"
              f"{ms(iters, lambda: a.sign(data, ec.ECDSA(hashes.SHA512()))):>10.4f}"
              f"{ms(iters, lambda: a.public_key().verify(sig, data, ec.ECDSA(hashes.SHA512()))):>10.4f}")
    for bits in (2048, 3072):
        k = rsa.generate_private_key(65537, bits)
        sig = k.sign(data, padding.PKCS1v15(), hashes.SHA512())
        print(f"{'RSA '+str(bits):<10}{'-':>10}{'-':>10}"
              f"{ms(iters, lambda: k.sign(data, padding.PKCS1v15(), hashes.SHA512())):>10.4f}"
              f"{ms(iters, lambda: k.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA512())):>10.4f}")


def ecies_demo():
    print("\n=== Mã hóa lai ECDH + HKDF-SHA256 + ChaCha20-Poly1305 ===")
    recv = ec.generate_private_key(ec.SECP256R1())
    eph = ec.generate_private_key(ec.SECP256R1())
    info = b"BaiTap-ECIES-v1"
    for size in (32, 1024, 5 * 1024 * 1024):
        plain = os.urandom(size)
        key = HKDF(hashes.SHA256(), 32, None, info).derive(eph.exchange(ec.ECDH(), recv.public_key()))
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key).encrypt(nonce, plain, None)
        key2 = HKDF(hashes.SHA256(), 32, None, info).derive(recv.exchange(ec.ECDH(), eph.public_key()))
        print(f"  {size:>8} byte -> giải mã đúng = {ChaCha20Poly1305(key2).decrypt(nonce, ct, None) == plain}")


def sha512_avalanche(trials=10000):
    print("\n=== SHA-512 thác đổ (đổi 1 bit, 10000 lần) ===")
    tot, mn, mx = 0, 10**9, 0
    for _ in range(trials):
        m = bytearray(os.urandom(64))
        h1 = hashlib.sha512(m).digest()
        bit = secrets.randbelow(512)
        m[bit // 8] ^= 1 << (bit % 8)
        h2 = hashlib.sha512(m).digest()
        d = bin(int.from_bytes(h1, "big") ^ int.from_bytes(h2, "big")).count("1")
        tot += d; mn = min(mn, d); mx = max(mx, d)
    print(f"trung bình {tot/trials:.2f}/512 bit ({tot/trials/512*100:.2f}%), min {mn}, max {mx}")


# --- ECDSA xác định RFC 6979 (P-256, SHA-512) ---
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    l = ((3 * p[0] * p[0] + A) * pow(2 * p[1], P - 2, P) if p == q else (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P)) % P
    x = (l * l - p[0] - q[0]) % P
    return x, (l * (p[0] - x) - p[1]) % P


def _mul(k, p):
    r = None
    while k:
        if k & 1: r = _add(r, p)
        p = _add(p, p); k >>= 1
    return r


def _bits2int(b):
    v = int.from_bytes(b, "big")
    return v >> (len(b) * 8 - 256) if len(b) * 8 > 256 else v


def _gen_k(x, h1, H):
    hl = H().digest_size
    xo, ho = x.to_bytes(32, "big"), (_bits2int(h1) % N).to_bytes(32, "big")
    V, K = b"\x01" * hl, b"\x00" * hl
    K = hmac.new(K, V + b"\x00" + xo + ho, H).digest(); V = hmac.new(K, V, H).digest()
    K = hmac.new(K, V + b"\x01" + xo + ho, H).digest(); V = hmac.new(K, V, H).digest()
    while True:
        T = b""
        while len(T) * 8 < 256:
            V = hmac.new(K, V, H).digest(); T += V
        k = _bits2int(T)
        if 1 <= k < N: return k
        K = hmac.new(K, V + b"\x00", H).digest(); V = hmac.new(K, V, H).digest()


def det_sign(x, msg, H=hashlib.sha512):
    h1 = H(msg).digest()
    k = _gen_k(x, h1, H)
    r = _mul(k, G)[0] % N
    return r, pow(k, N - 2, N) * (_bits2int(h1) + r * x) % N


def signatures():
    print("\n=== Chữ ký: ECDSA ngẫu nhiên vs RFC 6979, cùng dữ liệu, cùng khóa, 5 lần ===")
    data = b"Nguyen Huu Doan"
    key = ec.generate_private_key(ec.SECP256R1())
    rnd = {key.sign(data, ec.ECDSA(hashes.SHA512())) for _ in range(5)}
    print(f"ECDSA ngẫu nhiên: số chữ ký khác nhau = {len(rnd)} / 5")
    x = key.private_numbers().private_value
    det = {det_sign(x, data) for _ in range(5)}
    ok = True
    for r, s in det:
        key.public_key().verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA512()))
    print(f"RFC 6979         : số chữ ký khác nhau = {len(det)} / 5; xác minh đúng = {ok}")
    # vector kiểm thử của RFC 6979 (P-256, SHA-256, 'sample')
    x0 = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    r, s = det_sign(x0, b"sample", hashlib.sha256)
    print("Vector RFC 6979 (P-256/SHA-256):", r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
          and s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8)


if __name__ == "__main__":
    sizes = [int(a) for a in sys.argv[1:]] or [100, 1000, 3000]
    chacha_big(sizes)
    ecc_speed()
    ecies_demo()
    sha512_avalanche()
    signatures()
