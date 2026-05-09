# -*- coding: utf-8 -*-
"""
生成自签名SSL证书（用于HTTPS）
运行一次即可，证书有效期10年
纯Python实现，不依赖openssl命令或cryptography库
"""
import os
import struct
import hashlib
import random
import time
from datetime import datetime, timedelta, timezone

CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")


# ==================== 纯Python RSA + X.509 实现 ====================

def _int_to_bytes(n):
    """大整数转字节"""
    if n == 0:
        return b'\x00'
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


def _bytes_to_int(b):
    """字节转大整数"""
    return int.from_bytes(b, 'big')


def _modpow(base, exp, mod):
    """模幂运算"""
    return pow(base, exp, mod)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _modinv(a, m):
    """扩展欧几里得算法求模逆"""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("模逆不存在")
    return x % m


def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _is_probable_prime(n, k=20):
    """Miller-Rabin素性测试"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = _modpow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = _modpow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits):
    """生成指定位数的素数"""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n


def _generate_rsa_keypair(bits=2048):
    """生成RSA密钥对"""
    e = 65537
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if _gcd(e, phi) == 1:
            d = _modinv(e, phi)
            dp = d % (p - 1)
            dq = d % (q - 1)
            qinv = _modinv(q, p)
            return (n, e, d, p, q, dp, dq, qinv)


# ==================== ASN.1 DER 编码 ====================

def _der_len(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xff])
    else:
        return bytes([0x83, length >> 16, (length >> 8) & 0xff, length & 0xff])


def _der_int(n):
    data = _int_to_bytes(n)
    if data[0] & 0x80:
        data = b'\x00' + data
    return b'\x02' + _der_len(len(data)) + data


def _der_bitstring(data):
    return b'\x03' + _der_len(len(data) + 1) + b'\x00' + data


def _der_octetstring(data):
    return b'\x04' + _der_len(len(data)) + data


def _der_sequence(*items):
    body = b''.join(items)
    return b'\x30' + _der_len(len(body)) + body


def _der_set(*items):
    body = b''.join(items)
    return b'\x31' + _der_len(len(body)) + body


def _der_oid(oid_parts):
    body = bytes([oid_parts[0] * 40 + oid_parts[1]])
    for part in oid_parts[2:]:
        if part < 128:
            body += bytes([part])
        else:
            encoded = []
            encoded.append(part & 0x7f)
            part >>= 7
            while part > 0:
                encoded.append((part & 0x7f) | 0x80)
                part >>= 7
            body += bytes(reversed(encoded))
    return b'\x06' + _der_len(len(body)) + body


def _der_utf8string(s):
    data = s.encode('utf-8')
    return b'\x0c' + _der_len(len(data)) + data


def _der_printablestring(s):
    data = s.encode('ascii')
    return b'\x13' + _der_len(len(data)) + data


def _der_utctime(dt):
    data = dt.strftime('%y%m%d%H%M%SZ').encode('ascii')
    return b'\x17' + _der_len(len(data)) + data


def _der_explicit(tag, content):
    return bytes([0xa0 | tag]) + _der_len(len(content)) + content


def _der_null():
    return b'\x05\x00'


def _pkcs1_private_key(n, e, d, p, q, dp, dq, qinv):
    """PKCS#1 RSAPrivateKey DER编码"""
    return _der_sequence(
        _der_int(0),  # version
        _der_int(n),
        _der_int(e),
        _der_int(d),
        _der_int(p),
        _der_int(q),
        _der_int(dp),
        _der_int(dq),
        _der_int(qinv),
    )


def _pkcs1_public_key(n, e):
    """PKCS#1 RSAPublicKey DER编码"""
    return _der_sequence(_der_int(n), _der_int(e))


def _pkcs8_private_key(pkcs1_der):
    """PKCS#8 PrivateKeyInfo DER编码"""
    rsa_oid = _der_sequence(_der_oid([1, 2, 840, 113549, 1, 1, 1]), _der_null())
    return _der_sequence(
        _der_int(0),
        rsa_oid,
        _der_octetstring(pkcs1_der),
    )


def _spki_public_key(pkcs1_der):
    """SubjectPublicKeyInfo DER编码"""
    rsa_oid = _der_sequence(_der_oid([1, 2, 840, 113549, 1, 1, 1]), _der_null())
    return _der_sequence(rsa_oid, _der_bitstring(pkcs1_der))


def _x509_name(cn, o="", c=""):
    """X.501 Name DER编码（SEQUENCE OF RDN）"""
    def attr_rdn(oid, value):
        return _der_set(_der_sequence(oid, _der_utf8string(value)))
    parts = []
    if c:
        parts.append(attr_rdn(_der_oid([2, 5, 4, 6]), c))
    if o:
        parts.append(attr_rdn(_der_oid([2, 5, 4, 10]), o))
    parts.append(attr_rdn(_der_oid([2, 5, 4, 3]), cn))
    body = b''.join(parts)
    return b'\x30' + _der_len(len(body)) + body


def _make_tbs_cert(subject_der, issuer_der, serial, not_before, not_after, spki_der, san_der):
    """构建 TBSCertificate"""
    version = _der_explicit(0, _der_int(2))  # v3
    sig_algo = _der_sequence(_der_oid([1, 2, 840, 113549, 1, 1, 11]), _der_null())
    extensions = _der_explicit(3, _der_sequence(san_der))
    return _der_sequence(
        version,
        _der_int(serial),
        sig_algo,
        issuer_der,
        _der_sequence(_der_utctime(not_before), _der_utctime(not_after)),
        subject_der,
        spki_der,
        extensions,
    )


def _sha256(data):
    return hashlib.sha256(data).digest()


def _pkcs1_sign(data_der, n, d):
    """PKCS#1 v1.5 签名"""
    digest = _sha256(data_der)
    # DigestInfo
    digest_info = _der_sequence(
        _der_sequence(_der_oid([2, 16, 840, 1, 101, 3, 4, 2, 1]), _der_null()),
        _der_octetstring(digest),
    )
    # PKCS#1 padding
    em_len = (n.bit_length() + 7) // 8
    ps_len = em_len - len(digest_info) - 3
    padded = b'\x00\x01' + b'\xff' * ps_len + b'\x00' + digest_info
    # RSA签名
    m = _bytes_to_int(padded)
    s = _modpow(m, d, n)
    return _int_to_bytes(s)


def _pem_encode(data, marker):
    import base64
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {marker}-----\n" + '\n'.join(lines) + f"\n-----END {marker}-----\n"


# ==================== 主生成函数 ====================

def generate_cert():
    """纯Python生成自签名SSL证书"""
    os.makedirs(CERT_DIR, exist_ok=True)

    print("[SSL] 正在生成RSA密钥（可能需要几秒）...")
    n, e, d, p, q, dp, dq, qinv = _generate_rsa_keypair(2048)
    print("[SSL] RSA密钥生成完成")

    # 构建密钥
    pkcs1_key = _pkcs1_private_key(n, e, d, p, q, dp, dq, qinv)
    pkcs8_key = _pkcs8_private_key(pkcs1_key)
    pub_pkcs1 = _pkcs1_public_key(n, e)
    spki = _spki_public_key(pub_pkcs1)

    # 证书信息
    serial = random.getrandbits(64)
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=3650)

    subject_der = _x509_name("NetScan Local", "NetScan Security", "CN")
    issuer_der = subject_der  # 自签名

    # SAN扩展
    # DNS:localhost + IP:127.0.0.1
    san_content = _der_sequence(
        b'\x82\x09' + b'localhost',
        b'\x87\x04' + bytes([127, 0, 0, 1]),
    )
    san_ext = _der_sequence(
        _der_oid([2, 5, 29, 17]),
        _der_octetstring(san_content),
    )

    # 构建TBS
    tbs_der = _make_tbs_cert(subject_der, issuer_der, serial, not_before, not_after, spki, san_ext)

    # 签名
    sig_algo = _der_sequence(_der_oid([1, 2, 840, 113549, 1, 1, 11]), _der_null())
    signature = _pkcs1_sign(tbs_der, n, d)
    cert_der = _der_sequence(tbs_der, sig_algo, _der_bitstring(signature))

    # 写入文件
    with open(CERT_FILE, 'w') as f:
        f.write(_pem_encode(cert_der, "CERTIFICATE"))
    with open(KEY_FILE, 'w') as f:
        f.write(_pem_encode(pkcs8_key, "PRIVATE KEY"))

    print(f"[SSL] 证书生成成功！")
    print(f"  证书: {CERT_FILE}")
    print(f"  私钥: {KEY_FILE}")
    print(f"  有效期: 10年")
    return True


if __name__ == "__main__":
    generate_cert()
