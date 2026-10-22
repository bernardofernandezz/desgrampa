"""Extrai o certificado de assinatura de um APK (esquemas v1, v2 e v3), só com a stdlib.

Retorna o SHA-1 do certificado em DER — o mesmo formato usado na base de IOCs.
"""

import hashlib
import struct
import zipfile

from .util import sha256_file

V2_ID, V3_ID, V31_ID = 0x7109871A, 0xF05368C0, 0x1B93AD61
MAGIC = b"APK Sig Block 42"


def _lp(buf, off):
    """Lê um bloco prefixado por uint32 LE; devolve (bytes, próximo offset)."""
    (n,) = struct.unpack_from("<I", buf, off)
    return buf[off + 4: off + 4 + n], off + 4 + n


def _signing_block_certs(data):
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0:
        return []
    (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
    if cd_offset < 24 or data[cd_offset - 16: cd_offset] != MAGIC:
        return []
    (size,) = struct.unpack_from("<Q", data, cd_offset - 24)
    start = cd_offset - size - 8
    if start < 0:
        return []
    off, end = start + 8, cd_offset - 24
    blocks = {}
    while off + 12 <= end:
        (plen,) = struct.unpack_from("<Q", data, off)
        (pid,) = struct.unpack_from("<I", data, off + 8)
        blocks[pid] = data[off + 12: off + 8 + plen]
        off += 8 + plen
    for pid in (V31_ID, V3_ID, V2_ID):
        if pid not in blocks:
            continue
        signers, _ = _lp(blocks[pid], 0)
        certs, so = [], 0
        while so < len(signers):
            signer, so = _lp(signers, so)
            signed_data, _ = _lp(signer, 0)
            _, co = _lp(signed_data, 0)          # digests
            cert_seq, _ = _lp(signed_data, co)
            ko = 0
            while ko < len(cert_seq):
                cert, ko = _lp(cert_seq, ko)
                certs.append(cert)
        if certs:
            return certs
    return []


def _der(buf, off):
    """Lê um TLV DER; devolve (tag, início do conteúdo, fim)."""
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[off: off + k], "big")
        off += k
    return tag, off, off + n


def _pkcs7_certs(der):
    _, c, _ = _der(der, 0)                 # ContentInfo SEQUENCE
    _, _, e = _der(der, c)                 # contentType OID
    _, c, _ = _der(der, e)                 # [0] EXPLICIT
    _, c, end = _der(der, c)               # SignedData SEQUENCE
    off = c
    certs = []
    while off < end:
        tag, cs, ce = _der(der, off)
        if tag == 0xA0:                    # certificates [0] IMPLICIT
            o = cs
            while o < ce:
                _, _, e2 = _der(der, o)
                certs.append(der[o:e2])
                o = e2
            break
        off = ce
    return certs


def _v1_certs(path):
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            upper = name.upper()
            if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
                return _pkcs7_certs(z.read(name))
    return []


def certificates(path):
    """[{sha1, sha256}] dos certificados de assinatura (DER) do APK."""
    with open(path, "rb") as f:
        data = f.read()
    certs = _signing_block_certs(data)
    if not certs:
        try:
            certs = _v1_certs(path)
        except (zipfile.BadZipFile, IndexError, ValueError):
            certs = []
    return [{"sha1": hashlib.sha1(c).hexdigest().upper(), "sha256": hashlib.sha256(c).hexdigest().upper()}
            for c in certs]


def file_sha256(path):
    return sha256_file(path)
