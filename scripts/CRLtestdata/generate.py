#!/usr/bin/env python3
"""
Generate test CA certificates, leaf certificates, and CRLs for CRL
upload / management testing.

Output layout (all paths relative to this script's directory):
  ca1/ca.{key,crt}            -- CA1 key and self-signed cert
  ca2/ca.{key,crt}            -- CA2 key and self-signed cert
  certs/client.{key,crt}      -- client cert signed by CA1
  certs/server.{key,crt}      -- node cert   signed by CA2
  crls/ca1_empty.pem          -- CA1 CRL, no revocations  (CRL#1)
  crls/ca1_revoked_client.pem -- CA1 CRL, client revoked  (CRL#2)
  crls/ca2_empty.pem          -- CA2 CRL, no revocations  (CRL#1)
  crls/ca2_revoked_server.pem -- CA2 CRL, server revoked  (CRL#2)

Optional: --extra-revoked N pads every CRL with N additional fake
revoked serial numbers, inflating file size for load testing.
~200000 entries yield roughly 10 MB per CRL.

Requires: pip install cryptography
"""

import argparse
import datetime
import time
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DIR = Path(__file__).parent
NOW = datetime.datetime.now(datetime.timezone.utc)
TEN_YEARS = datetime.timedelta(days=3650)
THIRTY_DAYS = datetime.timedelta(days=30)
ONE_DAY = datetime.timedelta(days=1)


# ---- helpers -----------------------------------------------------------

def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_key(key, path):
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def save_cert(cert, path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def save_crl(crl, path):
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    der_path = path.with_suffix(".der")
    der_path.write_bytes(crl.public_bytes(serialization.Encoding.DER))


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CRLTest"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def make_ca_cert(key, cn):
    n = name(cn)
    return (
        x509.CertificateBuilder()
        .subject_name(n)
        .issuer_name(n)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False,
                decipher_only=False),
            critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .sign(key, hashes.SHA256())
    )


def make_leaf_cert(key, ca_cert, ca_key, cn, is_client):
    eku_oid = (ExtendedKeyUsageOID.CLIENT_AUTH
               if is_client else ExtendedKeyUsageOID.SERVER_AUTH)
    key_usage = x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=not is_client, data_encipherment=False,
        key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False)
    return (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([eku_oid]),
            critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def make_crl(ca_cert, ca_key, crl_number, issue_time,
             revoked_certs=None, extra_revoked=0):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(issue_time)
        .next_update(issue_time + THIRTY_DAYS)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()),
            critical=False)
    )
    # Collect all RevokedCertificate objects in a plain Python list and
    # assign them to the builder in one shot.  Calling
    # add_revoked_certificate() in a loop is O(n²): each call returns a
    # new builder instance with a freshly copied list, so n calls copy
    # 0+1+…+(n-1) elements.  A single direct assignment is O(n).
    revoked_list = [
        x509.RevokedCertificateBuilder()
        .serial_number(cert.serial_number)
        .revocation_date(issue_time)
        .build()
        for cert in (revoked_certs or [])
    ]
    if extra_revoked:
        t0 = time.monotonic()
        for i in range(extra_revoked):
            revoked_list.append(
                x509.RevokedCertificateBuilder()
                .serial_number(x509.random_serial_number())
                .revocation_date(issue_time)
                .build()
            )
            if (i + 1) % 10000 == 0:
                elapsed = time.monotonic() - t0
                rate = (i + 1) / elapsed
                print(f"  fake entries: {i+1}/{extra_revoked}"
                      f"  {elapsed:.1f}s  {rate:.0f} entries/s",
                      flush=True)
        t1 = time.monotonic()
        print(f"  fake entries done: {t1-t0:.2f}s", flush=True)
    builder._revoked_certificates = revoked_list
    if extra_revoked:
        t_sign = time.monotonic()
    crl = builder.sign(ca_key, hashes.SHA256())
    if extra_revoked:
        print(f"  sign: {time.monotonic()-t_sign:.2f}s", flush=True)
    return crl


# ---- parse arguments ---------------------------------------------------
_parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter)
_parser.add_argument(
    '--extra-revoked', type=int, default=0, metavar='N',
    help=('pad every CRL with N additional fake revoked serial numbers'
          ' (default 0; use ~200000 for ~10 MB CRLs)'))
_args = _parser.parse_args()
extra_revoked = _args.extra_revoked

# ---- clean previous run and create directories -------------------------
for d in ("ca1", "ca2", "certs", "crls"):
    shutil.rmtree(DIR / d, ignore_errors=True)
    (DIR / d).mkdir()

# ---- 1. CA1 ------------------------------------------------------------
ca1_key = gen_key()
ca1_cert = make_ca_cert(ca1_key, "TestCA1")
save_key(ca1_key, DIR / "ca1" / "ca.key")
save_cert(ca1_cert, DIR / "ca1" / "ca.crt")

# ---- 2. CA2 ------------------------------------------------------------
ca2_key = gen_key()
ca2_cert = make_ca_cert(ca2_key, "TestCA2")
save_key(ca2_key, DIR / "ca2" / "ca.key")
save_cert(ca2_cert, DIR / "ca2" / "ca.crt")

# ---- 3. Client cert signed by CA1 --------------------------------------
client_key = gen_key()
client_cert = make_leaf_cert(
    client_key, ca1_cert, ca1_key, "test-client", is_client=True)
save_key(client_key, DIR / "certs" / "client.key")
save_cert(client_cert, DIR / "certs" / "client.crt")

# ---- 4. Node cert signed by CA2 ----------------------------------------
server_key = gen_key()
server_cert = make_leaf_cert(
    server_key, ca2_cert, ca2_key, "test-server", is_client=False)
save_key(server_key, DIR / "certs" / "server.key")
save_cert(server_cert, DIR / "certs" / "server.crt")

# ---- 5. CA1 CRLs -------------------------------------------------------
# Empty CRL issued yesterday; revoked CRL issued today.  Both
# thisUpdate values are in the past and strictly ordered, simulating a
# real sequence where the CA issues a fresh CRL after a revocation.
print("Generating ca1_empty.pem ...", flush=True)
ca1_crl_empty = make_crl(
    ca1_cert, ca1_key, crl_number=1, issue_time=NOW - ONE_DAY,
    extra_revoked=extra_revoked)
save_crl(ca1_crl_empty, DIR / "crls" / "ca1_empty.pem")

print("Generating ca1_revoked_client.pem ...", flush=True)
ca1_crl_revoked = make_crl(
    ca1_cert, ca1_key, crl_number=2, issue_time=NOW,
    revoked_certs=[client_cert], extra_revoked=extra_revoked)
save_crl(ca1_crl_revoked, DIR / "crls" / "ca1_revoked_client.pem")

# ---- 6. CA2 CRLs -------------------------------------------------------
print("Generating ca2_empty.pem ...", flush=True)
ca2_crl_empty = make_crl(
    ca2_cert, ca2_key, crl_number=1, issue_time=NOW - ONE_DAY,
    extra_revoked=extra_revoked)
save_crl(ca2_crl_empty, DIR / "crls" / "ca2_empty.pem")

print("Generating ca2_revoked_server.pem ...", flush=True)
ca2_crl_revoked = make_crl(
    ca2_cert, ca2_key, crl_number=2, issue_time=NOW,
    revoked_certs=[server_cert], extra_revoked=extra_revoked)
save_crl(ca2_crl_revoked, DIR / "crls" / "ca2_revoked_server.pem")

# ---- summary -----------------------------------------------------------
print("\nCA certificates:")
for label, cert in [("ca1/ca.crt", ca1_cert), ("ca2/ca.crt", ca2_cert)]:
    print(f"  {label:<20} {cert.subject.rfc4514_string()}")

print("\nLeaf certificates:")
for label, cert, signer in [
        ("certs/client.crt", client_cert, "CA1"),
        ("certs/server.crt", server_cert, "CA2")]:
    print(f"  {label:<20} {cert.subject.rfc4514_string()}"
          f"  serial={cert.serial_number:#x}  [{signer}]")

print("\nCRLs:")
for label, crl in [
        ("ca1_empty.pem",          ca1_crl_empty),
        ("ca1_revoked_client.pem", ca1_crl_revoked),
        ("ca2_empty.pem",          ca2_crl_empty),
        ("ca2_revoked_server.pem", ca2_crl_revoked)]:
    num = crl.extensions.get_extension_for_class(
        x509.CRLNumber).value.crl_number
    count = sum(1 for _ in crl)
    pem_size = (DIR / "crls" / label).stat().st_size
    der_size = (DIR / "crls" / label).with_suffix(".der").stat().st_size
    print(f"  crls/{label:<36} CRL#{num}  {count} revoked"
          f"  pem={pem_size:,}B  der={der_size:,}B")

print()
