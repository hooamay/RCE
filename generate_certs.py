# generate_certs.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Generate private key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Create certificate subject and issuer
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PH"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"NCR"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Manila"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"LocalHost"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

# Build cert
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    key.public_key()).serial_number(
    x509.random_serial_number()).not_valid_before(
    datetime.utcnow()).not_valid_after(
    datetime.utcnow() + timedelta(days=365)).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())

# Write private key
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Write certificate
with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("[+] key.pem and cert.pem generated.")
