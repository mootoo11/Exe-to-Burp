import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def generate_strict_ca():
    # 1. Generate Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Builder
    builder = x509.CertificateBuilder()
    
    # 3. Subject and Issuer (Self-Signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ExeToBurp CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"proxy.local"),
    ])
    
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    
    # 4. Validity
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    
    # 5. Serial Number
    builder = builder.serial_number(x509.random_serial_number())
    
    # 6. Public Key
    builder = builder.public_key(private_key.public_key())
    
    # 7. Extensions
    
    # BasicConstraints: CA:TRUE
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), 
        critical=True
    )
    
    # KeyUsage: KeyCertSign, CRLSign
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    # SubjectKeyIdentifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    
    # AuthorityKeyIdentifier (Points to itself for Root CA)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False
    )

    # 8. Sign
    certificate = builder.sign(
        private_key=private_key, 
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # 9. Save
    with open("server.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open("server.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
    print("[+] Generated strict 'server.crt' and 'server.key'.")

if __name__ == "__main__":
    generate_strict_ca()
