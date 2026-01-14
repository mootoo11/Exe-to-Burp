from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os

def create_p12_crypto(cert_file, key_file, p12_file, password="password"):
    try:
        # Read Cert
        with open(cert_file, "rb") as f:
            cert_bytes = f.read()
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    
        # Read Key
        with open(key_file, "rb") as f:
            key_bytes = f.read()
            key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())

        # Serialize to P12
        p12_data = pkcs12.serialize_key_and_certificates(
            b"ExeToBurp CA", # Friendly Name
            key,
            cert,
            None, # No CAS
            serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

        with open(p12_file, "wb") as f:
            f.write(p12_data)
            
        print(f"[+] Created '{p12_file}'")
        print(f"[+] Password is: {password}")
        print(f"[+] Action Required: Import this file into Burp Suite (Proxy -> Import CA).")

    except Exception as e:
        print(f"[!] Error creating P12 with cryptography lib: {e}")

if __name__ == "__main__":
    if os.path.exists("server.crt") and os.path.exists("server.key"):
        create_p12_crypto("server.crt", "server.key", "burp_custom_ca.p12")
    else:
        print("[!] Error: 'server.crt' or 'server.key' not found.")
        print("    Please run 'python gen_cert_v2.py' first.")
