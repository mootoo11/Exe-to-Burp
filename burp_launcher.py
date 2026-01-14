import os
import subprocess
import sys
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generic Burp Suite/Proxy Launcher with SSL Bypass",
        epilog="Example: python burp_launcher.py -t game.exe -p 127.0.0.1:8080"
    )
    
    parser.add_argument("-t", "--target", required=True, help="Path to the executable to launch (e.g., app.exe)")
    parser.add_argument("-p", "--proxy", default="http://127.0.0.1:8080", help="Proxy address (default: http://127.0.0.1:8080)")
    parser.add_argument("-c", "--cert", default="server.crt", help="Path to the CA certificate to trust (PEM format)")
    parser.add_argument("--no-ssl", action="store_true", help="Disable automatic SSL certificate injection")
    
    return parser.parse_args()

def main():
    args = parse_args()
    
    print("=== Generic Proxy Launcher ===")
    print(f"[*] Target: {args.target}")
    
    # --- CHECK 1: Target File Existence ---
    # التحقق من وجود الملف التنفيذي
    if not os.path.exists(args.target):
        print(f"\n[!] ERROR: Target file not found: {args.target}")
        print("    Please sanity check the path and try again.")
        print("    تأكد من مسار الملف وحاول مرة أخرى.")
        sys.exit(1)

    # Environment Setup
    env = os.environ.copy()
    
    # --- CHECK 2: Proxy Setup ---
    # إعداد البروكسي
    print(f"[*] Setting Proxy: {args.proxy}")
    env["HTTP_PROXY"] = args.proxy
    env["HTTPS_PROXY"] = args.proxy
    
    # --- CHECK 3: SSL Certificate Existence ---
    # التحقق من وجود الشهادة وحقنها
    if not args.no_ssl:
        if os.path.exists(args.cert):
            print(f"[*] Trusting CA:   {args.cert}")
            
            # Convert to absolute path to avoid issues if working dir changes
            # تحويل المسار إلى مسار كامل لتجنب المشاكل
            cert_path = os.path.abspath(args.cert)
            
            # Inject into Python 'requests' / generic OpenSSL
            env["REQUESTS_CA_BUNDLE"] = cert_path
            env["SSL_CERT_FILE"] = cert_path
            
            # Inject into Node.js applications
            env["NODE_EXTRA_CA_CERTS"] = cert_path 
            
        else:
            print(f"\n[!] WARNING: Certificate file not found: {args.cert}")
            print(f"    SSL Pinning bypass will likely FAIL.")
            print(f"    To fix: Generate 'server.crt' or specify path with -c")
            print(f"    تحذير: ملف الشهادة غير موجود. قد يفشل تجاوز الحماية.")
            
            # Optional: Ask user if they want to proceed via input? 
            # For automation, we just warn.
    else:
        print("[*] SSL injection disabled by user (--no-ssl).")

    # --- EXECUTION ---
    # تشغيل البرنامج
    print("-" * 40)
    print(f"[*] Launching: {args.target}")
    print("-" * 40)
    
    try:
        # Launch the target with the modified environment
        subprocess.call([args.target], cwd=os.getcwd(), env=env)
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user.")
    except Exception as e:
        print(f"\n[!] FATAL ERROR launching executable: {e}")
        print("    Please check if the file is a valid executable.")

if __name__ == "__main__":
    main()
