import urllib.request
import time
import ssl
import sys

def generate_traffic():
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.cloudflare.com",
        "https://www.github.com",
        "https://www.wikipedia.org"
    ]

    print("Generating HTTPS traffic to test JA3 fingerprinting...")

    # Create an unverified context to avoid certificate issues in some test envs,
    # though standard sites should be fine.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            print(f"Requesting {url}...")
            with urllib.request.urlopen(url, context=ctx, timeout=5) as response:
                print(f"  Status: {response.status}")
        except Exception as e:
            print(f"  Failed: {e}")

        time.sleep(1)

if __name__ == "__main__":
    generate_traffic()
