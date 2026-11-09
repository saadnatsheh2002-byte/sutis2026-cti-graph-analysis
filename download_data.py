#!/usr/bin/env python3
"""MITRE ATT&CK Enterprise v20.1 verisini indirir ve SHA-256 ozetini kontrol eder.
Kullanim:  python download_data.py
Cikti: enterprise-attack.json (bu klasore). Son satir 'SHA-256 ESLESIYOR' olmali."""
import hashlib, sys, urllib.request

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack-20.1.json")
EXPECTED = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
OUT = "enterprise-attack.json"

print("Indiriliyor (yaklasik 55 MB):", URL)
urllib.request.urlretrieve(URL, OUT)
digest = hashlib.sha256(open(OUT, "rb").read()).hexdigest()
print("Indirilen dosyanin SHA-256 ozeti:", digest)
print("Beklenen ozet                  :", EXPECTED)
if digest == EXPECTED:
    print("SHA-256 ESLESIYOR")
    sys.exit(0)
print("SHA-256 FARKLI: dosya bildirideki surumle ayni degil, sayilar degisebilir.")
sys.exit(1)
