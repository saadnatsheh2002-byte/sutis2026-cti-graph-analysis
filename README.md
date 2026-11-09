# CTI graflarinda merkezilik ve topluluk tespiti karsilastirmasi (SUTIS 2026)

Veri: MITRE ATT&CK Enterprise v20.1 STIX 2.1 (surum numarali, degismeyen dosya)
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json
  SHA-256: 539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5

Calistirma sirasi (Python 3.12, bu klasorun icinde):
  pip install -r requirements.txt
  python download_data.py      # veriyi indirir ve ozeti kontrol eder -> "SHA-256 ESLESIYOR"
  python cti_graph_pipeline.py --stix enterprise-attack.json --out results --seeds 30 --lfr-reps 5
  python checks.py             # son satir ALL-CHECKS-OK olmali
  python make_figures_en.py    # bildirideki Ingilizce sekiller (make_figures.py: Turkce surum)
  python numbers_manifest.py   # bildirideki her sayi -> results/numbers_manifest.json

Not: Calisma sureleri (saniye) bilgisayara gore degisir; diger tum sayilar ayni cikmalidir.
