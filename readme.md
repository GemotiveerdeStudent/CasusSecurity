# Digitale Diefstal – IP Analyse

Een Python-tool voor het monitoren van netwerkverkeer, het detecteren van verdachte verbindingen en het analyseren van firewall- en SSH-logs op IOC’s.

## Features
- Analyse van uitgaand en inkomend verkeer
- Geografische herkomst per IP
- Firewall log interpretatie
- Linux SSH authenticatie-analyse
- IOC feed integratie (Feodo, ThreatFox, enz.)
- CSV/TXT rapportage en filtering

## Installatie
```bash
pip install -r requirements.txt
python main.py