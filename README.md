# Blauring Baden — Ausgabenverwaltung

Eine kleine Web-App zur Verwaltung von Vereinsausgaben für den Blauring Baden.

## Funktionen

- **Login** mit drei Rollen: Leiter, Kassier, Admin
- **Leiter:** Ausgaben erfassen (mit Foto/Quittung), eigene Ausgaben einsehen
- **Kassier:**
  - Alle Belege einsehen, Belegbilder öffnen
  - Einzelne Buchungen löschen
  - Zahlung auszahlen / rückgängig machen
  - Übersicht nach **Anlass** (mit Budget, Rest und Auslastung)
  - Übersicht nach **Leiter** (offen / abgerechnet / Total)
  - Buchungsnummer verwalten
  - CSV-Export
- **Stammdaten:** Leiter und Anlässe pflegen, Budget pro Anlass

## Technik

- **Backend:** Flask + waitress (Produktions-WSGI), SQLite
- **Frontend:** reines HTML/CSS/JavaScript (kein Framework)
- **Betrieb:** systemd-Dienst, optional hinter Apache als Reverse Proxy

## Buchungsnummern

Format **`JJ-XXXX`** (Zehner + Einer des Jahres, dann fortlaufend vierstellig), z. B. `26-0001`.
Hochgeladene Belege erhalten den gleichen Namen wie die Buchungsnummer (z. B. `26-0001.jpg`).

## Sicherheit

- Passwörter als PBKDF2-SHA256 (260 000 Iterationen), automatische Migration alter Hashes
- Login-Rate-Limit (8 Versuche / 5 Minuten, danach 5 Minuten Sperre)
- Beleg-Downloads nur für angemeldete Benutzer
- Secret Key wird lokal in `state/blauring_secret.key` erzeugt (nicht im Repo)

## Setup

```bash
pip install -r requirements.txt
python3 blauring_app.py          # Entwicklung
```

Produktiv über systemd (`blauring.service`) mit waitress; Beispiel-Apache-Config in
`apache-blauring.conf`.

## Standard-Zugangsdaten (Demo)

| Benutzer | Passwort | Rolle    |
|----------|----------|----------|
| `paula`  | `demo123`| Leiter   |
| `marc`   | `demo123`| Leiter   |
| `kassier`| `demo123`| Kassier  |

> Für den produktiven Einsatz unbedingt ändern.
