# Przewodnik wdrożenia polskiego profilu Conpot / Polish Conpot Profile Deployment Guide

## Spis treści / Table of Contents

1. [Wprowadzenie / Introduction](#wprowadzenie--introduction)
2. [Architektura profilu / Profile Architecture](#architektura-profilu--profile-architecture)
3. [Wdrożenie / Deployment](#wdrożenie--deployment)
4. [Testowanie / Testing](#testowanie--testing)
5. [Weryfikacja IDS / IDS Verification](#weryfikacja-ids--ids-verification)
6. [Monitorowanie / Monitoring](#monitorowanie--monitoring)
7. [Rozwiązywanie problemów / Troubleshooting](#rozwiązywanie-problemów--troubleshooting)

---

## Wprowadzenie / Introduction

### Cel / Purpose

Niniejszy dokument opisuje pełny proces wdrożenia i weryfikacji spersonalizowanego profilu Conpot dla HoneyNetV2. Profil symuluje polską stację dystrybucji energii elektrycznej 110/15kV zlokalizowaną w Katowicach.

**This document describes the complete deployment and verification process for a customized Conpot profile for HoneyNetV2. The profile simulates a Polish 110/15kV power distribution station located in Katowice.**

### Cechy profilu / Profile Features

✅ **Polska lokalizacja** - Katowice, województwo śląskie
✅ **Realistyczne dane operacyjne** - Pomiary napięcia, prądu, mocy
✅ **Protokoły ICS/SCADA** - Modbus TCP, SNMP, S7comm, BACnet, HTTP
✅ **Polskojęzyczne opisy** - Nazwy urządzeń, komunikaty, interfejs web
✅ **Kompatybilność z IDS** - Działa z istniejącymi regułami Suricata
✅ **Szczegółowe logowanie** - Integracja z Logstash i ClickHouse

---

## Architektura profilu / Profile Architecture

### Struktura plików / File Structure

```
configs/conpot/templates/polish_power_station/
├── README.md                    # Dokumentacja profilu
├── conpot.cfg                   # Główna konfiguracja
├── template.xml                 # Metadane urządzenia
├── modbus/
│   └── modbus.xml              # Mapa rejestrów Modbus TCP
├── snmp/
│   └── snmp.xml                # Definicje MIB SNMP
└── http/
    └── http.xml                # Interfejs web HMI
```

### Urządzenie symulowane / Simulated Device

- **Model**: Siemens S7-1200 CPU 1214C DC/DC/DC
- **Numer katalogowy**: 6ES7 214-1AG40-0XB0
- **Typ obiektu**: Stacja Transformatorowa 110/15kV
- **Organizacja**: Energetyka Śląska S.A.
- **Lokalizacja**: Katowice, ul. Energetyczna 47

### Protokoły i porty / Protocols and Ports

| Protokół | Port | Opis |
|----------|------|------|
| Modbus TCP | 502 | Industrial automation protocol |
| SNMP | 161/UDP | Network management |
| S7comm | 102 | Siemens S7 PLC communication |
| BACnet | 47808/UDP | Building automation |
| HTTP | 8800 | Web-based HMI interface |
| IPMI | 623/UDP | Platform management |

---

## Wdrożenie / Deployment

### Krok 1: Weryfikacja plików / Verify Files

Sprawdź, czy wszystkie pliki profilu zostały utworzone:

```bash
ls -la /home/user/HoneyNetV2/configs/conpot/templates/polish_power_station/
```

Powinieneś zobaczyć:
```
conpot.cfg
template.xml
README.md
modbus/modbus.xml
snmp/snmp.xml
http/http.xml
```

### Krok 2: Weryfikacja konfiguracji Docker / Verify Docker Configuration

Sprawdź konfigurację w `docker-compose.yml`:

```bash
grep -A 25 "# Conpot" /home/user/HoneyNetV2/docker-compose.yml
```

Upewnij się, że:
- `CONPOT_TEMPLATE=polish_power_station`
- Volume z szablonem jest zamontowany
- Porty są prawidłowo zmapowane

### Krok 3: Uruchomienie kontenera / Start Container

```bash
# Z katalogu głównego projektu
cd /home/user/HoneyNetV2

# Uruchom tylko Conpot (dla testów)
docker-compose up -d conpot

# LUB uruchom cały stack
docker-compose up -d
```

### Krok 4: Weryfikacja logów / Verify Logs

```bash
# Sprawdź logi kontenera
docker-compose logs conpot

# Szukaj potwierdzenia załadowania profilu
docker-compose logs conpot | grep -i "polish_power_station\|template"
```

Oczekiwany output powinien zawierać:
```
Loading template: polish_power_station
Template loaded successfully
Modbus server started on 0.0.0.0:502
SNMP server started on 0.0.0.0:161
```

### Krok 5: Weryfikacja portów / Verify Ports

```bash
# Sprawdź nasłuchujące porty
docker-compose exec conpot netstat -tuln | grep -E '502|161|102|8800'
```

---

## Testowanie / Testing

### Test 1: Modbus TCP

#### Przygotowanie / Preparation

Zainstaluj narzędzia klienckie:

```bash
# Python Modbus client
pip3 install pymodbus

# LUB użyj modpoll (komercyjne, ale dostępna wersja demo)
# wget https://www.modbusdriver.com/downloads/modpoll.tgz
```

#### Test odczytu rejestrów / Register Read Test

```python
#!/usr/bin/env python3
"""Test Modbus connectivity to Polish Power Station profile"""

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

def test_modbus_connection():
    """Test basic Modbus connectivity"""
    client = ModbusTcpClient('172.20.0.12', port=502)

    try:
        if client.connect():
            print("✓ Połączono z Modbus TCP")

            # Test 1: Read voltage L1 (register 0)
            result = client.read_holding_registers(0, 1, slave=1)
            if not result.isError():
                voltage_l1 = result.registers[0] / 10.0
                print(f"✓ Napięcie L1 WN: {voltage_l1} kV")

            # Test 2: Read voltage L2 (register 1)
            result = client.read_holding_registers(1, 1, slave=1)
            if not result.isError():
                voltage_l2 = result.registers[0] / 10.0
                print(f"✓ Napięcie L2 WN: {voltage_l2} kV")

            # Test 3: Read active power (register 200)
            result = client.read_holding_registers(200, 1, slave=1)
            if not result.isError():
                power = result.registers[0] / 10.0
                print(f"✓ Moc czynna: {power} MW")

            # Test 4: Read frequency (register 230)
            result = client.read_holding_registers(230, 1, slave=1)
            if not result.isError():
                freq = result.registers[0] / 100.0
                print(f"✓ Częstotliwość: {freq} Hz")

            # Test 5: Read multiple registers (voltage measurements)
            result = client.read_holding_registers(0, 8, slave=1)
            if not result.isError():
                print(f"✓ Odczytano {len(result.registers)} rejestrów pomiarowych")

            print("\n✅ Wszystkie testy Modbus zakończone pomyślnie")

        else:
            print("✗ Nie można połączyć się z serwerem Modbus")

    except ModbusException as e:
        print(f"✗ Błąd Modbus: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    test_modbus_connection()
```

Uruchom test:
```bash
python3 test_modbus.py
```

#### Oczekiwane wyniki / Expected Results

```
✓ Połączono z Modbus TCP
✓ Napięcie L1 WN: 110.2 kV
✓ Napięcie L2 WN: 110.5 kV
✓ Moc czynna: 67.3 MW
✓ Częstotliwość: 50.02 Hz
✓ Odczytano 8 rejestrów pomiarowych

✅ Wszystkie testy Modbus zakończone pomyślnie
```

### Test 2: SNMP

#### Test podstawowy / Basic Test

```bash
# Wymagane narzędzie snmp
sudo apt-get install -y snmp snmp-mibs-downloader

# Test 1: System Description
snmpget -v2c -c public 172.20.0.12 1.3.6.1.2.1.1.1.0

# Test 2: System Name
snmpget -v2c -c public 172.20.0.12 1.3.6.1.2.1.1.5.0

# Test 3: System Location
snmpget -v2c -c public 172.20.0.12 1.3.6.1.2.1.1.6.0

# Test 4: System Contact
snmpget -v2c -c public 172.20.0.12 1.3.6.1.2.1.1.4.0
```

#### Oczekiwane wyniki / Expected Results

```
SNMPv2-MIB::sysDescr.0 = STRING: Siemens SIMATIC S7-1200 CPU 1214C, Stacja Transformatorowa Katowice Centrum...
SNMPv2-MIB::sysName.0 = STRING: PLC_Katowice_Centrum_01
SNMPv2-MIB::sysLocation.0 = STRING: Katowice, ul. Energetyczna 47, 40-111 Katowice, województwo śląskie, Polska
SNMPv2-MIB::sysContact.0 = STRING: NOC Energetyka Śląska S.A., Jan Kowalski, tel: +48 32 123 4567...
```

#### Test Siemens Enterprise MIB

```bash
# Odczyt napięcia z prywatnego MIB Siemens
snmpget -v2c -c energetyka 172.20.0.12 1.3.6.1.4.1.4196.1.3.1.0

# Odczyt mocy czynnej
snmpget -v2c -c energetyka 172.20.0.12 1.3.6.1.4.1.4196.1.3.20.0

# Odczyt temperatury oleju T1
snmpget -v2c -c energetyka 172.20.0.12 1.3.6.1.4.1.4196.1.3.30.0
```

#### Test SNMPv3

```bash
snmpget -v3 -u admin -l authPriv -a MD5 -A adminpass123 -x DES -X privkey123 \
  172.20.0.12 1.3.6.1.2.1.1.5.0
```

### Test 3: HTTP Interface

```bash
# Test 1: Strona główna
curl -s http://172.20.0.12:8800/ | grep -o '<title>.*</title>'

# Test 2: JSON API
curl -s http://172.20.0.12:8800/api/status | jq .

# Test 3: Headers
curl -I http://172.20.0.12:8800/
```

#### Oczekiwane wyniki / Expected Results

```bash
# Test 1
<title>Siemens SIMATIC S7-1200 - Stacja Transformatorowa Katowice</title>

# Test 2 (JSON output)
{
  "device": "PLC_Katowice_Centrum_01",
  "status": "online",
  "system_health": "OK",
  "timestamp": "2024-10-24T12:30:00+01:00",
  "location": "Katowice, Polska",
  "measurements": {
    "voltage_l1_hv": 110.2,
    ...
  }
}

# Test 3
Server: Siemens-SIMATIC/4.2
X-Powered-By: WinCC SCADA
X-Device-Name: PLC_Katowice_Centrum_01
```

### Test 4: S7comm Protocol

S7comm wymaga specjalistycznych narzędzi:

```bash
# Użyj snap7 lub python-snap7
pip3 install python-snap7

# Przykładowy test połączenia
python3 << 'EOF'
import snap7
from snap7.util import *

client = snap7.client.Client()
try:
    client.connect('172.20.0.12', 0, 1)
    print(f"✓ Połączono z PLC S7")
    print(f"  CPU: {client.get_cpu_info()}")
    print(f"  Stan: {client.get_cpu_state()}")
except Exception as e:
    print(f"✗ Błąd: {e}")
finally:
    client.disconnect()
EOF
```

---

## Weryfikacja IDS / IDS Verification

### Kompatybilność reguł / Rule Compatibility

Profil polski jest w pełni kompatybilny z istniejącymi regułami Suricata, ponieważ:

1. **Reguły bazują na protokołach, nie na danych** - Suricata wykrywa wzorce w ruchu sieciowym
2. **Function codes są uniwersalne** - Modbus function code 03 (Read) jest taki sam dla wszystkich urządzeń
3. **Struktura pakietów nie zmienia się** - Tylko wartości i nazwy są polskie

### Reguły Modbus (honeypot-custom.rules)

```
SID 1000011: HONEYPOT Modbus Unauthorized Read
  - Wykrywa funkcję 03 (Read Holding Registers)
  - Działa niezależnie od wartości w rejestrach

SID 1000012: HONEYPOT Modbus Write Command
  - Wykrywa funkcję 06 (Write Single Register)
  - Wykrywa próby modyfikacji konfiguracji
```

### Test IDS

#### 1. Generuj ruch testowy

```bash
# Wykonaj odczyty Modbus (powinny wyzwolić SID 1000011)
python3 test_modbus.py

# Wykonaj zapytania SNMP (powinny wyzwolić SID 1000013 jeśli używasz "public")
snmpwalk -v2c -c public 172.20.0.12 1.3.6.1.2.1.1
```

#### 2. Sprawdź alerty Suricata

```bash
# Czytaj logi Suricata
tail -f /home/user/HoneyNetV2/data/suricata/eve.json | jq 'select(.event_type=="alert")'

# LUB wyszukaj konkretne SID
grep "1000011\|1000012\|1000013" /home/user/HoneyNetV2/data/suricata/eve.json | jq .
```

#### 3. Weryfikacja w Grafana

1. Otwórz Grafana: http://localhost:3000
2. Przejdź do dashboard "IDS Alerts"
3. Filtruj po: `alert.signature_id IN (1000011, 1000012, 1000013)`
4. Sprawdź czy alerty zawierają:
   - Source IP atakującego
   - Destination IP: 172.20.0.12 (Conpot)
   - Prawidłowy opis alertu

### Dodatkowe reguły (opcjonalne)

Możesz dodać specyficzne reguły dla polskiego profilu:

```bash
cat >> /home/user/HoneyNetV2/configs/suricata/rules/local.rules << 'EOF'
# Polish Power Station specific rules
alert tcp any any -> 172.20.0.12 502 (msg:"HONEYPOT Polish Power Station Modbus Access"; flow:to_server,established; classtype:attempted-recon; sid:2000001; rev:1;)

alert udp any any -> 172.20.0.12 161 (msg:"HONEYPOT Polish Power Station SNMP Query"; flow:to_server; classtype:attempted-recon; sid:2000002; rev:1;)

alert tcp any any -> 172.20.0.12 8800 (msg:"HONEYPOT Polish Power Station Web Access"; flow:to_server,established; classtype:attempted-recon; sid:2000003; rev:1;)
EOF

# Przeładuj reguły Suricata
docker-compose restart suricata
```

---

## Monitorowanie / Monitoring

### Logi Conpot

```bash
# Real-time log monitoring
tail -f /home/user/HoneyNetV2/data/conpot/conpot.json | jq .

# Ostatnie 10 zdarzeń
tail -10 /home/user/HoneyNetV2/data/conpot/conpot.json | jq .

# Filtruj po typie protokołu
jq 'select(.data_type=="modbus")' /home/user/HoneyNetV2/data/conpot/conpot.json

# Statystyki IP atakujących
jq -r '.remote[0]' /home/user/HoneyNetV2/data/conpot/conpot.json | sort | uniq -c | sort -rn
```

### Grafana Dashboards

#### Dashboard: "Conpot ICS/SCADA Activity"

Metryki do monitorowania:
- Liczba połączeń na protokół (Modbus, SNMP, S7comm)
- Top źródłowe IP
- Geolokalizacja ataków
- Timeline aktywności
- Najczęściej odczytywane rejestry Modbus

#### Przykładowe zapytania ClickHouse

```sql
-- Top 10 atakujących
SELECT
    source_ip_hash,
    source_ip_country,
    COUNT(*) as event_count
FROM honeynet.honeypot_events
WHERE honeypot_type = 'conpot'
  AND timestamp > now() - INTERVAL 24 HOUR
GROUP BY source_ip_hash, source_ip_country
ORDER BY event_count DESC
LIMIT 10;

-- Aktywność per protokół
SELECT
    protocol,
    COUNT(*) as count
FROM honeynet.honeypot_events
WHERE honeypot_type = 'conpot'
  AND timestamp > now() - INTERVAL 7 DAY
GROUP BY protocol
ORDER BY count DESC;

-- Timeline ataków (per godzina)
SELECT
    toStartOfHour(timestamp) as hour,
    COUNT(*) as events
FROM honeynet.honeypot_events
WHERE honeypot_type = 'conpot'
  AND timestamp > now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour;
```

---

## Rozwiązywanie problemów / Troubleshooting

### Problem 1: Conpot nie startuje

**Symptom**: Kontener restartuje się w pętli

```bash
# Sprawdź logi
docker-compose logs conpot

# Szukaj błędów w konfiguracji
docker-compose logs conpot | grep -i "error\|fail\|exception"
```

**Rozwiązanie**:
- Sprawdź składnię XML w plikach template.xml, modbus.xml, snmp.xml
- Upewnij się że volume jest poprawnie zamontowany
- Sprawdź uprawnienia do plików: `chmod -R 644 configs/conpot/`

### Problem 2: Brak połączenia z Modbus

**Symptom**: Timeout przy próbie połączenia

```bash
# Test conectivity
nc -zv 172.20.0.12 502
```

**Rozwiązanie**:
- Sprawdź czy kontener działa: `docker-compose ps conpot`
- Sprawdź mapowanie portów: `docker-compose port conpot 502`
- Sprawdź firewall: `sudo iptables -L -n | grep 502`
- Sprawdź czy port jest nasłuchujący w kontenerze:
  ```bash
  docker-compose exec conpot netstat -tuln | grep 502
  ```

### Problem 3: SNMP zwraca timeout

**Symptom**: snmpget nie otrzymuje odpowiedzi

```bash
snmpget -v2c -c public -t 5 -r 3 172.20.0.12 1.3.6.1.2.1.1.1.0
```

**Rozwiązanie**:
- Sprawdź czy używasz poprawnego community string
- Sprawdź port UDP 161: `nc -zuv 172.20.0.12 161`
- Sprawdź logi Conpot: `docker-compose logs conpot | grep -i snmp`

### Problem 4: IDS nie generuje alertów

**Symptom**: Brak alertów w Suricata mimo ruchu

```bash
# Sprawdź czy Suricata działa
docker-compose ps suricata

# Sprawdź czy reguły są załadowane
docker-compose exec suricata suricatasc -c "ruleset-stats" | jq .
```

**Rozwiązanie**:
- Sprawdź czy reguły są włączone w suricata.yaml
- Zrestartuj Suricata: `docker-compose restart suricata`
- Sprawdź interfejs sieciowy: Suricata musi nasłuchiwać na właściwym interfejsie
- Test lokalny:
  ```bash
  # Generuj prosty alert testowy
  curl "http://172.20.0.12:8800/test?cmd=whoami"  # Powinien wyzwolić web attack rule
  ```

### Problem 5: Brak danych w Grafana

**Symptom**: Puste wykresy w dashboardzie Conpot

**Rozwiązanie**:
1. Sprawdź czy Logstash przetwarza logi:
   ```bash
   docker-compose logs logstash | grep conpot
   ```

2. Sprawdź czy dane trafiają do ClickHouse:
   ```sql
   SELECT COUNT(*) FROM honeynet.honeypot_events WHERE honeypot_type = 'conpot';
   ```

3. Sprawdź konfigurację datasource w Grafana:
   - Settings → Data Sources → ClickHouse
   - Test connection

4. Sprawdź czas w zapytaniach (timezone):
   - Grafana używa UTC
   - Conpot loguje w Europe/Warsaw (UTC+1)

---

## Podsumowanie / Summary

### Checklist wdrożenia / Deployment Checklist

- [ ] Pliki profilu utworzone w `configs/conpot/templates/polish_power_station/`
- [ ] docker-compose.yml zaktualizowany z `CONPOT_TEMPLATE=polish_power_station`
- [ ] Kontener Conpot uruchomiony bez błędów
- [ ] Test Modbus: odczyt rejestrów działa
- [ ] Test SNMP: zapytania zwracają polskie dane
- [ ] Test HTTP: strona główna wyświetla polską stację
- [ ] Reguły IDS generują alerty dla ruchu Modbus/SNMP
- [ ] Logi Conpot trafiają do ClickHouse
- [ ] Dashboard Grafana wyświetla dane z Conpot

### Następne kroki / Next Steps

1. **Monitorowanie produkcyjne** - Obserwuj rzeczywiste ataki przez minimum 7 dni
2. **Analiza wzorców** - Zidentyfikuj typowe wzorce ataków na ICS
3. **Tuning IDS** - Dostosuj reguły Suricata na podstawie fałszywych pozytywów
4. **Dokumentacja ataków** - Twórz raporty z interesujących incydentów
5. **Rozszerzenie profilu** - Rozważ dodanie kolejnych polskich profili (np. oczyszczalnia, fabryka)

### Kontakt i wsparcie / Contact and Support

Dla pytań technicznych dotyczących profilu, otwórz issue w repozytorium GitHub projektu HoneyNetV2.

---

**Dokument utworzony**: 2024-10-24
**Wersja profilu**: 1.0
**Projekt**: HoneyNetV2 - AgentConpotProfile
