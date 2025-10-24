# Polish Power Distribution Station - Conpot Profile

## Opis / Description

Spersonalizowany profil Conpot symulujący polską stację dystrybucji energii elektrycznej. Profil zawiera realistyczne dane operacyjne stacji transformatorowej 110/15kV zlokalizowanej w Katowicach.

**Custom Conpot profile simulating a Polish power distribution station. The profile contains realistic operational data for a 110/15kV transformer station located in Katowice, Poland.**

## Szczegóły urządzenia / Device Details

### Podstawowe informacje / Basic Information
- **Nazwa urządzenia / Device Name**: PLC_Katowice_Centrum_01
- **Model**: Siemens S7-1200 CPU 1214C DC/DC/DC
- **Numer katalogowy / Part Number**: 6ES7 214-1AG40-0XB0
- **Numer seryjny / Serial Number**: PL-KAT-2019-00847
- **Wersja firmware / Firmware Version**: V4.2.3 PL
- **Data uruchomienia / Commissioning Date**: 2019-03-15

### Lokalizacja / Location
- **Organizacja / Organization**: Energetyka Śląska S.A.
- **Dział / Department**: Dział Automatyki i Sterowania
- **Adres / Address**: ul. Energetyczna 47, 40-111 Katowice, Polska
- **Województwo / Region**: Śląskie
- **Współrzędne / Coordinates**: 50.2649°N, 19.0238°E
- **Strefa czasowa / Timezone**: Europe/Warsaw (UTC+1)

### Typ obiektu / Facility Type
- **Typ**: Stacja Transformatorowa 110/15kV
- **Moc znamionowa / Rated Power**: 2x 40 MVA (Transformatory T1, T2)
- **Napięcie znamionowe WN / HV Rated Voltage**: 110 kV
- **Napięcie znamionowe SN / MV Rated Voltage**: 15 kV
- **Sektor / Sector**: Energetyka
- **Kod obiektu / Facility Code**: KAT-ST-001

## Protokoły ICS/SCADA / ICS/SCADA Protocols

### 1. Modbus TCP (Port 502)

#### Mapa rejestrów / Register Map

| Zakres / Range | Typ / Type | Opis / Description |
|----------------|------------|-------------------|
| 0-99 | Holding Registers | Pomiary napięcia / Voltage measurements |
| 100-199 | Holding Registers | Pomiary prądu / Current measurements |
| 200-299 | Holding Registers | Pomiary mocy / Power measurements |
| 300-399 | Holding Registers | Pomiary temperatury / Temperature |
| 400-499 | Holding Registers | Rejestry statusu / Status registers |
| 500-599 | Holding Registers | Rejestry sterowania / Control registers |
| 600-699 | Holding Registers | Alarmy / Alarms |
| 700-799 | Holding Registers | Konfiguracja / Configuration |
| 800-899 | Holding Registers | Statystyki / Statistics |

#### Przykładowe rejestry / Sample Registers

```
Register 0   : Napięcie L1 110kV (Value: 1102 = 110.2 kV)
Register 1   : Napięcie L2 110kV (Value: 1105 = 110.5 kV)
Register 100 : Prąd L1 WN (Value: 4237 = 423.7 A)
Register 200 : Moc czynna całkowita (Value: 673 = 67.3 MW)
Register 230 : Częstotliwość (Value: 5002 = 50.02 Hz)
Register 400 : Status wyłącznika L1 WN (1=zamknięty, 0=otwarty)
```

### 2. SNMP (Port 161/UDP)

#### Community Strings
- **public** (read-only) - standardowy dostęp odczytu
- **private** (read-write) - dostęp do zapisu (słabe hasło dla honeypota)
- **energetyka** (read-only) - dedykowany dla systemu SCADA
- **scada2019** (read-only) - alternatywny dostęp

#### SNMPv3 Users
- **admin** / MD5 auth / DES priv
- **operator** / SHA auth / AES priv
- **noc** / MD5 auth / DES priv

#### Kluczowe OID / Key OIDs

```
System Description: 1.3.6.1.2.1.1.1.0
  "Siemens SIMATIC S7-1200 CPU 1214C, Stacja Transformatorowa Katowice Centrum..."

System Name: 1.3.6.1.2.1.1.5.0
  "PLC_Katowice_Centrum_01"

System Location: 1.3.6.1.2.1.1.6.0
  "Katowice, ul. Energetyczna 47, 40-111 Katowice, województwo śląskie, Polska"

System Contact: 1.3.6.1.2.1.1.4.0
  "NOC Energetyka Śląska S.A., Jan Kowalski, tel: +48 32 123 4567..."
```

#### Siemens Enterprise MIB (1.3.6.1.4.1.4196.*)

```
1.3.6.1.4.1.4196.1.3.1.0  - Napięcie L1 WN (110200 V)
1.3.6.1.4.1.4196.1.3.20.0 - Moc czynna (67300 kW)
1.3.6.1.4.1.4196.1.3.30.0 - Temperatura oleju T1 (67.3°C)
1.3.6.1.4.1.4196.1.4.1.0  - Status wyłącznika L1 (1=zamknięty)
1.3.6.1.4.1.4196.1.5.1.0  - Alarm wysoka temperatura (0=OK)
```

### 3. S7comm (Port 102)

Protokół Siemens S7 do komunikacji PLC.

- **Module Type**: CPU 1214C
- **Serial Number**: S C-X4U304560029
- **Plant Identification**: ENERGETYKA_SLASKA_KAT
- **Copyright**: Original Siemens Equipment

### 4. BACnet (Port 47808/UDP)

Building Automation and Control Networks protocol.

- **Device ID**: 389001
- **Object Name**: PLC_KAT_Centrum
- **Vendor**: Siemens
- **Model**: BACnet-MS/TP

### 5. HTTP/HTTPS (Port 8800)

Web-based HMI interface (mapped to port 80 internally, exposed as 8800).

- **Server Header**: Siemens-SIMATIC/4.2
- **Web Interface**: Siemens SIMATIC HMI
- **Endpoints**:
  - `/` - Strona główna z informacjami o stacji
  - `/login` - Formularz logowania
  - `/api/status` - JSON API z danymi procesu

### 6. IPMI (Port 623/UDP)

Intelligent Platform Management Interface.

- **Manufacturer**: Siemens
- **Product**: SIMATIC Industrial Server
- **Firmware**: 2.10.0

## Dane procesu / Process Data

### Pomiary elektryczne / Electrical Measurements

| Parametr / Parameter | Wartość / Value | Jednostka / Unit |
|---------------------|-----------------|------------------|
| Napięcie L1 WN | 110.2 | kV |
| Napięcie L2 WN | 110.5 | kV |
| Napięcie szyna SN | 15.1 | kV |
| Prąd L1 WN | 423.7 | A |
| Prąd L2 WN | 385.2 | A |
| Moc czynna całkowita | 67.3 | MW |
| Moc bierna całkowita | 12.8 | MVAr |
| Współczynnik mocy | 0.982 | - |
| Częstotliwość | 50.02 | Hz |

### Transformatory / Transformers

**Transformator T1:**
- Obciążenie / Load: 78.5%
- Temperatura oleju / Oil Temperature: 67.3°C
- Temperatura uzwojenia / Winding Temperature: 71.2°C
- Status: Operacyjny / Operational

**Transformator T2:**
- Obciążenie / Load: 71.2%
- Temperatura oleju / Oil Temperature: 64.8°C
- Temperatura uzwojenia / Winding Temperature: 68.5°C
- Status: Operacyjny / Operational

### Wyłączniki / Circuit Breakers

| Wyłącznik / CB | Status | Liczba cykli / Cycles |
|----------------|--------|----------------------|
| Linia 1 WN | Zamknięty / Closed | 234 |
| Linia 2 WN | Zamknięty / Closed | 189 |
| Sprzęgło szyn | Zamknięty / Closed | 56 |
| Wyjście 1 SN | Zamknięty / Closed | 312 |
| Wyjście 2 SN | Zamknięty / Closed | 287 |
| Wyjście 3 SN | Zamknięty / Closed | 245 |

## Kontakt / Contact

- **Administrator**: Jan Kowalski
- **Email**: j.kowalski@energetyka-slaska.pl
- **Telefon / Phone**: +48 32 123 4567
- **NOC Email**: noc@energetyka-slaska.pl
- **Telefon awaryjny / Emergency**: +48 32 123 4500

## Uwagi bezpieczeństwa / Security Notes

⚠️ **UWAGA / WARNING**: To jest profil honeypota zawierający celowo słabe dane uwierzytelniające dla celów badawczych i detekcji zagrożeń.

**This is a honeypot profile containing intentionally weak credentials for research and threat detection purposes.**

### Domyślne uwierzytelnianie / Default Credentials

**NIGDY nie używaj tych danych w prawdziwych systemach produkcyjnych!**
**NEVER use these credentials in real production systems!**

- Username: `admin` / Password: `siemens`
- Username: `operator` / Password: `energetyka2019`
- SNMP Community: `public`, `private`, `energetyka`

## Testowanie / Testing

### Test Modbus

```bash
# Install modbus client
sudo apt-get install python3-pip
pip3 install pymodbus

# Read voltage register (register 0)
python3 -c "from pymodbus.client import ModbusTcpClient; c = ModbusTcpClient('172.20.0.12', port=502); print(c.read_holding_registers(0, 1, slave=1))"
```

### Test SNMP

```bash
# Read system description
snmpget -v2c -c public 172.20.0.12 1.3.6.1.2.1.1.1.0

# Walk system tree
snmpwalk -v2c -c public 172.20.0.12 1.3.6.1.2.1.1

# Read voltage from Siemens MIB
snmpget -v2c -c energetyka 172.20.0.12 1.3.6.1.4.1.4196.1.3.1.0
```

### Test HTTP

```bash
# Get main page
curl http://172.20.0.12:8800/

# Get JSON status
curl http://172.20.0.12:8800/api/status
```

## Integracja z IDS / IDS Integration

Profil jest kompatybilny z regułami Suricata dla protokołów ICS:
- Modbus (reguły w `/configs/suricata/rules/ics-modbus.rules`)
- BACnet (reguły w `/configs/suricata/rules/ics-bacnet.rules`)

The profile is compatible with Suricata rules for ICS protocols defined in the project's IDS configuration.

## Logowanie / Logging

Wszystkie interakcje są logowane do:
- **JSON Log**: `/var/log/conpot/conpot.json`
- **Logstash Pipeline**: `configs/logstash/pipelines/conpot.conf`
- **ClickHouse Table**: `honeypot_events`
- **Grafana Dashboard**: "Conpot ICS/SCADA Activity"

## Autorzy / Authors

Profil stworzony dla projektu HoneyNetV2.
Profile created for HoneyNetV2 project.

## Licencja / License

Ten profil jest częścią projektu HoneyNetV2 i jest udostępniany wyłącznie do celów badawczych w zakresie cyberbezpieczeństwa.

This profile is part of the HoneyNetV2 project and is provided solely for cybersecurity research purposes.
