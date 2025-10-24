# AgentUPnP - Implementacja Honeypota UPnP

## Podsumowanie Implementacji

AgentUPnP jest kompletnym honepotem symulującym urządzenie **InternetGatewayDevice** (router IoT z obsługą UPnP). Implementacja obejmuje pełną obsługę protokołów SSDP i SOAP/HTTP, co pozwala na wykrywanie i logowanie prób skanowania oraz nadużyć UPnP.

---

## Architektura

### Komponenty

1. **SSDP Server (UDP/1900)**
   - Nasłuchuje zapytań multicast M-SEARCH
   - Odpowiada informacjami o symulowanym urządzeniu
   - Udostępnia lokalizację pliku XML z opisem urządzenia

2. **HTTP/SOAP Server (TCP/5000)**
   - Serwuje XML z opisem urządzenia (device description)
   - Serwuje XML z opisem usług (service description)
   - Przyjmuje żądania SOAP (AddPortMapping, DeletePortMapping, GetExternalIPAddress)
   - Loguje wszystkie próby manipulacji portami jako ataki

### Symulowane Urządzenie

**Profil urządzenia:**
- **Typ**: `urn:schemas-upnp-org:device:InternetGatewayDevice:1`
- **Producent**: Generic IoT Corp
- **Model**: Smart Router IGD-1000
- **Numer modelu**: IGD-1000-v2
- **Serial**: Dynamicznie generowany UUID

**Usługi UPnP:**
- `WANIPConnection:1` - Usługa mapowania portów WAN IP
- `WANPPPConnection:1` - Usługa mapowania portów WAN PPP

**Akcje SOAP:**
- `AddPortMapping` - Dodawanie przekierowań portów (wykrywane jako atak)
- `DeletePortMapping` - Usuwanie przekierowań portów (wykrywane jako atak)
- `GetExternalIPAddress` - Zwracanie zewnętrznego IP

---

## Pliki Implementacji

### Honeypot
```
honeypots/upnp/
├── upnp_honeypot.py    # Główna implementacja honeypota (666 linii)
├── Dockerfile          # Kontener Docker
└── README.md           # Dokumentacja techniczna
```

### Konfiguracja Docker Compose
- Dodano serwis `upnp` do `docker-compose.yml`
- IP: 172.20.0.14 w sieci honeypot_net
- Porty: 1900/UDP (SSDP), 5000/TCP (HTTP/SOAP)
- Zasoby: 256MB RAM, 0.25 CPU
- Capabilities: NET_BIND_SERVICE

### Pipeline Logstash
```
configs/logstash/pipelines/upnp.conf
```
- Parsowanie logów JSON z honeypota
- Anonimizacja IP z wykorzystaniem SHA256
- GeoIP lookup przed anonimizacją
- Ekstrakcja parametrów SOAP (external_port, internal_port, etc.)
- Zapisywanie do ClickHouse (honeypot_events, upnp_attacks)

### Schemat ClickHouse
- Dodano `upnp` do enum honeypot_type
- Utworzono tabelę `upnp_attacks` z polami:
  - attack_id, source_ip_hash, attack_type
  - soap_action, upnp_action
  - external_port, internal_port, internal_client, protocol
  - attack_details (JSON)

### Testy
```
tests/upnp/
├── test_upnp.sh    # Bash test suite (9 testów)
└── test_upnp.py    # Python test suite (8 testów)
```

---

## Scenariusze Ataków i Detekcja

### 1. Skanowanie SSDP (MITRE T1046 - Network Service Discovery)

**Atak:**
```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
ST: ssdp:all
```

**Odpowiedź honeypota:**
- Zwraca informacje o urządzeniu IGD
- Udostępnia URL do pliku description.xml
- Loguje zapytanie jako `ssdp_msearch`

**Detekcja Suricata:**
- **SID 2000016**: "IoT UPnP SSDP scan - M-SEARCH discovery"
- Threshold: 20 zapytań w ciągu 60 sekund z tego samego źródła

### 2. Nadużycie AddPortMapping (MITRE T1557 - Adversary-in-the-Middle)

**Atak:**
```xml
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
  <NewExternalPort>8080</NewExternalPort>
  <NewInternalPort>80</NewInternalPort>
  <NewInternalClient>192.168.1.100</NewInternalClient>
  <NewProtocol>TCP</NewProtocol>
</u:AddPortMapping>
```

**Odpowiedź honeypota:**
- Zwraca pozytywną odpowiedź SOAP (bez wykonywania akcji)
- Loguje jako `attack_detected` z typem "AddPortMapping abuse"
- Zapisuje wszystkie parametry żądania

**Detekcja Suricata:**
- **SID 2000017**: "IoT UPnP AddPortMapping abuse attempt"
- Wykrywa ciągi "AddPortMapping" i "NewExternalPort" w ruchu TCP na portach 1900/5000

---

## Format Logów

### Przykład logu SSDP M-SEARCH:
```json
{
  "timestamp": "2025-10-24T12:00:00.000000Z",
  "honeypot_type": "upnp",
  "event_type": "ssdp_msearch",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "172.20.0.14",
  "dest_port": 1900,
  "protocol": "udp",
  "search_target": "ssdp:all",
  "mx": "3"
}
```

### Przykład logu ataku SOAP:
```json
{
  "timestamp": "2025-10-24T12:01:00.000000Z",
  "honeypot_type": "upnp",
  "event_type": "attack_detected",
  "src_ip": "192.168.1.100",
  "src_port": 54322,
  "dest_ip": "172.20.0.14",
  "dest_port": 5000,
  "protocol": "tcp",
  "soap_action": "AddPortMapping",
  "action": "AddPortMapping",
  "params": {
    "NewExternalPort": "8080",
    "NewInternalPort": "80",
    "NewInternalClient": "192.168.1.100",
    "NewProtocol": "TCP"
  },
  "attack_detected": true,
  "attack_type": "AddPortMapping abuse"
}
```

---

## Testowanie

### Uruchomienie testów

**Bash test suite:**
```bash
cd tests/upnp
./test_upnp.sh
```

**Python test suite:**
```bash
cd tests/upnp
python3 test_upnp.py
```

### Testy obejmują:

1. **SSDP M-SEARCH Discovery** - Weryfikacja odpowiedzi na zapytania SSDP
2. **Device Description XML** - Pobranie i parsowanie opisu urządzenia
3. **Service Description XML** - Weryfikacja dostępności akcji AddPortMapping
4. **SOAP AddPortMapping** - Symulacja ataku mapowania portów
5. **SOAP DeletePortMapping** - Symulacja usuwania mapowania
6. **SOAP GetExternalIPAddress** - Test zwracania IP
7. **Presentation URL** - Weryfikacja interfejsu webowego
8. **SSDP Scan Threshold** - 25 żądań dla triggera Suricaty
9. **Log Verification** - Sprawdzanie poprawności logowania

### Oczekiwane rezultaty:

- Wszystkie 8-9 testów powinny zakończyć się sukcesem
- Suricata powinna wygenerować alerty:
  - SID 2000016 po 20+ zapytaniach M-SEARCH
  - SID 2000017 po żądaniu AddPortMapping
- Logi honeypota w `data/upnp/upnp.json` powinny zawierać:
  - Zdarzenia `ssdp_msearch`
  - Zdarzenia `soap_request`
  - Zdarzenia `attack_detected`

---

## Integracja z HoneyNetV2

### Deploy

```bash
# Build i uruchomienie całego stacku (w tym UPnP)
docker-compose up -d

# Tylko UPnP
docker-compose up -d upnp

# Sprawdzenie statusu
docker-compose ps upnp

# Logi
docker-compose logs -f upnp
```

### Monitoring

**Grafana:**
- Logi UPnP będą dostępne w dashboardach po zintegrowaniu z ClickHouse
- Query example: `SELECT * FROM honeypot_events WHERE honeypot_type = 'upnp'`
- Attack analysis: `SELECT * FROM upnp_attacks ORDER BY timestamp DESC`

**Suricata Alerts:**
```bash
# Sprawdzenie alertów UPnP
tail -f data/suricata/fast.log | grep -E "(2000016|2000017)"

# EVE JSON
jq 'select(.alert.signature_id == 2000016 or .alert.signature_id == 2000017)' data/suricata/eve.json
```

**Honeypot Logs:**
```bash
# Real-time monitoring
tail -f data/upnp/upnp.json | jq .

# Attack statistics
jq 'select(.attack_detected == true) | .attack_type' data/upnp/upnp.json | sort | uniq -c

# SSDP scan attempts
jq 'select(.event_type == "ssdp_msearch") | .src_ip' data/upnp/upnp.json | sort | uniq -c
```

---

## Bezpieczeństwo

**Izolacja:**
- Kontener działa w sieci DMZ (honeypot_net) bez dostępu do Internetu
- Brak możliwości outbound connections

**Privileges:**
- Uruchamiane jako user `upnp` (uid 1000)
- Tylko capability NET_BIND_SERVICE
- DROP ALL innych capabilities

**Resource Limits:**
- RAM: 256MB
- CPU: 0.25 core
- Log rotation: max 10MB x 3 pliki

---

## Narzędzia Atakujących

Honeypot został zaprojektowany do wykrywania popularnych narzędzi UPnP:

- **upnpc** (MiniUPnP client) - CLI do mapowania portów
- **Miranda** - Narzędzie do interrogacji usług UPnP
- **Evil SSDP** - SSDP spoofing i MITM
- **Nmap** - Skrypty upnp-info, broadcast-upnp-info
- **Metasploit** - Moduły upnp_ssdp_amplification, upnp_msearch

---

## Odpowiedzi na Pytania z Zadania

### Q: Jakie atrybuty urządzenia UPnP powinny zostać zasymulowane?

**A:** Zaimplementowano następujący profil:
- **Device Type**: InternetGatewayDevice:1 (najbardziej atrakcyjny cel)
- **Manufacturer**: Generic IoT Corp
- **Model**: Smart Router IGD-1000
- **Friendly Name**: Generic Smart Router IGD-1000
- **Services**: WANIPConnection, WANPPPConnection

To sprawia, że honeypot wygląda jak typowy router IoT z obsługą UPnP, który jest głównym celem ataków.

### Q: Czy port 5000/TCP ma być na pewno wystawiony, czy wystarczy symulacja samego SSDP?

**A:** **TAK, port 5000/TCP musi być wystawiony**. Powody:
1. Suricata wykrywa AddPortMapping na portach [1900, 5000] (SID 2000017)
2. Standardowy UPnP wymaga HTTP dla:
   - Plików XML z opisem urządzenia (description.xml)
   - Plików XML z opisem usług (WANIPConnection.xml)
   - Endpointów SOAP dla akcji kontrolnych (/ctl/IPConn)
3. Bez portu 5000 honeypot odpowiadałby tylko na M-SEARCH, ale nie pozwalałby na faktyczne testy exploitów

---

## Statystyki Implementacji

- **Plików utworzonych**: 7
- **Linii kodu Python**: 666 (upnp_honeypot.py)
- **Linii kodu testowego**: 450+ (bash + python)
- **Konfiguracji**: 4 (docker-compose, logstash, clickhouse, pipelines.yml)
- **Wspieranych protokołów**: SSDP (UDP), HTTP (TCP), SOAP (TCP)
- **Wykrywanych ataków**: 2+ typy (AddPortMapping, DeletePortMapping)
- **Reguł Suricata**: 2 (SID 2000016, 2000017)

---

## Referencje

- [UPnP Device Architecture v1.0](http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf)
- [UPnP IGD v1.0 Specification](http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v1-Device.pdf)
- [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)

---

## Status

✅ **COMPLETED** - Implementacja w pełni funkcjonalna i gotowa do deploy

Wszystkie komponenty zostały zaimplementowane zgodnie z wymaganiami:
- ✅ SSDP listener (UDP/1900)
- ✅ SOAP HTTP server (TCP/5000)
- ✅ Device description XML
- ✅ Obsługa AddPortMapping/DeletePortMapping
- ✅ Logowanie w formacie JSON
- ✅ Integracja z docker-compose
- ✅ Pipeline Logstash
- ✅ Schemat ClickHouse
- ✅ Testy automatyczne
- ✅ Dokumentacja
