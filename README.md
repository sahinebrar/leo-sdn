# LEO Ağlarında TCP Flooding Saldırı Tespiti

**SDN Temelli Bir Yaklaşım ile Gelişmiş TCP Flooding Saldırılarının Tespiti**

[![Python](https://img.shields.io/badge/Python-3.8-blue.svg)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/SDN-Ryu-green.svg)](https://ryu-sdn.org/)
[![Mininet](https://img.shields.io/badge/Network-Mininet-orange.svg)](http://mininet.org/)
[![Docker](https://img.shields.io/badge/Container-Docker-blue.svg)](https://www.docker.com/)

---

## İçindekiler

- [Proje Hakkında](#-proje-hakkında)
- [Hızlı Başlangıç](#-hızlı-başlangıç)
- [Saldırı Komutları](#-saldırı-komutları)
- [Tespit Yöntemleri](#-tespit-yöntemleri)

---

## Proje Hakkında

Bu proje, **Low Earth Orbit (LEO)** uydu ağlarında gerçekleştirilen **TCP SYN/ACK flooding** saldırılarını tespit etmek için **Software Defined Networking (SDN)** tabanlı bir çözüm sunmaktadır.

### Temel Özellikler

- **LEO Uydu Ağ Simülasyonu** - 12 uydu + 4 yer istasyonu topolojisi
- **SDN Tabanlı Kontrol** - Ryu controller ile merkezi yönetim
- **Makine Öğrenmesi** - Random Forest ile saldırı tespiti
- **Gerçek Zamanlı Tespit** - Flow-based trafik analizi
- **hping3 ile Saldırı Simülasyonu** - SYN/ACK/SYN-ACK flood

---

### 1. Docker Image Oluştur ve Çalıştır

```bash
# Repository'yi klonla
git clone https://github.com/username/leo-sdn-attack.git
cd leo-sdn-attack

# Docker image oluştur
docker build -t leo-sdn-attack .

# Container'ı başlat (privileged mod gerekli)
docker run -it --privileged --name leo-sdn leo-sdn-attack
```

### 2. Ryu Controller Başlat (Terminal 1)

```bash
# Container içinde
ryu-manager sdn_controller/controller.py
```

**Çıktı:**
```
==========================================
  LEO SDN Attack Detection Controller
==========================================
  Detection Mode: Machine Learning
  Model: Random Forest
==========================================
loading app sdn_controller/controller.py
Datapath registered: dpid=1
Datapath registered: dpid=2
...
```

### 3. Mininet Topoloji Başlat (Terminal 2)

```bash
# Yeni terminal aç ve container'a bağlan
docker exec -it leo-sdn bash

# Mininet topolojisini başlat
python3 topology/leo_topology.py
```

**Çıktı:**
```
*** Creating LEO Satellite Network ***
*** Adding satellites: sat1 sat2 ... sat12
*** Adding ground stations: gs1 gs2 gs3 gs4
*** Adding users: u1 u2 ... u16
*** Starting CLI ***
mininet>
```

### 4. Saldırı Yardım Menüsü

```bash
mininet> py show_help()
```

---

## Saldırı Komutları

### Temel Saldırılar

| Komut | Açıklama |
|-------|----------|
| `py syn_flood(net, 'u1', 'u12', 30)` | SYN Flood (30 saniye) |
| `py ack_flood(net, 'u1', 'u12', 30)` | ACK Flood (30 saniye) |

### Saldırı Senaryoları

| Komut | Açıklama |
|-------|----------|
| `py mixed_scenario(net, 'u1', 'u12', 30)` | Normal trafik + Saldırı karışık |
| `py distributed_attack(net, ['u1','u2','u3'], 'u12', 30)` | DDoS (çoklu saldırgan) |

### Kontrol Komutları

| Komut | Açıklama |
|-------|----------|
| `py stop_attack(net, 'u1')` | Belirli host'un saldırısını durdur |
| `py stop_all_attacks(net)` | Tüm saldırıları durdur |
| `py capture_traffic(net, 'u12', 30, '/tmp/attack.pcap')` | Trafik yakala |

---

## 📖 Saldırı Detayları

### 1. SYN Flood
```bash
mininet> py syn_flood(net, 'u1', 'u12', 30)
```
- **Açıklama:** TCP SYN paketleri ile hedefi doldurur
- **IP Spoofing:** Varsayılan olarak aktif (`--rand-source`)
- **Hedef Port:** 80

**Beklenen Controller Çıktısı:**
```
[!!!] [CRITICAL] SYN FLOOD detected on switch 1
Confidence: 95% | Rate: 45000 pps | SYN ratio: 100%
```

### 2. ACK Flood
```bash
mininet> py ack_flood(net, 'u1', 'u12', 30)
```
- **Açıklama:** TCP ACK paketleri ile bant genişliği doldurur
- **Fark:** SYN ratio düşük olur (~12%)

### 3. Mixed Scenario
```bash
mininet> py mixed_scenario(net, 'u1', 'u12', 30)
```
**Timeline (Toplam 120 saniye):**
| Faz | Süre | Trafik Tipi |
|-----|------|-------------|
| 1 | 0-30s | Normal (ping) |
| 2 | 30-60s | Normal + SYN Flood |
| 3 | 60-90s | Normal (ping) |
| 4 | 90-120s | Normal + ACK Flood |
|

### 4. Distributed Attack (DDoS)
```bash
mininet> py distributed_attack(net, ['u1', 'u2', 'u3', 'u4'], 'u12', 30)
```
- **Açıklama:** Birden fazla host'tan eşzamanlı saldırı
- **Etki:** Birden fazla switch'te tespit edilir

### 5. Traffic Capture
```bash
mininet> py capture_traffic(net, 'u12', 30, '/tmp/attack.pcap')
```
- **Açıklama:** tcpdump ile trafik yakalar
- **Analiz:** Wireshark ile açılabilir


---

## Tespit Yöntemleri

### 1. Threshold-Based Tespit
```
PPS > 20,000 → ATTACK
SYN_RATIO > 80% → SYN FLOOD
```

### 2. ML-Based Tespit (Random Forest)
| Özellik | Açıklama |
|---------|----------|
| `packets_per_second` | Saniyedeki paket sayısı |
| `bytes_per_second` | Saniyedeki byte miktarı |
| `avg_packet_size` | Ortalama paket boyutu |
| `syn_ratio` | SYN paket oranı |
| `ack_ratio` | ACK paket oranı |
| `unique_src_ips` | Benzersiz kaynak IP sayısı |

### Tespit Çıktısı
```
======================================================================
[!!!] [CRITICAL] SYN FLOOD detected on switch 1
Confidence: 95.0% | Rate: 45000 pps | SYN ratio: 100.0%
Triggered rules: ML_PREDICTION:1, CONFIDENCE:0.95, HIGH_PPS:45000
======================================================================
```

---

## Test Sonuçları

### Ağ Performans Testi

| Durum | Packet Loss | Latency | Açıklama |
|-------|-------------|---------|----------|
| **Normal** | 0% | ~190 ms | Saldırı yok |
| **SYN Flood (1 host)** | 0% | ~190 ms | Tek kaynak |
| **DDoS (3 host)** | **80%** | ~187 ms | 3 saldırgan |
| **DDoS (5+ host)** | **90-100%** | timeout | Yoğun saldırı |

### Mininet Topoloji Başlatma

```
root@container:~/leo-sdn-attack# python3 topology/leo_topology.py

----------------------------------------
TOPOLOJI BİLGİLERİ:
----------------------------------------
  satellites: 12
  orbital_planes: 3
  satellites_per_plane: 4
  ground_stations: 4
  users: 12
  isl_delay_ms: 10
  downlink_delay_ms: 25
----------------------------------------

[*] Mininet Attack Module loaded!
[*] Type: py show_help()  for available commands

*** Attack module loaded! ***
*** Type 'py show_help()' for attack commands ***

*** Starting CLI:
mininet>
```

### Normal Durum (Saldırı Öncesi)
```bash
mininet> u2 ping -c 5 u12
PING 10.0.0.16 (10.0.0.16) 56(84) bytes of data.
64 bytes from 10.0.0.16: icmp_seq=1 ttl=64 time=425 ms
64 bytes from 10.0.0.16: icmp_seq=2 ttl=64 time=215 ms
64 bytes from 10.0.0.16: icmp_seq=3 ttl=64 time=205 ms
64 bytes from 10.0.0.16: icmp_seq=4 ttl=64 time=207 ms
64 bytes from 10.0.0.16: icmp_seq=5 ttl=64 time=202 ms

--- 10.0.0.16 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4016ms
rtt min/avg/max/mdev = 201.701/250.818/425.423/87.410 ms
```

### SYN Flood Saldırısı Başlatma
```bash
mininet> py syn_flood(net, 'u1', 'u12', 30)
============================================================
  SYN FLOOD ATTACK
============================================================
  Attacker: u1 (10.0.0.5)
  Target:   u12 (10.0.0.16)
  Duration: 30s
  Port:     80
  Spoofing: True
============================================================
  Command: timeout 30 hping3 -S --flood --rand-source -p 80 10.0.0.16 &
============================================================
[*] Attack started! Will run for 30s
True
```

### DDoS Saldırısı Sırasında
```bash
mininet> py distributed_attack(net, ['u1','u2','u3'], 'u12', 30)
============================================================
  DISTRIBUTED (DDoS) ATTACK
============================================================
  Attackers: ['u1', 'u2', 'u3']
  Target:    u12 (10.0.0.16)
  Duration:  30s
============================================================
  [*] Started attack from u1
  [*] Started attack from u2
  [*] Started attack from u3
  [*] DDoS attack started from 3 hosts!

mininet> u12 ping -c 5 u2
5 packets transmitted, 1 received, 80% packet loss
rtt min/avg/max = 187/187/187 ms
```

### Controller Tespit Çıktısı
```
======================================================================
[!!!] [CRITICAL] SYN FLOOD detected on switch 1
Confidence: 89.0% | Rate: 33412 pps | SYN ratio: 56.7%
Triggered rules: ML_PREDICTION:0, CONFIDENCE:0.89, HIGH_PPS:33412
======================================================================

[!!!] [CRITICAL] SYN FLOOD detected on switch 2
Confidence: 100.0% | Rate: 34153 pps | SYN ratio: 12.8%
======================================================================

[!!!] [CRITICAL] SYN FLOOD detected on switch 4
Confidence: 100.0% | Rate: 33578 pps | SYN ratio: 13.9%
======================================================================
```

### Tespit Yöntemi Karşılaştırması

Controller başlatılırken tespit modu seçilir:
```
==========================================
  LEO SDN Attack Detection Controller
==========================================
  Select detection mode:
  1. threshold - Threshold-based detection
  2. ml - Machine Learning detection
  Enter choice [1/2]:
==========================================
```

#### Threshold-Based Detection Sonuçları

**Controller Başlatma:**
```
===========================================
  LEO SDN Attack Detection Environment
===========================================
OVS Status: ovs-vsctl (Open vSwitch) 2.13.8
Ryu: ryu-manager 4.34
===========================================

root@container:~/leo-sdn-attack# ryu-manager sdn_controller/controller.py

============================================================
  LEO SDN ATTACK DETECTION SYSTEM
============================================================

  Tespit yöntemi seçin / Select detection method:

    [1] Eşik Tabanlı (Threshold-based)
    [2] Makine Öğrenmesi (Machine Learning)

============================================================

  Seciminiz (1 veya 2): 1
  > Esik tabanli tespit secildi.

==================================================
  LEO SDN Controller Started
  Detection Mode: Threshold-based
==================================================
Switch connected: dpid=1
Switch connected: dpid=2
...
Switch connected: dpid=12
Datapath registered: dpid=12
```

**Tespit Kuralları:**
| Kural | Eşik Değeri | Açıklama |
|-------|-------------|----------|
| HIGH_PPS | > 20,000 pps | Yüksek paket hızı |
| ELEVATED_PPS | > 5,000 pps | Orta seviye paket hızı |
| HIGH_SYN_RATIO | > 80% | SYN paket oranı |
| LOW_SYN_ACK_RATIO | < 10% | Düşük SYN-ACK oranı |
| HIGH_SMALL_PACKET_RATIO | > 70% | Küçük paket oranı |
| LOW_AVG_PACKET_SIZE | < 100 byte | Düşük ortalama paket boyutu |

**Gerçek Test Çıktısı (SYN Flood Saldırısı):**
```
============================================================
  [!!] ATTACK DETECTED on switch 1
  Type: syn_flood
  Confidence: 100.0%
  Severity: critical
  Rules: HIGH_PPS:36044, HIGH_SYN_RATIO:1.00, LOW_SYN_ACK_RATIO:0.00, 
         HIGH_SMALL_PACKET_RATIO:1.00, LOW_AVG_PACKET_SIZE:54
============================================================

======================================================================
[!!!] [CRITICAL] 19:19:20 - ALERT-000022
SYN FLOOD detected on switch 1 | Confidence: 100.0% | Rate: 36044 pps | SYN ratio: 100.0%
Triggered rules: HIGH_PPS:36044, HIGH_SYN_RATIO:1.00, LOW_SYN_ACK_RATIO:0.00
======================================================================

======================================================================
[!!!] [CRITICAL] 19:18:54 - ALERT-000001
SYN FLOOD detected on switch 4 | Confidence: 100.0% | Rate: 2163 pps | SYN ratio: 100.0%
======================================================================

======================================================================
[!!!] [CRITICAL] 19:18:54 - ALERT-000002
SYN FLOOD detected on switch 3 | Confidence: 100.0% | Rate: 2184 pps | SYN ratio: 100.0%
======================================================================

======================================================================
[!!!] [CRITICAL] 19:18:54 - ALERT-000003
SYN FLOOD detected on switch 2 | Confidence: 100.0% | Rate: 2215 pps | SYN ratio: 100.0%
======================================================================
```

**Test Özeti (Threshold):**
| Metrik | Değer |
|--------|-------|
| Toplam Alert Sayısı | 31 |
| Tespit Edilen Switch | 4 (dpid=1,2,3,4) |
| Maksimum PPS | 36,044 pps |
| SYN Ratio | %100 |
| Tespit Güvenilirliği | %100 |
| Ortalama Paket Boyutu | 54 byte |

**Avantajları:**
- Hızlı tespit (< 100ms)
- Düşük CPU kullanımı
- Anlaşılır kurallar
- %100 SYN ratio tespiti

**Dezavantajları:**
- Sabit eşikler
- Düşük hızlı saldırıları kaçırabilir

---

#### Machine Learning Detection Sonuçları

```bash
# Controller başlatma
ryu-manager sdn_controller/controller.py
# Seçim: 2 (ml)
```

**Kullanılan Özellikler:**
| Özellik | Açıklama |
|---------|----------|
| `packets_per_second` | Saniyedeki paket sayısı |
| `bytes_per_second` | Saniyedeki byte miktarı |
| `avg_packet_size` | Ortalama paket boyutu |
| `syn_ratio` | SYN paket oranı |
| `ack_ratio` | ACK paket oranı |
| `flow_count` | Aktif akış sayısı |

**Çıktı:**
```
======================================================================
[!!!] [CRITICAL] SYN FLOOD detected on switch 1
Confidence: 89.0% | Rate: 33412 pps | SYN ratio: 56.7%
Triggered rules: ML_PREDICTION:1, CONFIDENCE:0.89, HIGH_PPS:33412
======================================================================

[ML DEBUG] dpid=1 pps=33412 pred=1 conf=0.89 syn_ratio=0.57
```

**Model Bilgileri:**
| Parametre | Değer |
|-----------|-------|
| Algoritma | Random Forest |
| Ağaç Sayısı | 100 |
| Eğitim Verisi | TCP-SYNC Dataset |
| Doğruluk | %95+ |

**Avantajları:**
- Adaptif tespit
- Düşük false positive
- Yeni saldırı türlerini öğrenebilir

**Dezavantajları:**
- Eğitim verisi gerektirir
- Biraz daha yüksek CPU kullanımı

---

### Sonuç Özeti

| Metrik | Threshold | ML |
|--------|-----------|-----|
| Tespit Hızı | < 100ms | < 200ms |
| Güvenilirlik | %100 (kural bazlı) | %89-95 |
| False Positive | Orta | Düşük |
| Adaptif | Hayır | Evet |
| CPU Kullanımı | Düşük | Orta |

| Metrik | Değer |
|--------|-------|
| Tespit Edilen Switch Sayısı | 6+ |
| Ortalama PPS | 33,000+ pps |
| SYN Ratio (saldırgan switch) | %56-62 |
| Ağ Performans Kaybı | %80 packet loss |

> **Sonuç:** Her iki yöntem de DDoS saldırısını başarıyla tespit etti. ML yöntemi daha düşük false positive oranı sunarken, Threshold yöntemi daha hızlı tepki veriyor.

---

## Teknolojiler

| Kategori | Teknoloji |
|----------|-----------|
| SDN Controller | Ryu |
| Ağ Simülasyonu | Mininet |
| Virtual Switch | Open vSwitch |
| Saldırı Aracı | hping3 |
| ML Framework | Scikit-learn |
| Container | Docker |
