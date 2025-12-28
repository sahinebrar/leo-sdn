#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - LEO Topology Module
LEO (Low Earth Orbit) uydu ağı topolojisi simülasyonu

Bu modül Starlink benzeri bir LEO uydu ağını Mininet üzerinde simüle eder:
- Birden fazla orbital düzlemde uydular
- Inter-Satellite Links (ISL)
- Yer istasyonları ve kullanıcı terminalleri
- SDN kontrollü OpenFlow switch'ler
"""

import sys
import os

# Mininet imports
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
from mininet.topo import Topo

# Proje imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import get_logger, setup_logging
from utils.config import Config


logger = get_logger(__name__)


class LEOSatellite:
    """LEO uydu nesnesi"""
    
    def __init__(self, sat_id: int, plane_id: int, position: int):
        """
        Args:
            sat_id: Uydu ID'si
            plane_id: Orbital düzlem ID'si
            position: Düzlemdeki pozisyon
        """
        self.sat_id = sat_id
        self.plane_id = plane_id
        self.position = position
        self.name = f"sat{sat_id}"
        self.switch_name = f"s{sat_id}"
        
        # Bağlı yer istasyonları
        self.connected_ground_stations = []
        
        # Komşu uydular (ISL)
        self.isl_neighbors = []
    
    def __repr__(self):
        return f"LEOSatellite(id={self.sat_id}, plane={self.plane_id}, pos={self.position})"


class LEOTopology(Topo):
    """
    LEO Uydu Ağı Topolojisi
    
    Mimari:
    - Her uydu bir OVS switch olarak modellenir
    - Uydular arası ISL bağlantıları
    - Yer istasyonları switch'lere bağlı hostlar
    - Kullanıcılar yer istasyonlarına bağlı hostlar
    """
    
    def __init__(self, config: Config = None, **params):
        """
        Args:
            config: Konfigürasyon nesnesi
        """
        self.config = config or Config()
        
        # Topoloji parametreleri
        self.n_planes = self.config.get('topology.satellites.orbital_planes', 3)
        self.sats_per_plane = self.config.get('topology.satellites.satellites_per_plane', 4)
        self.n_satellites = self.n_planes * self.sats_per_plane
        self.n_ground_stations = self.config.get('topology.ground_stations.count', 4)
        self.users_per_station = self.config.get('topology.ground_stations.users_per_station', 3)
        
        # Link parametreleri
        self.isl_delay = self.config.get('topology.links.isl_delay_ms', 10)
        self.isl_bw = self.config.get('topology.links.isl_bandwidth_mbps', 1000)
        self.downlink_delay = self.config.get('topology.links.downlink_delay_ms', 25)
        self.downlink_bw = self.config.get('topology.links.downlink_bandwidth_mbps', 500)
        self.user_delay = self.config.get('topology.links.user_delay_ms', 5)
        self.user_bw = self.config.get('topology.links.user_bandwidth_mbps', 100)
        
        # Uydu ve istasyon nesneleri
        self.satellites = []
        self.ground_stations = []
        self.users = []
        
        super().__init__(**params)
    
    def build(self):
        """Topolojiyi oluşturur"""
        info("*** LEO Uydu Ağı Topolojisi Oluşturuluyor ***\n")
        
        # 1. Uyduları oluştur
        self._create_satellites()
        
        # 2. ISL bağlantılarını oluştur
        self._create_isl_links()
        
        # 3. Yer istasyonlarını oluştur
        self._create_ground_stations()
        
        # 4. Kullanıcıları oluştur
        self._create_users()
        
        info(f"*** Topoloji tamamlandı: {self.n_satellites} uydu, "
             f"{self.n_ground_stations} yer istasyonu, "
             f"{len(self.users)} kullanıcı ***\n")
    
    def _create_satellites(self):
        """Uydu switch'lerini oluşturur"""
        info("  + Uydular oluşturuluyor...\n")
        
        sat_id = 1
        for plane in range(self.n_planes):
            for pos in range(self.sats_per_plane):
                # LEO uydu nesnesi
                satellite = LEOSatellite(sat_id, plane, pos)
                self.satellites.append(satellite)
                
                # OVS switch olarak ekle (protokol LEONetwork'te belirlenir)
                self.addSwitch(satellite.switch_name)
                
                info(f"    - {satellite.name} (Plane {plane}, Pos {pos})\n")
                sat_id += 1
    
    def _create_isl_links(self):
        """Inter-Satellite Link (ISL) bağlantılarını oluşturur"""
        info("  + ISL bağlantıları oluşturuluyor...\n")
        
        for sat in self.satellites:
            plane = sat.plane_id
            pos = sat.position
            
            # Aynı düzlemdeki bir sonraki uydu (intra-plane ISL)
            next_pos = (pos + 1) % self.sats_per_plane
            next_sat = self._get_satellite(plane, next_pos)
            
            if next_sat and sat.sat_id < next_sat.sat_id:
                self._add_isl_link(sat, next_sat, "intra")
            
            # Komşu düzlemdeki uydu (inter-plane ISL)
            next_plane = (plane + 1) % self.n_planes
            adjacent_sat = self._get_satellite(next_plane, pos)
            
            if adjacent_sat and sat.sat_id < adjacent_sat.sat_id:
                self._add_isl_link(sat, adjacent_sat, "inter")
    
    def _add_isl_link(self, sat1: LEOSatellite, sat2: LEOSatellite, link_type: str):
        """İki uydu arasında ISL bağlantısı ekler"""
        # Gecikme hesapla (inter-plane biraz daha yüksek)
        delay = self.isl_delay if link_type == "intra" else int(self.isl_delay * 1.5)
        
        self.addLink(
            sat1.switch_name,
            sat2.switch_name,
            cls=TCLink,
            delay=f"{delay}ms",
            bw=self.isl_bw
        )
        
        sat1.isl_neighbors.append(sat2)
        sat2.isl_neighbors.append(sat1)
        
        info(f"    - ISL ({link_type}): {sat1.name} <-> {sat2.name} [{delay}ms]\n")
    
    def _get_satellite(self, plane: int, position: int) -> LEOSatellite:
        """Belirtilen konumdaki uyduyu döndürür"""
        for sat in self.satellites:
            if sat.plane_id == plane and sat.position == position:
                return sat
        return None
    
    def _create_ground_stations(self):
        """Yer istasyonlarını oluşturur ve uyduulara bağlar"""
        info("  + Yer istasyonları oluşturuluyor...\n")
        
        for gs_id in range(1, self.n_ground_stations + 1):
            # Yer istasyonu host olarak (aynı subnet: 10.0.0.x)
            gs_name = f"gs{gs_id}"
            gs_ip = f"10.0.0.{gs_id}/24"
            
            gs_host = self.addHost(gs_name, ip=gs_ip)
            self.ground_stations.append(gs_name)
            
            # En yakın uyduya bağla (round-robin dağılım)
            sat_idx = (gs_id - 1) % len(self.satellites)
            sat = self.satellites[sat_idx]
            
            self.addLink(
                gs_name,
                sat.switch_name,
                cls=TCLink,
                delay=f"{self.downlink_delay}ms",
                bw=self.downlink_bw
            )
            
            sat.connected_ground_stations.append(gs_name)
            info(f"    - {gs_name} ({gs_ip}) -> {sat.name} [{self.downlink_delay}ms]\n")
    
    def _create_users(self):
        """Kullanıcı terminallerini oluşturur"""
        info("  + Kullanıcılar oluşturuluyor...\n")
        
        user_id = 1
        for gs_id, gs_name in enumerate(self.ground_stations, 1):
            for u in range(self.users_per_station):
                user_name = f"u{user_id}"
                # Aynı subnet: 10.0.0.x (ground station'lardan sonra devam)
                host_ip_id = self.n_ground_stations + user_id
                user_ip = f"10.0.0.{host_ip_id}/24"
                
                user_host = self.addHost(user_name, ip=user_ip)
                self.users.append(user_name)
                
                # Yer istasyonunun bağlı olduğu uyduya bağla
                sat_idx = (gs_id - 1) % len(self.satellites)
                sat = self.satellites[sat_idx]
                
                self.addLink(
                    user_name,
                    sat.switch_name,
                    cls=TCLink,
                    delay=f"{self.user_delay + self.downlink_delay}ms",
                    bw=self.user_bw
                )
                
                info(f"    - {user_name} ({user_ip}) -> {sat.name}\n")
                user_id += 1
    
    def get_topology_info(self) -> dict:
        """Topoloji bilgilerini döndürür"""
        return {
            'satellites': len(self.satellites),
            'orbital_planes': self.n_planes,
            'satellites_per_plane': self.sats_per_plane,
            'ground_stations': len(self.ground_stations),
            'users': len(self.users),
            'isl_delay_ms': self.isl_delay,
            'downlink_delay_ms': self.downlink_delay
        }


class LEONetwork:
    """
    LEO Ağı Yöneticisi
    Mininet ağını başlatır ve yönetir
    """
    
    def __init__(self, config: Config = None, remote_controller: bool = True):
        """
        Args:
            config: Konfigürasyon nesnesi
            remote_controller: True ise remote SDN controller kullan
        """
        self.config = config or Config()
        self.remote_controller = remote_controller
        self.net = None
        self.topo = None
    
    def start(self):
        """Ağı başlatır"""
        info("\n" + "="*60 + "\n")
        info("   LEO SDN ATTACK DETECTION - AĞ SİMÜLASYONU\n")
        info("="*60 + "\n\n")
        
        # Topolojiyi oluştur
        self.topo = LEOTopology(self.config)
        
        # Controller ayarları
        if self.remote_controller:
            controller_ip = self.config.get('controller.ip', '127.0.0.1')
            controller_port = self.config.get('controller.port', 6633)
            
            info(f"*** Remote Controller: {controller_ip}:{controller_port}\n")
            
            self.net = Mininet(
                topo=self.topo,
                controller=lambda name: RemoteController(
                    name,
                    ip=controller_ip,
                    port=controller_port
                ),
                switch=OVSKernelSwitch,
                link=TCLink,
                autoSetMacs=True
            )
        else:
            # Dahili controller için OVSSwitch kullan (OpenFlow 1.0)
            self.net = Mininet(
                topo=self.topo,
                controller=Controller,
                switch=OVSSwitch,
                link=TCLink,
                autoSetMacs=True
            )
        
        # Ağı başlat
        self.net.start()
        
        # STP (Spanning Tree Protocol) aktifleştir - döngü önleme
        for switch in self.net.switches:
            switch.cmd('ovs-vsctl set bridge {} stp_enable=true'.format(switch.name))
        info("\n*** STP enabled on all switches ***\n")
        
        info("\n*** Ağ başlatıldı ***\n")
        
        # Topoloji bilgilerini göster
        self._print_topology_info()
        
        return self.net
    
    def _print_topology_info(self):
        """Topoloji bilgilerini yazdırır"""
        info("\n" + "-"*40 + "\n")
        info("TOPOLOJI BİLGİLERİ:\n")
        info("-"*40 + "\n")
        
        topo_info = self.topo.get_topology_info()
        for key, value in topo_info.items():
            info(f"  {key}: {value}\n")
        
        info("-"*40 + "\n\n")
    
    def stop(self):
        """Ağı durdurur"""
        if self.net:
            info("\n*** Ağ durduruluyor... ***\n")
            self.net.stop()
    
    def cli(self):
        """Mininet CLI başlatır"""
        if self.net:
            CLI(self.net)
    
    def ping_all(self):
        """Tüm hostlar arası ping testi"""
        if self.net:
            return self.net.pingAll()
    
    def get_hosts(self):
        """Tüm hostları döndürür"""
        if self.net:
            return self.net.hosts
        return []
    
    def get_switches(self):
        """Tüm switch'leri döndürür"""
        if self.net:
            return self.net.switches
        return []


def create_leo_network(use_remote_controller: bool = True) -> LEONetwork:
    """
    LEO ağı oluşturur ve döndürür.
    
    Args:
        use_remote_controller: Remote SDN controller kullanılsın mı
    
    Returns:
        LEONetwork: Ağ yöneticisi nesnesi
    """
    setup_logging(level="INFO")
    config = Config()
    
    network = LEONetwork(config, remote_controller=use_remote_controller)
    return network


def main():
    """Ana fonksiyon - CLI ile çalıştırma"""
    import argparse
    
    parser = argparse.ArgumentParser(description='LEO Uydu Ağı Simülasyonu')
    parser.add_argument('--no-controller', action='store_true',
                        help='Remote controller kullanma')
    parser.add_argument('--test', action='store_true',
                        help='Ping testi yap ve çık')
    args = parser.parse_args()
    
    setLogLevel('info')
    
    # Ağı oluştur ve başlat
    network = create_leo_network(use_remote_controller=not args.no_controller)
    
    try:
        network.start()
        
        if args.test:
            info("\n*** Ping testi yapılıyor... ***\n")
            network.ping_all()
        else:
            # Attack modülünü yükle ve CLI namespace'ine ekle
            try:
                from attack.mininet_attacks import (
                    syn_flood, ack_flood, synack_flood, low_rate_syn,
                    stop_attack, stop_all_attacks, mixed_scenario,
                    sequential_attacks, ramp_up_attack, burst_attack,
                    quick_test, distributed_attack, capture_traffic, show_help
                )
                
                # CLI locals'a ekle
                cli_locals = {
                    'net': network.net,
                    'syn_flood': syn_flood,
                    'ack_flood': ack_flood,
                    'synack_flood': synack_flood,
                    'low_rate_syn': low_rate_syn,
                    'stop_attack': stop_attack,
                    'stop_all_attacks': stop_all_attacks,
                    'mixed_scenario': mixed_scenario,
                    'sequential_attacks': sequential_attacks,
                    'ramp_up_attack': ramp_up_attack,
                    'burst_attack': burst_attack,
                    'quick_test': quick_test,
                    'distributed_attack': distributed_attack,
                    'capture_traffic': capture_traffic,
                    'show_help': show_help
                }
                
                # Global namespace'e ekle (py komutu için)
                import builtins
                for name, func in cli_locals.items():
                    setattr(builtins, name, func)
                
                info("\n*** Attack module loaded! ***\n")
                info("*** Type 'py show_help()' for attack commands ***\n\n")
                
            except ImportError as e:
                info(f"\n*** Warning: Attack module not loaded: {e} ***\n")
            
            info("\n*** Mininet CLI başlatılıyor... ***\n")
            info("Çıkmak için 'exit' yazın\n\n")
            network.cli()
    
    finally:
        network.stop()


if __name__ == '__main__':
    main()

