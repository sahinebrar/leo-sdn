#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Main Controller
Ana SDN kontrolcü uygulaması (Ryu tabanlı)

Bu modül:
- Switch'leri yönetir
- Paket yönlendirme yapar
- Saldırı tespit modülü ile entegre çalışır
- Akış istatistiklerini toplar

Kullanım:
    ryu-manager sdn_controller/controller.py
"""

import sys
import os

# Proje path'ini ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp, icmp
from ryu.lib import hub

from collections import defaultdict
from typing import Dict, List, Optional
import time
import logging

from sdn_controller.flow_manager import FlowManager
from sdn_controller.stats_collector import StatsCollector

# Detection modülleri
from detection.feature_extractor import FeatureExtractor
from detection.detector import AttackDetector, DetectionResult, AttackType
from detection.alerter import Alerter, create_default_alerter

# ML Detection (opsiyonel)
try:
    from detection.ml_detector import MLDetector, create_ml_detector, ML_AVAILABLE
except ImportError:
    ML_AVAILABLE = False
    MLDetector = None
    create_ml_detector = None

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LEOController(app_manager.RyuApp):
    """
    LEO Ağı SDN Kontrolcü
    
    Özellikleri:
    - L2 öğrenme switch
    - Akış istatistikleri toplama
    - Saldırı tespit entegrasyonu
    - TCP SYN flood koruması
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(LEOController, self).__init__(*args, **kwargs)
        
        # MAC tablosu: {dpid: {mac: port}}
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)
        
        # Flow manager'lar: {dpid: FlowManager}
        self.flow_managers: Dict[int, FlowManager] = {}
        
        # İstatistik toplayıcı
        self.stats_collector = StatsCollector(interval=5)
        self.stats_collector.add_stats_callback(self._on_stats_update)
        
        # ===== DETECTION SYSTEM =====
        # Öznitelik çıkarıcı
        self.feature_extractor = FeatureExtractor(window_size=10)
        
        # Detection modu seçimi
        self.detection_mode = self._select_detection_mode()
        
        # Saldırı tespit motoru
        if self.detection_mode == "ml" and ML_AVAILABLE:
            logger.info("Initializing ML-based detector...")
            
            # Gerçek veri ile eğitim kontrolü
            real_data_path = getattr(self, '_train_from_real_data', None)
            
            if real_data_path:
                from detection.ml_detector import MLDetector, MLConfig
                config = MLConfig()
                self.attack_detector = MLDetector(config)
                self.attack_detector.train_from_csv(real_data_path)
            else:
                self.attack_detector = create_ml_detector(train_if_needed=True)
        else:
            logger.info("Initializing Threshold-based detector...")
            self.attack_detector = AttackDetector()
        
        self.attack_detector.set_on_attack_detected(self._on_attack_detected)
        self.attack_detector.set_on_attack_ended(self._on_attack_ended)
        
        # Alarm yöneticisi
        self.alerter = create_default_alerter(log_dir="logs")
        
        # Detection aktif mi?
        self.detection_enabled = True
        # ===========================
        
        # Engellenen IP'ler
        self.blocked_ips: Dict[int, set] = defaultdict(set)
        
        # Trafik izleme
        self.traffic_monitor: Dict[int, Dict] = defaultdict(dict)
        
        # SYN flood eşikleri
        self.syn_threshold = 1000  # SYN paket/saniye
        self.syn_counters: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.last_syn_check = time.time()
        
        # TCP flag sayaçları (detection için)
        self.tcp_flag_counters: Dict[int, Dict[str, int]] = defaultdict(lambda: {
            'syn': 0, 'ack': 0, 'syn_ack': 0, 'fin': 0, 'rst': 0, 'total': 0
        })
        
        mode_name = "Machine Learning" if self.detection_mode == "ml" else "Threshold-based"
        logger.info("="*50)
        logger.info("  LEO SDN Controller Started")
        logger.info(f"  Detection Mode: {mode_name}")
        logger.info("="*50)
    
    def _select_detection_mode(self) -> str:
        """
        Kullanıcıdan tespit modunu seç.
        
        Returns:
            "threshold" veya "ml"
        """
        print("\n" + "="*60)
        print("  LEO SDN ATTACK DETECTION SYSTEM")
        print("="*60)
        print("\n  Tespit yöntemi seçin / Select detection method:\n")
        print("    [1] Eşik Tabanlı (Threshold-based)")
        print("        - Hızlı başlangıç")
        print("        - Sabit eşik değerleri")
        print("        - Model eğitimi gerektirmez")
        print()
        
        if ML_AVAILABLE:
            print("    [2] Makine Öğrenmesi (Machine Learning)")
            print("        - Random Forest sınıflandırıcı")
            print("        - Daha yüksek doğruluk")
            print("        - Otomatik model eğitimi")
        else:
            print("    [2] ML kullanılamıyor (scikit-learn yüklü değil)")
        
        print("\n" + "="*60)
        
        while True:
            try:
                choice = input("\n  Seçiminiz (1 veya 2) [varsayılan: 1]: ").strip()
                
                if choice == "" or choice == "1":
                    print("\n  > Esik tabanli tespit secildi.\n")
                    return "threshold"
                elif choice == "2":
                    if ML_AVAILABLE:
                        print("\n  > Makine ogrenmesi tabanli tespit secildi.")
                        self._check_real_dataset()
                        return "ml"
                    else:
                        print("\n  [!] ML kullanilamiyor. Esik tabanli seciliyor.\n")
                        return "threshold"
                else:
                    print("  Geçersiz seçim. 1 veya 2 girin.")
            except (EOFError, KeyboardInterrupt):
                print("\n  Varsayılan seçiliyor: Eşik tabanlı\n")
                return "threshold"
    
    def _check_real_dataset(self) -> None:
        """Gerçek dataset varsa kullan"""
        import os
        
        # Olası dataset yolları
        possible_paths = [
            "TCP-SYNC DATASET.csv",
            "data/TCP-SYNC DATASET.csv",
            "/root/leo-sdn-attack/TCP-SYNC DATASET.csv",
            os.path.expanduser("~/Desktop/workspace/leo-sdn-attack/TCP-SYNC DATASET.csv")
        ]
        
        dataset_path = None
        for path in possible_paths:
            if os.path.exists(path):
                dataset_path = path
                break
        
        if dataset_path:
            print(f"\n  [*] Gercek dataset bulundu: {dataset_path}")
            try:
                choice = input("  Gercek veri ile egitmek ister misiniz? (e/h) [e]: ").strip().lower()
                if choice in ['', 'e', 'evet', 'y', 'yes']:
                    self._train_from_real_data = dataset_path
                    print("  > Gercek veri ile egitilecek.\n")
                else:
                    self._train_from_real_data = None
                    print("  > Sentetik veri ile egitilecek.\n")
            except (EOFError, KeyboardInterrupt):
                self._train_from_real_data = None
        else:
            self._train_from_real_data = None
            print("\n  [i] Gercek dataset bulunamadi, sentetik veri kullanilacak.\n")
    
    def set_attack_detector(self, detector) -> None:
        """
        Saldırı tespit modülünü ayarla.
        
        Args:
            detector: Saldırı tespit nesnesi
        """
        self.attack_detector = detector
        self.stats_collector.add_stats_callback(detector.analyze)
        logger.info("Attack detector registered")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Switch bağlantı eventi.
        Yeni switch bağlandığında çağrılır.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        logger.info(f"Switch connected: dpid={dpid}")
        
        # Flow manager oluştur
        self.flow_managers[dpid] = FlowManager(datapath)
        
        # Varsayılan flow'u ekle (controller'a gönder)
        self.flow_managers[dpid].add_default_flow()
        
        # TCP SYN/ACK izleme kurallarını ekle (SYN flood tespiti için)
        self.flow_managers[dpid].add_tcp_syn_monitoring()
        logger.info(f"TCP SYN monitoring enabled for dpid={dpid}")
        
        # İstatistik toplayıcıya kaydet
        self.stats_collector.register_datapath(datapath)
        
        # İstatistik toplamayı başlat (ilk switch'te)
        if len(self.flow_managers) == 1:
            self.stats_collector.start()
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Switch durum değişikliği eventi"""
        datapath = ev.datapath
        dpid = datapath.id
        
        if ev.state == DEAD_DISPATCHER:
            logger.warning(f"Switch disconnected: dpid={dpid}")
            
            # Temizle
            if dpid in self.flow_managers:
                del self.flow_managers[dpid]
            self.stats_collector.unregister_datapath(dpid)
            self.mac_to_port.pop(dpid, None)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Packet-In eventi.
        Switch'ten gelen paketleri işler.
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        # Paketi parse et
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth is None:
            return
        
        # LLDP paketlerini atla
        if eth.ethertype == 0x88cc:
            return
        
        src_mac = eth.src
        dst_mac = eth.dst
        
        # MAC tablosunu güncelle
        self.mac_to_port[dpid][src_mac] = in_port
        
        # Hedef portu belirle
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # IPv4 paketlerini analiz et
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Engelli IP kontrolü
            if src_ip in self.blocked_ips[dpid]:
                logger.debug(f"Blocked packet from {src_ip}")
                return
            
            # TCP paketlerini analiz et
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                self._handle_tcp_packet(dpid, src_ip, dst_ip, tcp_pkt)
        
        # Aksiyonları oluştur
        actions = [parser.OFPActionOutput(out_port)]
        
        # Flood değilse flow ekle
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.flow_managers[dpid].add_flow(
                    priority=FlowManager.PRIORITY_NORMAL,
                    match=match,
                    actions=actions,
                    idle_timeout=300,
                    buffer_id=msg.buffer_id
                )
                return
            else:
                self.flow_managers[dpid].add_flow(
                    priority=FlowManager.PRIORITY_NORMAL,
                    match=match,
                    actions=actions,
                    idle_timeout=300
                )
        
        # Paketi gönder
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
    
    def _handle_tcp_packet(self, dpid: int, src_ip: str, dst_ip: str, tcp_pkt) -> None:
        """
        TCP paketlerini analiz et.
        SYN flood tespiti yapar.
        
        Args:
            dpid: Switch ID
            src_ip: Kaynak IP
            dst_ip: Hedef IP
            tcp_pkt: TCP paketi
        """
        # TCP flags'i güvenli şekilde al
        try:
            flags = tcp_pkt.bits
            # Eğer tuple ise ilk elemanı al
            if isinstance(flags, tuple):
                flags = flags[0] if flags else 0
            flags = int(flags)
        except (AttributeError, TypeError, ValueError):
            flags = 0
        
        counters = self.tcp_flag_counters[dpid]
        
        # TCP flag sayaçlarını güncelle
        counters['total'] += 1
        
        if flags & 0x02:  # SYN
            counters['syn'] += 1
            self.syn_counters[dpid][src_ip] += 1
        
        if flags & 0x10:  # ACK
            counters['ack'] += 1
        
        if flags == 0x12:  # SYN+ACK
            counters['syn_ack'] += 1
        
        if flags & 0x01:  # FIN
            counters['fin'] += 1
        
        if flags & 0x04:  # RST
            counters['rst'] += 1
        
        # Periyodik kontrol
        current_time = time.time()
        if current_time - self.last_syn_check > 1:
            self._check_syn_flood(dpid)
            self.last_syn_check = current_time
    
    def _check_syn_flood(self, dpid: int) -> None:
        """SYN flood kontrolü yap"""
        for src_ip, count in list(self.syn_counters[dpid].items()):
            if count > self.syn_threshold:
                logger.warning(f"SYN flood detected from {src_ip}: {count} SYN/s")
                self._mitigate_attack(dpid, src_ip)
        
        # Sayaçları sıfırla
        self.syn_counters[dpid].clear()
    
    def _mitigate_attack(self, dpid: int, attacker_ip: str) -> None:
        """
        Saldırıyı engelle.
        
        Args:
            dpid: Switch ID
            attacker_ip: Saldırgan IP
        """
        if dpid in self.flow_managers:
            self.flow_managers[dpid].block_ip(attacker_ip, direction="src")
            self.blocked_ips[dpid].add(attacker_ip)
            logger.warning(f"Attacker blocked: {attacker_ip} on dpid={dpid}")
    
    def unblock_attacker(self, dpid: int, ip_address: str) -> None:
        """
        Saldırgan engelini kaldır.
        
        Args:
            dpid: Switch ID
            ip_address: IP adresi
        """
        if dpid in self.flow_managers:
            self.flow_managers[dpid].unblock_ip(ip_address)
            self.blocked_ips[dpid].discard(ip_address)
            logger.info(f"Attacker unblocked: {ip_address}")
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Flow stats reply handler"""
        self.stats_collector.handle_flow_stats_reply(ev)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Port stats reply handler"""
        self.stats_collector.handle_port_stats_reply(ev)
    
    def _on_stats_update(self, dpid: int, flows, ports) -> None:
        """
        İstatistik güncellemesi callback'i.
        
        Args:
            dpid: Switch ID
            flows: Flow istatistikleri
            ports: Port istatistikleri
        """
        # Trafik izleme güncelle
        traffic = self.stats_collector.get_traffic_rate(dpid)
        self.traffic_monitor[dpid] = traffic
        
        # Yüksek trafik uyarısı
        if traffic['packets_per_sec'] > 10000:
            logger.warning(f"High traffic on dpid={dpid}: {traffic['packets_per_sec']:.0f} pps")
        
        # ===== DETECTION SYSTEM =====
        if self.detection_enabled:
            # Flow ve port stats'ları dict listesine çevir
            flow_stats = self._convert_flow_stats(flows)
            port_stats = self._convert_port_stats(ports)
            
            # Öznitelik çıkar
            features = self.feature_extractor.extract_features(dpid, flow_stats, port_stats)
            
            # TCP flag bilgilerini ekle (packet_in'den toplanan)
            tcp_counts = self.tcp_flag_counters[dpid]
            if tcp_counts['total'] > 0:
                features.syn_count = tcp_counts['syn']
                features.ack_count = tcp_counts['ack']
                features.syn_ack_count = tcp_counts['syn_ack']
                features.fin_count = tcp_counts['fin']
                features.rst_count = tcp_counts['rst']
                
                # SYN oranını hesapla
                features.syn_ratio = tcp_counts['syn'] / tcp_counts['total']
                
                # SYN-ACK oranını hesapla
                if tcp_counts['syn'] > 0:
                    features.syn_ack_ratio = tcp_counts['syn_ack'] / tcp_counts['syn']
            
            # Sayaçları sıfırla (periyodik)
            self.tcp_flag_counters[dpid] = {
                'syn': 0, 'ack': 0, 'syn_ack': 0, 'fin': 0, 'rst': 0, 'total': 0
            }
            
            # Saldırı tespiti
            result = self.attack_detector.detect(features)
            
            # Saldırı varsa alarm oluştur
            if result.is_attack:
                self.alerter.create_alert(result)
    
    def _convert_flow_stats(self, flows) -> List[Dict]:
        """Flow stats'ları dict listesine çevir"""
        result = []
        for flow in flows:
            result.append({
                'packet_count': getattr(flow, 'packet_count', 0),
                'byte_count': getattr(flow, 'byte_count', 0),
                'duration_sec': getattr(flow, 'duration_sec', 0),
                'match': self._match_to_dict(getattr(flow, 'match', {}))
            })
        return result
    
    def _convert_port_stats(self, ports) -> List[Dict]:
        """Port stats'ları dict listesine çevir"""
        result = []
        for port in ports:
            result.append({
                'port_no': getattr(port, 'port_no', 0),
                'rx_packets': getattr(port, 'rx_packets', 0),
                'tx_packets': getattr(port, 'tx_packets', 0),
                'rx_bytes': getattr(port, 'rx_bytes', 0),
                'tx_bytes': getattr(port, 'tx_bytes', 0),
                'rx_dropped': getattr(port, 'rx_dropped', 0),
                'tx_dropped': getattr(port, 'tx_dropped', 0),
                'rx_errors': getattr(port, 'rx_errors', 0),
                'tx_errors': getattr(port, 'tx_errors', 0)
            })
        return result
    
    def _match_to_dict(self, match) -> Dict:
        """Match nesnesini dict'e çevir"""
        result = {}
        try:
            if hasattr(match, 'items'):
                for field, value in match.items():
                    result[field] = value
            elif hasattr(match, '_fields2'):
                for field in match._fields2:
                    if hasattr(match, field[0]):
                        result[field[0]] = getattr(match, field[0])
        except:
            pass
        return result
    
    def _on_attack_detected(self, result: DetectionResult) -> None:
        """
        Saldırı tespit edildiğinde çağrılır.
        
        Args:
            result: Tespit sonucu
        """
        logger.warning("="*60)
        logger.warning(f"  [!!] ATTACK DETECTED on switch {result.dpid}")
        logger.warning(f"  Type: {result.attack_type.value}")
        logger.warning(f"  Confidence: {result.confidence:.1%}")
        logger.warning(f"  Severity: {result.severity}")
        logger.warning(f"  Rules: {', '.join(result.triggered_rules)}")
        logger.warning("="*60)
        
        # Otomatik önlem al (opsiyonel)
        # self._auto_mitigate(result)
    
    def _on_attack_ended(self, result: DetectionResult) -> None:
        """
        Saldırı bittiğinde çağrılır.
        
        Args:
            result: Tespit sonucu
        """
        logger.info("="*60)
        logger.info(f"  [*] Attack ended on switch {result.dpid}")
        logger.info("="*60)
    
    def enable_detection(self) -> None:
        """Detection sistemini aktifleştir"""
        self.detection_enabled = True
        logger.info("Detection system ENABLED")
    
    def disable_detection(self) -> None:
        """Detection sistemini devre dışı bırak"""
        self.detection_enabled = False
        logger.info("Detection system DISABLED")
    
    def get_detection_status(self) -> Dict:
        """Detection durumunu döndür"""
        return {
            'enabled': self.detection_enabled,
            'active_attacks': len(self.attack_detector.get_active_attacks()),
            'total_alerts': self.alerter.get_stats()['total_alerts'],
            'attacks_by_switch': {
                dpid: result.attack_type.value
                for dpid, result in self.attack_detector.get_active_attacks().items()
            }
        }
    
    def get_network_stats(self) -> Dict:
        """
        Ağ istatistiklerini döndür.
        
        Returns:
            Tüm switch'lerin istatistikleri
        """
        stats = {
            'switches': {},
            'blocked_ips': dict(self.blocked_ips),
            'traffic': dict(self.traffic_monitor)
        }
        
        for dpid in self.flow_managers:
            switch_stats = self.stats_collector.get_switch_stats(dpid)
            if switch_stats:
                stats['switches'][dpid] = {
                    'n_flows': switch_stats.n_flows,
                    'n_ports': switch_stats.n_ports,
                    'total_packets': switch_stats.total_packets,
                    'total_bytes': switch_stats.total_bytes,
                    'mac_table_size': len(self.mac_to_port[dpid])
                }
        
        return stats
    
    def get_top_talkers(self, dpid: int, n: int = 5) -> List:
        """
        En çok trafik üreten akışları döndür.
        
        Args:
            dpid: Switch ID
            n: Döndürülecek akış sayısı
        
        Returns:
            Top talker listesi
        """
        return self.stats_collector.get_top_flows(dpid, n, metric='packets')


# CLI ile çalıştırma için
def main():
    """
    Controller'ı başlat.
    
    Kullanım:
        ryu-manager sdn_controller/controller.py
    
    Veya:
        python3 -m ryu.cmd.manager sdn_controller/controller.py
    """
    from ryu.cmd import manager
    
    # Controller'ı başlat
    manager.main(args=[
        '--verbose',
        '--ofp-tcp-listen-port', '6633',
        os.path.abspath(__file__)
    ])


if __name__ == '__main__':
    main()

