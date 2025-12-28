#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Feature Extractor
Akış istatistiklerinden öznitelik çıkarımı

Bu modül:
- Flow ve port istatistiklerinden öznitelik çıkarır
- Zaman serisi analizi yapar
- Saldırı tespiti için gerekli metrikleri hesaplar
"""

import time
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime


@dataclass
class FlowFeatures:
    """Bir switch için çıkarılan öznitelikler"""
    dpid: int
    timestamp: float
    
    # Temel metrikler
    total_packets: int = 0
    total_bytes: int = 0
    flow_count: int = 0
    
    # Hız metrikleri
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    flows_per_second: float = 0.0
    
    # TCP flag metrikleri
    syn_count: int = 0
    ack_count: int = 0
    syn_ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    
    # Oranlar
    syn_ratio: float = 0.0           # SYN / total
    syn_ack_ratio: float = 0.0       # SYN-ACK / SYN
    small_packet_ratio: float = 0.0  # Küçük paketlerin oranı
    
    # Çeşitlilik metrikleri
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_src_ports: int = 0
    unique_dst_ports: int = 0
    
    # Entropy (rastgelelik ölçüsü)
    src_ip_entropy: float = 0.0
    dst_port_entropy: float = 0.0
    
    # Port istatistikleri
    rx_packets: int = 0
    tx_packets: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    
    # Ortalama paket boyutu
    avg_packet_size: float = 0.0
    
    def to_dict(self) -> Dict:
        """Sözlük olarak döndür"""
        return {
            'dpid': self.dpid,
            'timestamp': self.timestamp,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'flow_count': self.flow_count,
            'syn_ratio': self.syn_ratio,
            'syn_ack_ratio': self.syn_ack_ratio,
            'small_packet_ratio': self.small_packet_ratio,
            'unique_src_ips': self.unique_src_ips,
            'src_ip_entropy': self.src_ip_entropy,
            'avg_packet_size': self.avg_packet_size
        }
    
    def to_vector(self) -> List[float]:
        """ML için feature vector olarak döndür"""
        return [
            self.packets_per_second,
            self.bytes_per_second,
            self.flow_count,
            self.syn_ratio,
            self.syn_ack_ratio,
            self.small_packet_ratio,
            self.unique_src_ips,
            self.src_ip_entropy,
            self.avg_packet_size,
            self.rx_dropped + self.tx_dropped,
            self.rx_errors + self.tx_errors
        ]


class FeatureExtractor:
    """
    Öznitelik Çıkarıcı
    
    Flow ve port istatistiklerinden saldırı tespiti için
    gerekli öznitelikleri çıkarır.
    """
    
    # Küçük paket eşiği (TCP SYN genellikle 60-80 byte)
    SMALL_PACKET_THRESHOLD = 100  # bytes
    
    def __init__(self, window_size: int = 10):
        """
        Args:
            window_size: Zaman penceresi boyutu (saniye)
        """
        self.window_size = window_size
        
        # Her switch için geçmiş veriler
        self._history: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        
        # Önceki ölçümler (delta hesabı için)
        self._prev_stats: Dict[int, Dict] = {}
        self._prev_time: Dict[int, float] = {}
        
        # IP ve port takibi
        self._src_ips: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._dst_ips: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._src_ports: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._dst_ports: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    
    def extract_features(self, dpid: int, flow_stats: List[Dict], 
                         port_stats: List[Dict]) -> FlowFeatures:
        """
        Flow ve port istatistiklerinden öznitelik çıkar.
        
        Args:
            dpid: Switch ID
            flow_stats: Flow istatistikleri listesi
            port_stats: Port istatistikleri listesi
            
        Returns:
            FlowFeatures: Çıkarılan öznitelikler
        """
        current_time = time.time()
        features = FlowFeatures(dpid=dpid, timestamp=current_time)
        
        # Flow istatistiklerini işle
        self._process_flow_stats(dpid, flow_stats, features)
        
        # Port istatistiklerini işle
        self._process_port_stats(dpid, port_stats, features)
        
        # Hız metriklerini hesapla
        self._calculate_rates(dpid, features, current_time)
        
        # Oranları hesapla
        self._calculate_ratios(features)
        
        # Entropy hesapla
        self._calculate_entropy(dpid, features)
        
        # Geçmişe ekle
        self._history[dpid].append(features)
        
        # Önceki değerleri güncelle
        self._prev_stats[dpid] = {
            'packets': features.total_packets,
            'bytes': features.total_bytes,
            'flows': features.flow_count,
            'syn': features.syn_count
        }
        self._prev_time[dpid] = current_time
        
        return features
    
    def _process_flow_stats(self, dpid: int, flow_stats: List[Dict], 
                            features: FlowFeatures) -> None:
        """Flow istatistiklerini işle"""
        features.flow_count = len(flow_stats)
        
        # IP ve port setlerini sıfırla
        src_ips = set()
        dst_ips = set()
        src_ports = set()
        dst_ports = set()
        
        small_packet_count = 0
        
        for flow in flow_stats:
            # Paket ve byte sayıları
            packet_count = flow.get('packet_count', 0)
            byte_count = flow.get('byte_count', 0)
            
            features.total_packets += packet_count
            features.total_bytes += byte_count
            
            # Match alanlarını kontrol et
            match = flow.get('match', {})
            
            # IP adresleri
            if 'ipv4_src' in match:
                src_ips.add(match['ipv4_src'])
                self._src_ips[dpid][match['ipv4_src']] += packet_count
            
            if 'ipv4_dst' in match:
                dst_ips.add(match['ipv4_dst'])
                self._dst_ips[dpid][match['ipv4_dst']] += packet_count
            
            # TCP portları
            if 'tcp_src' in match:
                src_ports.add(match['tcp_src'])
                self._src_ports[dpid][match['tcp_src']] += packet_count
            
            if 'tcp_dst' in match:
                dst_ports.add(match['tcp_dst'])
                self._dst_ports[dpid][match['tcp_dst']] += packet_count
            
            # TCP flags (eğer varsa)
            tcp_flags = match.get('tcp_flags', 0)
            # Tuple ise ilk elemanı al (OpenFlow bazen tuple döner)
            if isinstance(tcp_flags, tuple):
                tcp_flags = tcp_flags[0] if tcp_flags else 0
            try:
                tcp_flags = int(tcp_flags)
            except (TypeError, ValueError):
                tcp_flags = 0
            
            if tcp_flags:
                if tcp_flags & 0x02:  # SYN
                    features.syn_count += packet_count
                if tcp_flags & 0x10:  # ACK
                    features.ack_count += packet_count
                if tcp_flags & 0x12:  # SYN+ACK
                    features.syn_ack_count += packet_count
                if tcp_flags & 0x01:  # FIN
                    features.fin_count += packet_count
                if tcp_flags & 0x04:  # RST
                    features.rst_count += packet_count
            
            # Küçük paket kontrolü
            if packet_count > 0:
                avg_size = byte_count / packet_count
                if avg_size < self.SMALL_PACKET_THRESHOLD:
                    small_packet_count += packet_count
        
        # Benzersiz sayıları kaydet
        features.unique_src_ips = len(src_ips)
        features.unique_dst_ips = len(dst_ips)
        features.unique_src_ports = len(src_ports)
        features.unique_dst_ports = len(dst_ports)
        
        # Ortalama paket boyutu
        if features.total_packets > 0:
            features.avg_packet_size = features.total_bytes / features.total_packets
            features.small_packet_ratio = small_packet_count / features.total_packets
    
    def _process_port_stats(self, dpid: int, port_stats: List[Dict],
                            features: FlowFeatures) -> None:
        """Port istatistiklerini işle"""
        for port in port_stats:
            features.rx_packets += port.get('rx_packets', 0)
            features.tx_packets += port.get('tx_packets', 0)
            features.rx_dropped += port.get('rx_dropped', 0)
            features.tx_dropped += port.get('tx_dropped', 0)
            features.rx_errors += port.get('rx_errors', 0)
            features.tx_errors += port.get('tx_errors', 0)
    
    def _calculate_rates(self, dpid: int, features: FlowFeatures,
                         current_time: float) -> None:
        """Hız metriklerini hesapla"""
        if dpid not in self._prev_time:
            return
        
        time_delta = current_time - self._prev_time[dpid]
        if time_delta <= 0:
            return
        
        prev = self._prev_stats.get(dpid, {})
        
        # Paket/saniye
        packet_delta = features.total_packets - prev.get('packets', 0)
        features.packets_per_second = max(0, packet_delta / time_delta)
        
        # Byte/saniye
        byte_delta = features.total_bytes - prev.get('bytes', 0)
        features.bytes_per_second = max(0, byte_delta / time_delta)
        
        # Flow/saniye
        flow_delta = features.flow_count - prev.get('flows', 0)
        features.flows_per_second = max(0, flow_delta / time_delta)
    
    def _calculate_ratios(self, features: FlowFeatures) -> None:
        """Oranları hesapla"""
        if features.total_packets > 0:
            features.syn_ratio = features.syn_count / features.total_packets
        
        if features.syn_count > 0:
            features.syn_ack_ratio = features.syn_ack_count / features.syn_count
    
    def _calculate_entropy(self, dpid: int, features: FlowFeatures) -> None:
        """Shannon entropy hesapla"""
        # Kaynak IP entropy
        features.src_ip_entropy = self._shannon_entropy(
            list(self._src_ips[dpid].values())
        )
        
        # Hedef port entropy
        features.dst_port_entropy = self._shannon_entropy(
            list(self._dst_ports[dpid].values())
        )
    
    def _shannon_entropy(self, counts: List[int]) -> float:
        """Shannon entropy hesapla"""
        if not counts:
            return 0.0
        
        total = sum(counts)
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def get_history(self, dpid: int) -> List[FlowFeatures]:
        """Switch'in öznitelik geçmişini döndür"""
        return list(self._history[dpid])
    
    def get_average_features(self, dpid: int) -> Optional[FlowFeatures]:
        """Pencere içindeki ortalama öznitelikleri döndür"""
        history = self._history[dpid]
        if not history:
            return None
        
        # Ortalama hesapla
        avg = FlowFeatures(dpid=dpid, timestamp=time.time())
        n = len(history)
        
        for f in history:
            avg.packets_per_second += f.packets_per_second / n
            avg.bytes_per_second += f.bytes_per_second / n
            avg.syn_ratio += f.syn_ratio / n
            avg.unique_src_ips += f.unique_src_ips / n
            avg.src_ip_entropy += f.src_ip_entropy / n
            avg.avg_packet_size += f.avg_packet_size / n
        
        return avg
    
    def reset(self, dpid: Optional[int] = None) -> None:
        """Geçmişi sıfırla"""
        if dpid is not None:
            self._history[dpid].clear()
            self._prev_stats.pop(dpid, None)
            self._prev_time.pop(dpid, None)
            self._src_ips[dpid].clear()
            self._dst_ips[dpid].clear()
        else:
            self._history.clear()
            self._prev_stats.clear()
            self._prev_time.clear()
            self._src_ips.clear()
            self._dst_ips.clear()

