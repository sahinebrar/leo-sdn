#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Stats Collector
OpenFlow istatistik toplama modülü

Bu modül:
- Switch'lerden akış istatistikleri toplar
- Port istatistiklerini izler
- Saldırı tespiti için veri sağlar
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
from datetime import datetime
import logging

from ryu.ofproto import ofproto_v1_3


logger = logging.getLogger(__name__)


@dataclass
class FlowStats:
    """Tek bir akışın istatistikleri"""
    dpid: int
    table_id: int
    priority: int
    match: dict
    packet_count: int
    byte_count: int
    duration_sec: int
    duration_nsec: int
    timestamp: float = field(default_factory=time.time)
    
    @property
    def packets_per_second(self) -> float:
        """Saniye başına paket sayısı"""
        if self.duration_sec > 0:
            return self.packet_count / self.duration_sec
        return 0.0
    
    @property
    def bytes_per_second(self) -> float:
        """Saniye başına byte sayısı"""
        if self.duration_sec > 0:
            return self.byte_count / self.duration_sec
        return 0.0
    
    @property
    def avg_packet_size(self) -> float:
        """Ortalama paket boyutu"""
        if self.packet_count > 0:
            return self.byte_count / self.packet_count
        return 0.0


@dataclass
class PortStats:
    """Port istatistikleri"""
    dpid: int
    port_no: int
    rx_packets: int
    tx_packets: int
    rx_bytes: int
    tx_bytes: int
    rx_dropped: int
    tx_dropped: int
    rx_errors: int
    tx_errors: int
    timestamp: float = field(default_factory=time.time)
    
    @property
    def total_packets(self) -> int:
        return self.rx_packets + self.tx_packets
    
    @property
    def total_bytes(self) -> int:
        return self.rx_bytes + self.tx_bytes
    
    @property
    def error_rate(self) -> float:
        """Hata oranı"""
        total = self.total_packets
        if total > 0:
            return (self.rx_errors + self.tx_errors) / total
        return 0.0


@dataclass
class SwitchStats:
    """Switch genel istatistikleri"""
    dpid: int
    n_flows: int
    n_ports: int
    total_packets: int
    total_bytes: int
    timestamp: float = field(default_factory=time.time)


class StatsCollector:
    """
    İstatistik Toplayıcı
    
    Düzenli aralıklarla switch'lerden istatistik toplar ve saklar.
    """
    
    def __init__(self, interval: int = 5):
        """
        Args:
            interval: İstatistik toplama aralığı (saniye)
        """
        self.interval = interval
        
        # Switch datapath'leri
        self.datapaths: Dict[int, object] = {}
        
        # İstatistikler
        self.flow_stats: Dict[int, List[FlowStats]] = defaultdict(list)
        self.port_stats: Dict[int, Dict[int, PortStats]] = defaultdict(dict)
        self.switch_stats: Dict[int, SwitchStats] = {}
        
        # Geçmiş veriler (zaman serisi)
        self.flow_history: Dict[int, List[List[FlowStats]]] = defaultdict(list)
        self.port_history: Dict[int, List[Dict[int, PortStats]]] = defaultdict(list)
        
        # Callback'ler
        self._stats_callbacks: List[Callable] = []
        
        # Thread kontrolü
        self._running = False
        self._thread: Optional[threading.Thread] = None
        
        # Maksimum geçmiş boyutu
        self.max_history = 100
    
    def register_datapath(self, datapath) -> None:
        """
        Switch datapath'ini kaydet.
        
        Args:
            datapath: OpenFlow datapath
        """
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        logger.info(f"Datapath registered: dpid={dpid}")
    
    def unregister_datapath(self, dpid: int) -> None:
        """
        Switch datapath'ini kaldır.
        
        Args:
            dpid: Datapath ID
        """
        if dpid in self.datapaths:
            del self.datapaths[dpid]
            logger.info(f"Datapath unregistered: dpid={dpid}")
    
    def add_stats_callback(self, callback: Callable) -> None:
        """
        İstatistik güncellemesi callback'i ekle.
        Callback fonksiyonu (dpid, flow_stats, port_stats) parametreleri alır.
        
        Args:
            callback: Callback fonksiyonu
        """
        self._stats_callbacks.append(callback)
    
    def start(self) -> None:
        """İstatistik toplama döngüsünü başlat"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._collection_loop, daemon=True)
        self._thread.start()
        logger.info(f"Stats collector started (interval={self.interval}s)")
    
    def stop(self) -> None:
        """İstatistik toplama döngüsünü durdur"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Stats collector stopped")
    
    def _collection_loop(self) -> None:
        """Ana toplama döngüsü"""
        while self._running:
            for dpid, datapath in list(self.datapaths.items()):
                try:
                    self._request_flow_stats(datapath)
                    self._request_port_stats(datapath)
                except Exception as e:
                    logger.error(f"Error collecting stats from dpid={dpid}: {e}")
            
            time.sleep(self.interval)
    
    def _request_flow_stats(self, datapath) -> None:
        """Flow istatistikleri iste"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    def _request_port_stats(self, datapath) -> None:
        """Port istatistikleri iste"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    def handle_flow_stats_reply(self, ev) -> None:
        """
        Flow stats reply handler.
        Controller'dan çağrılır.
        
        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        flows = []
        for stat in body:
            flow = FlowStats(
                dpid=dpid,
                table_id=stat.table_id,
                priority=stat.priority,
                match=dict(stat.match.items()) if stat.match else {},
                packet_count=stat.packet_count,
                byte_count=stat.byte_count,
                duration_sec=stat.duration_sec,
                duration_nsec=stat.duration_nsec
            )
            flows.append(flow)
        
        # Güncelle
        self.flow_stats[dpid] = flows
        
        # Geçmişe ekle
        self.flow_history[dpid].append(flows)
        if len(self.flow_history[dpid]) > self.max_history:
            self.flow_history[dpid].pop(0)
        
        # Switch stats güncelle
        self._update_switch_stats(dpid)
        
        # Callback'leri çağır
        for callback in self._stats_callbacks:
            try:
                callback(dpid, flows, self.port_stats.get(dpid, {}))
            except Exception as e:
                logger.error(f"Stats callback error: {e}")
        
        logger.debug(f"Flow stats received: dpid={dpid}, flows={len(flows)}")
    
    def handle_port_stats_reply(self, ev) -> None:
        """
        Port stats reply handler.
        Controller'dan çağrılır.
        
        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        ports = {}
        for stat in body:
            port = PortStats(
                dpid=dpid,
                port_no=stat.port_no,
                rx_packets=stat.rx_packets,
                tx_packets=stat.tx_packets,
                rx_bytes=stat.rx_bytes,
                tx_bytes=stat.tx_bytes,
                rx_dropped=stat.rx_dropped,
                tx_dropped=stat.tx_dropped,
                rx_errors=stat.rx_errors,
                tx_errors=stat.tx_errors
            )
            ports[stat.port_no] = port
        
        # Güncelle
        self.port_stats[dpid] = ports
        
        # Geçmişe ekle
        self.port_history[dpid].append(ports)
        if len(self.port_history[dpid]) > self.max_history:
            self.port_history[dpid].pop(0)
        
        logger.debug(f"Port stats received: dpid={dpid}, ports={len(ports)}")
    
    def _update_switch_stats(self, dpid: int) -> None:
        """Switch genel istatistiklerini güncelle"""
        flows = self.flow_stats.get(dpid, [])
        ports = self.port_stats.get(dpid, {})
        
        total_packets = sum(f.packet_count for f in flows)
        total_bytes = sum(f.byte_count for f in flows)
        
        self.switch_stats[dpid] = SwitchStats(
            dpid=dpid,
            n_flows=len(flows),
            n_ports=len(ports),
            total_packets=total_packets,
            total_bytes=total_bytes
        )
    
    def get_flow_stats(self, dpid: int) -> List[FlowStats]:
        """Belirtilen switch'in flow istatistiklerini döndür"""
        return self.flow_stats.get(dpid, [])
    
    def get_port_stats(self, dpid: int) -> Dict[int, PortStats]:
        """Belirtilen switch'in port istatistiklerini döndür"""
        return self.port_stats.get(dpid, {})
    
    def get_switch_stats(self, dpid: int) -> Optional[SwitchStats]:
        """Belirtilen switch'in genel istatistiklerini döndür"""
        return self.switch_stats.get(dpid)
    
    def get_all_stats(self) -> Dict:
        """Tüm istatistikleri döndür"""
        return {
            'flow_stats': dict(self.flow_stats),
            'port_stats': dict(self.port_stats),
            'switch_stats': dict(self.switch_stats)
        }
    
    def get_traffic_rate(self, dpid: int, window: int = 2) -> Dict:
        """
        Belirtilen pencere içindeki trafik hızını hesapla.
        
        Args:
            dpid: Switch ID
            window: Kaç önceki örnek kullanılacak
        
        Returns:
            Trafik hızı metrikleri
        """
        history = self.flow_history.get(dpid, [])
        
        if len(history) < window:
            return {'packets_per_sec': 0, 'bytes_per_sec': 0}
        
        # Son iki örnek
        current = history[-1]
        previous = history[-window]
        
        current_packets = sum(f.packet_count for f in current)
        previous_packets = sum(f.packet_count for f in previous)
        
        current_bytes = sum(f.byte_count for f in current)
        previous_bytes = sum(f.byte_count for f in previous)
        
        time_diff = self.interval * (window - 1)
        
        if time_diff > 0:
            pps = (current_packets - previous_packets) / time_diff
            bps = (current_bytes - previous_bytes) / time_diff
        else:
            pps = 0
            bps = 0
        
        return {
            'packets_per_sec': max(0, pps),
            'bytes_per_sec': max(0, bps),
            'total_packets': current_packets,
            'total_bytes': current_bytes
        }
    
    def get_top_flows(self, dpid: int, n: int = 10, metric: str = 'packets') -> List[FlowStats]:
        """
        En yoğun akışları döndür.
        
        Args:
            dpid: Switch ID
            n: Döndürülecek akış sayısı
            metric: Sıralama metriği ('packets', 'bytes', 'pps')
        
        Returns:
            Sıralı akış listesi
        """
        flows = self.flow_stats.get(dpid, [])
        
        if metric == 'packets':
            key_func = lambda f: f.packet_count
        elif metric == 'bytes':
            key_func = lambda f: f.byte_count
        elif metric == 'pps':
            key_func = lambda f: f.packets_per_second
        else:
            key_func = lambda f: f.packet_count
        
        return sorted(flows, key=key_func, reverse=True)[:n]
    
    def export_stats(self, filepath: str) -> None:
        """
        İstatistikleri dosyaya kaydet.
        
        Args:
            filepath: Dosya yolu
        """
        import json
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'switches': {}
        }
        
        for dpid in self.datapaths:
            data['switches'][dpid] = {
                'flows': [
                    {
                        'match': f.match,
                        'packets': f.packet_count,
                        'bytes': f.byte_count,
                        'duration': f.duration_sec
                    }
                    for f in self.flow_stats.get(dpid, [])
                ],
                'ports': {
                    port_no: {
                        'rx_packets': p.rx_packets,
                        'tx_packets': p.tx_packets,
                        'rx_bytes': p.rx_bytes,
                        'tx_bytes': p.tx_bytes
                    }
                    for port_no, p in self.port_stats.get(dpid, {}).items()
                }
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Stats exported to {filepath}")

