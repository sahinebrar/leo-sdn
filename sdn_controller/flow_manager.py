#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Flow Manager
OpenFlow akış kuralları yönetimi

Bu modül:
- Akış kurallarını switch'lere yükler
- Paket eşleştirme kuralları oluşturur
- Saldırı tespitinde trafik engelleme/yönlendirme yapar
"""

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from typing import Dict, List, Optional, Tuple
import logging


logger = logging.getLogger(__name__)


class FlowManager:
    """
    OpenFlow Akış Yöneticisi
    
    Switch'lere akış kuralları ekler, siler ve günceller.
    """
    
    # Öncelik seviyeleri
    PRIORITY_DEFAULT = 0
    PRIORITY_LOW = 100
    PRIORITY_NORMAL = 500
    PRIORITY_HIGH = 1000
    PRIORITY_CRITICAL = 10000
    
    # Tablo ID'leri
    TABLE_MAIN = 0
    TABLE_ACL = 1
    TABLE_FORWARD = 2
    
    def __init__(self, datapath):
        """
        Args:
            datapath: OpenFlow switch datapath nesnesi
        """
        self.datapath = datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser
        
        # MAC tablosu (öğrenilen MAC adresleri)
        self.mac_table: Dict[str, int] = {}
    
    def add_flow(self, 
                 priority: int,
                 match,
                 actions: List,
                 idle_timeout: int = 0,
                 hard_timeout: int = 0,
                 table_id: int = 0,
                 buffer_id: int = None) -> None:
        """
        Switch'e akış kuralı ekler.
        
        Args:
            priority: Kural önceliği
            match: Eşleştirme kriterleri
            actions: Uygulanacak aksiyonlar
            idle_timeout: Boşta kalma süresi (saniye, 0=sınırsız)
            hard_timeout: Maksimum süre (saniye, 0=sınırsız)
            table_id: Akış tablosu ID
            buffer_id: Buffer ID (opsiyonel)
        """
        inst = [self.parser.OFPInstructionActions(
            self.ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        
        if buffer_id is not None:
            mod = self.parser.OFPFlowMod(
                datapath=self.datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                table_id=table_id
            )
        else:
            mod = self.parser.OFPFlowMod(
                datapath=self.datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                table_id=table_id
            )
        
        self.datapath.send_msg(mod)
        logger.debug(f"Flow added: priority={priority}, match={match}")
    
    def delete_flow(self, match=None, table_id: int = 0) -> None:
        """
        Akış kuralı siler.
        
        Args:
            match: Silinecek kuralın eşleştirme kriterleri (None=tümü)
            table_id: Tablo ID
        """
        if match is None:
            match = self.parser.OFPMatch()
        
        mod = self.parser.OFPFlowMod(
            datapath=self.datapath,
            command=self.ofproto.OFPFC_DELETE,
            out_port=self.ofproto.OFPP_ANY,
            out_group=self.ofproto.OFPG_ANY,
            match=match,
            table_id=table_id
        )
        
        self.datapath.send_msg(mod)
        logger.info(f"Flow deleted: match={match}")
    
    def add_default_flow(self) -> None:
        """
        Varsayılan akış kuralı ekler (controller'a gönder).
        Eşleşmeyen paketler controller'a iletilir.
        """
        match = self.parser.OFPMatch()
        actions = [self.parser.OFPActionOutput(
            self.ofproto.OFPP_CONTROLLER,
            self.ofproto.OFPCML_NO_BUFFER
        )]
        
        self.add_flow(
            priority=self.PRIORITY_DEFAULT,
            match=match,
            actions=actions
        )
        logger.info(f"Default flow added for dpid={self.datapath.id}")
    
    def add_tcp_flag_monitoring_flows(self) -> None:
        """
        TCP flag izleme kuralları ekler.
        SYN, ACK, FIN, RST paketlerini controller'a kopyalar.
        
        Bu kurallar sayesinde TCP bağlantı durumu takip edilebilir
        ve SYN flood saldırıları daha doğru tespit edilebilir.
        """
        dpid = self.datapath.id
        
        # TCP SYN paketleri (bağlantı başlatma)
        # tcp_flags: SYN=0x02
        self._add_tcp_flag_flow(
            tcp_flags=0x02,  # SYN
            flag_mask=0x02,
            description="SYN"
        )
        
        # TCP SYN+ACK paketleri (bağlantı kabul)
        # tcp_flags: SYN+ACK=0x12
        self._add_tcp_flag_flow(
            tcp_flags=0x12,  # SYN+ACK
            flag_mask=0x12,
            description="SYN-ACK"
        )
        
        # TCP ACK paketleri (sadece ACK, SYN olmadan)
        # Bu çok fazla paket olabilir, dikkatli kullan
        # self._add_tcp_flag_flow(
        #     tcp_flags=0x10,  # ACK
        #     flag_mask=0x12,  # SYN olmadan ACK
        #     description="ACK"
        # )
        
        # TCP FIN paketleri (bağlantı sonlandırma)
        self._add_tcp_flag_flow(
            tcp_flags=0x01,  # FIN
            flag_mask=0x01,
            description="FIN"
        )
        
        # TCP RST paketleri (bağlantı sıfırlama)
        self._add_tcp_flag_flow(
            tcp_flags=0x04,  # RST
            flag_mask=0x04,
            description="RST"
        )
        
        logger.info(f"TCP flag monitoring flows added for dpid={dpid}")
    
    def _add_tcp_flag_flow(self, tcp_flags: int, flag_mask: int, 
                           description: str) -> None:
        """
        Belirli TCP flag'e sahip paketleri controller'a gönderen kural ekler.
        
        Args:
            tcp_flags: TCP flag değeri
            flag_mask: Flag maskesi
            description: Açıklama (log için)
        """
        # Match: IPv4 + TCP + belirli flag
        match = self.parser.OFPMatch(
            eth_type=0x0800,      # IPv4
            ip_proto=6,           # TCP
            tcp_flags=(tcp_flags, flag_mask)
        )
        
        # Actions: Controller'a kopyala + normal iletim
        # OFPP_CONTROLLER ile paketi controller'a gönder
        # OFPP_TABLE ile normal flow işlemine devam et
        actions = [
            self.parser.OFPActionOutput(
                self.ofproto.OFPP_CONTROLLER,
                self.ofproto.OFPCML_NO_BUFFER
            )
        ]
        
        # Yüksek öncelik (normal L2 kurallarından önce)
        self.add_flow(
            priority=self.PRIORITY_HIGH,
            match=match,
            actions=actions
        )
        
        logger.debug(f"TCP {description} monitoring flow added")
    
    def add_tcp_syn_monitoring(self) -> None:
        """
        Sadece TCP SYN paketlerini izle (hafif versiyon).
        SYN flood tespiti için yeterli.
        """
        dpid = self.datapath.id
        
        # SYN paketleri (SYN=1, ACK=0)
        match = self.parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_flags=(0x02, 0x12)  # SYN set, ACK not set
        )
        
        actions = [
            self.parser.OFPActionOutput(
                self.ofproto.OFPP_CONTROLLER,
                self.ofproto.OFPCML_NO_BUFFER
            )
        ]
        
        self.add_flow(
            priority=self.PRIORITY_HIGH,
            match=match,
            actions=actions
        )
        
        logger.info(f"TCP SYN monitoring enabled for dpid={dpid}")
    
    def add_l2_forwarding_flow(self,
                                dst_mac: str,
                                out_port: int,
                                idle_timeout: int = 300) -> None:
        """
        L2 yönlendirme kuralı ekler.
        
        Args:
            dst_mac: Hedef MAC adresi
            out_port: Çıkış portu
            idle_timeout: Boşta kalma süresi
        """
        match = self.parser.OFPMatch(eth_dst=dst_mac)
        actions = [self.parser.OFPActionOutput(out_port)]
        
        self.add_flow(
            priority=self.PRIORITY_NORMAL,
            match=match,
            actions=actions,
            idle_timeout=idle_timeout
        )
        
        # MAC tablosunu güncelle
        self.mac_table[dst_mac] = out_port
        logger.debug(f"L2 flow: {dst_mac} -> port {out_port}")
    
    def add_l3_forwarding_flow(self,
                                dst_ip: str,
                                out_port: int,
                                src_ip: str = None,
                                idle_timeout: int = 300) -> None:
        """
        L3 yönlendirme kuralı ekler.
        
        Args:
            dst_ip: Hedef IP adresi
            out_port: Çıkış portu
            src_ip: Kaynak IP adresi (opsiyonel)
            idle_timeout: Boşta kalma süresi
        """
        match_dict = {
            'eth_type': 0x0800,  # IPv4
            'ipv4_dst': dst_ip
        }
        
        if src_ip:
            match_dict['ipv4_src'] = src_ip
        
        match = self.parser.OFPMatch(**match_dict)
        actions = [self.parser.OFPActionOutput(out_port)]
        
        self.add_flow(
            priority=self.PRIORITY_NORMAL,
            match=match,
            actions=actions,
            idle_timeout=idle_timeout
        )
        logger.debug(f"L3 flow: {src_ip} -> {dst_ip} via port {out_port}")
    
    def block_ip(self, ip_address: str, direction: str = "both") -> None:
        """
        IP adresini engeller.
        
        Args:
            ip_address: Engellenecek IP
            direction: "src", "dst" veya "both"
        """
        if direction in ("src", "both"):
            match = self.parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=ip_address
            )
            # Drop action (boş aksiyon listesi)
            self.add_flow(
                priority=self.PRIORITY_CRITICAL,
                match=match,
                actions=[]
            )
            logger.warning(f"Blocked source IP: {ip_address}")
        
        if direction in ("dst", "both"):
            match = self.parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=ip_address
            )
            self.add_flow(
                priority=self.PRIORITY_CRITICAL,
                match=match,
                actions=[]
            )
            logger.warning(f"Blocked destination IP: {ip_address}")
    
    def unblock_ip(self, ip_address: str) -> None:
        """
        IP engelini kaldırır.
        
        Args:
            ip_address: Engeli kaldırılacak IP
        """
        # Kaynak engeli kaldır
        match = self.parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_address
        )
        self.delete_flow(match)
        
        # Hedef engeli kaldır
        match = self.parser.OFPMatch(
            eth_type=0x0800,
            ipv4_dst=ip_address
        )
        self.delete_flow(match)
        
        logger.info(f"Unblocked IP: {ip_address}")
    
    def rate_limit_ip(self, 
                       ip_address: str,
                       meter_id: int,
                       rate_kbps: int) -> None:
        """
        IP için hız sınırı uygular (meter kullanarak).
        
        Args:
            ip_address: Hız sınırlanacak IP
            meter_id: Meter ID
            rate_kbps: Maksimum hız (Kbps)
        """
        # Meter oluştur
        bands = [
            self.parser.OFPMeterBandDrop(
                rate=rate_kbps,
                burst_size=rate_kbps // 10
            )
        ]
        
        meter_mod = self.parser.OFPMeterMod(
            datapath=self.datapath,
            command=self.ofproto.OFPMC_ADD,
            flags=self.ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        self.datapath.send_msg(meter_mod)
        
        # Meter'ı kullanan flow ekle
        match = self.parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_address
        )
        
        inst = [
            self.parser.OFPInstructionMeter(meter_id),
            self.parser.OFPInstructionActions(
                self.ofproto.OFPIT_APPLY_ACTIONS,
                [self.parser.OFPActionOutput(self.ofproto.OFPP_NORMAL)]
            )
        ]
        
        mod = self.parser.OFPFlowMod(
            datapath=self.datapath,
            priority=self.PRIORITY_HIGH,
            match=match,
            instructions=inst
        )
        self.datapath.send_msg(mod)
        
        logger.info(f"Rate limited {ip_address} to {rate_kbps} Kbps")
    
    def block_tcp_syn_flood(self, 
                            src_ip: str = None,
                            dst_ip: str = None,
                            dst_port: int = None) -> None:
        """
        TCP SYN flood saldırısını engeller.
        
        Args:
            src_ip: Kaynak IP (opsiyonel)
            dst_ip: Hedef IP (opsiyonel)
            dst_port: Hedef port (opsiyonel)
        """
        match_dict = {
            'eth_type': 0x0800,
            'ip_proto': 6,  # TCP
            'tcp_flags': 0x02  # SYN flag
        }
        
        if src_ip:
            match_dict['ipv4_src'] = src_ip
        if dst_ip:
            match_dict['ipv4_dst'] = dst_ip
        if dst_port:
            match_dict['tcp_dst'] = dst_port
        
        match = self.parser.OFPMatch(**match_dict)
        
        # Drop
        self.add_flow(
            priority=self.PRIORITY_CRITICAL,
            match=match,
            actions=[],
            hard_timeout=60  # 60 saniye sonra kaldır
        )
        
        logger.warning(f"TCP SYN flood blocked: src={src_ip}, dst={dst_ip}:{dst_port}")
    
    def get_mac_table(self) -> Dict[str, int]:
        """MAC tablosunu döndürür"""
        return self.mac_table.copy()
    
    def clear_mac_table(self) -> None:
        """MAC tablosunu temizler"""
        self.mac_table.clear()
        logger.info("MAC table cleared")
    
    def flood_packet(self, msg) -> None:
        """
        Paketi tüm portlara flood eder.
        
        Args:
            msg: OpenFlow mesajı
        """
        actions = [self.parser.OFPActionOutput(self.ofproto.OFPP_FLOOD)]
        data = msg.data if msg.buffer_id == self.ofproto.OFP_NO_BUFFER else None
        
        out = self.parser.OFPPacketOut(
            datapath=self.datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=data
        )
        self.datapath.send_msg(out)
    
    def send_packet(self, msg, out_port: int) -> None:
        """
        Paketi belirtilen porta gönderir.
        
        Args:
            msg: OpenFlow mesajı
            out_port: Çıkış portu
        """
        actions = [self.parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == self.ofproto.OFP_NO_BUFFER else None
        
        out = self.parser.OFPPacketOut(
            datapath=self.datapath,
            buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'],
            actions=actions,
            data=data
        )
        self.datapath.send_msg(out)

