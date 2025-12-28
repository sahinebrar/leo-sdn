#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Attack Detector
Saldırı tespit motoru

Bu modül:
- Eşik tabanlı tespit (Threshold-based)
- İstatistiksel anomali tespiti
- Çoklu kriter değerlendirmesi
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum
from collections import defaultdict

from .feature_extractor import FlowFeatures


class AttackType(Enum):
    """Saldırı tipleri"""
    NONE = "none"
    SYN_FLOOD = "syn_flood"
    ACK_FLOOD = "ack_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    SLOWLORIS = "slowloris"
    UNKNOWN = "unknown"


@dataclass
class DetectionResult:
    """Tespit sonucu"""
    dpid: int
    timestamp: float
    is_attack: bool
    attack_type: AttackType
    confidence: float          # 0.0 - 1.0
    severity: str              # low, medium, high, critical
    details: Dict
    triggered_rules: List[str]
    
    def __str__(self) -> str:
        if self.is_attack:
            return (f"[ATTACK] dpid={self.dpid} type={self.attack_type.value} "
                    f"confidence={self.confidence:.2f} severity={self.severity}")
        return f"[NORMAL] dpid={self.dpid}"


@dataclass 
class DetectionThresholds:
    """Tespit eşikleri"""
    # Paket hızı eşikleri
    pps_warning: float = 5000      # Paket/saniye - uyarı
    pps_critical: float = 10000    # Paket/saniye - kritik
    
    # SYN oranı eşikleri
    syn_ratio_warning: float = 0.5   # %50 SYN
    syn_ratio_critical: float = 0.8  # %80 SYN
    
    # SYN-ACK oranı (düşük oran = saldırı)
    syn_ack_ratio_min: float = 0.3   # Normal: SYN'lerin %30'u ACK almalı
    
    # Küçük paket oranı
    small_packet_ratio_warning: float = 0.7
    small_packet_ratio_critical: float = 0.9
    
    # Benzersiz kaynak IP
    unique_src_warning: int = 100
    unique_src_critical: int = 500
    
    # Entropy eşikleri
    src_entropy_warning: float = 4.0   # Yüksek entropy = spoofed IP
    src_entropy_critical: float = 6.0
    
    # Ortalama paket boyutu
    avg_packet_size_min: float = 100   # SYN paketleri küçüktür
    
    # Hata ve drop oranları
    drop_ratio_warning: float = 0.01   # %1 drop
    drop_ratio_critical: float = 0.05  # %5 drop


class AttackDetector:
    """
    Saldırı Tespit Motoru
    
    Çoklu kriter kullanarak TCP flood saldırılarını tespit eder.
    """
    
    def __init__(self, thresholds: Optional[DetectionThresholds] = None):
        """
        Args:
            thresholds: Özel eşikler (None ise varsayılan kullanılır)
        """
        self.thresholds = thresholds or DetectionThresholds()
        
        # Her switch için son tespit sonucu
        self._last_results: Dict[int, DetectionResult] = {}
        
        # Saldırı geçmişi
        self._attack_history: Dict[int, List[DetectionResult]] = defaultdict(list)
        
        # Baseline (normal trafik profili)
        self._baseline: Dict[int, Dict] = {}
        
        # Callback fonksiyonları
        self._on_attack_detected = None
        self._on_attack_ended = None
    
    # Minimum paket eşiği (false positive önleme)
    MIN_PACKETS_FOR_DETECTION = 1000  # En az 1000 paket olmalı
    MIN_PPS_FOR_DETECTION = 100       # En az 100 pps olmalı
    
    def detect(self, features: FlowFeatures) -> DetectionResult:
        """
        Özniteliklere göre saldırı tespiti yap.
        
        Args:
            features: Çıkarılan öznitelikler
            
        Returns:
            DetectionResult: Tespit sonucu
        """
        dpid = features.dpid
        triggered_rules = []
        scores = []
        details = {}
        
        # Minimum trafik kontrolü (false positive önleme)
        if features.packets_per_second < self.MIN_PPS_FOR_DETECTION:
            return DetectionResult(
                dpid=dpid,
                timestamp=time.time(),
                is_attack=False,
                attack_type=AttackType.NONE,
                confidence=0.0,
                severity="none",
                details={'reason': 'Low traffic - skipping detection'},
                triggered_rules=[]
            )
        
        # 1. Paket hızı kontrolü
        pps_score, pps_rules = self._check_packet_rate(features)
        scores.append(pps_score)
        triggered_rules.extend(pps_rules)
        details['pps'] = features.packets_per_second
        
        # 2. SYN oranı kontrolü
        syn_score, syn_rules = self._check_syn_ratio(features)
        scores.append(syn_score)
        triggered_rules.extend(syn_rules)
        details['syn_ratio'] = features.syn_ratio
        
        # 3. SYN-ACK oranı kontrolü (düşük = saldırı)
        synack_score, synack_rules = self._check_syn_ack_ratio(features)
        scores.append(synack_score)
        triggered_rules.extend(synack_rules)
        details['syn_ack_ratio'] = features.syn_ack_ratio
        
        # 4. Küçük paket oranı kontrolü
        small_score, small_rules = self._check_small_packet_ratio(features)
        scores.append(small_score)
        triggered_rules.extend(small_rules)
        details['small_packet_ratio'] = features.small_packet_ratio
        
        # 5. Kaynak IP çeşitliliği kontrolü
        src_score, src_rules = self._check_source_diversity(features)
        scores.append(src_score)
        triggered_rules.extend(src_rules)
        details['unique_src_ips'] = features.unique_src_ips
        
        # 6. Entropy kontrolü
        entropy_score, entropy_rules = self._check_entropy(features)
        scores.append(entropy_score)
        triggered_rules.extend(entropy_rules)
        details['src_ip_entropy'] = features.src_ip_entropy
        
        # 7. Paket boyutu kontrolü
        size_score, size_rules = self._check_packet_size(features)
        scores.append(size_score)
        triggered_rules.extend(size_rules)
        details['avg_packet_size'] = features.avg_packet_size
        
        # Toplam skor hesapla (ağırlıklı ortalama)
        # Sadece tetiklenen kuralları say (0 olmayan skorlar)
        active_scores = [s for s in scores if s > 0]
        
        if active_scores:
            # Tetiklenen kuralların ortalaması
            confidence = sum(active_scores) / len(active_scores)
            # Tetiklenen kural sayısına göre bonus
            rule_bonus = min(0.2, len(triggered_rules) * 0.05)
            confidence = min(1.0, confidence + rule_bonus)
        else:
            confidence = 0
        
        # Saldırı tespiti
        # En az 3 kural tetiklenmeli VE confidence >= 0.5 VEYA
        # PPS çok yüksekse (>10000) tek başına yeterli
        high_pps = features.packets_per_second > 10000
        is_attack = (confidence >= 0.5 and len(triggered_rules) >= 2) or \
                    (len(triggered_rules) >= 3) or \
                    high_pps
        
        # Saldırı tipini belirle
        attack_type = self._determine_attack_type(features, triggered_rules)
        
        # Şiddeti belirle
        severity = self._determine_severity(confidence, triggered_rules)
        
        # Sonuç oluştur
        result = DetectionResult(
            dpid=dpid,
            timestamp=time.time(),
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            severity=severity,
            details=details,
            triggered_rules=triggered_rules
        )
        
        # Callback'leri çağır
        self._handle_detection(result)
        
        # Sonucu kaydet
        self._last_results[dpid] = result
        if is_attack:
            self._attack_history[dpid].append(result)
        
        return result
    
    def _check_packet_rate(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """Paket hızı kontrolü"""
        pps = features.packets_per_second
        rules = []
        
        if pps >= self.thresholds.pps_critical:
            rules.append(f"HIGH_PPS:{pps:.0f}")
            return 1.0, rules
        elif pps >= self.thresholds.pps_warning:
            rules.append(f"ELEVATED_PPS:{pps:.0f}")
            return 0.6, rules
        
        return 0.0, rules
    
    def _check_syn_ratio(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """SYN paket oranı kontrolü"""
        ratio = features.syn_ratio
        rules = []
        
        if ratio >= self.thresholds.syn_ratio_critical:
            rules.append(f"HIGH_SYN_RATIO:{ratio:.2f}")
            return 1.0, rules
        elif ratio >= self.thresholds.syn_ratio_warning:
            rules.append(f"ELEVATED_SYN_RATIO:{ratio:.2f}")
            return 0.6, rules
        
        return 0.0, rules
    
    def _check_syn_ack_ratio(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """SYN-ACK oranı kontrolü (düşük oran = yanıtsız SYN'ler = saldırı)"""
        # SYN var ama SYN-ACK yok = saldırı belirtisi
        if features.syn_count > 100:  # Yeterli SYN varsa kontrol et
            ratio = features.syn_ack_ratio
            rules = []
            
            if ratio < self.thresholds.syn_ack_ratio_min:
                rules.append(f"LOW_SYN_ACK_RATIO:{ratio:.2f}")
                return 0.8, rules
        
        return 0.0, []
    
    def _check_small_packet_ratio(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """Küçük paket oranı kontrolü"""
        ratio = features.small_packet_ratio
        rules = []
        
        if ratio >= self.thresholds.small_packet_ratio_critical:
            rules.append(f"HIGH_SMALL_PACKET_RATIO:{ratio:.2f}")
            return 1.0, rules
        elif ratio >= self.thresholds.small_packet_ratio_warning:
            rules.append(f"ELEVATED_SMALL_PACKET_RATIO:{ratio:.2f}")
            return 0.5, rules
        
        return 0.0, rules
    
    def _check_source_diversity(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """Kaynak IP çeşitliliği kontrolü (spoofing tespiti)"""
        unique = features.unique_src_ips
        rules = []
        
        if unique >= self.thresholds.unique_src_critical:
            rules.append(f"HIGH_SRC_DIVERSITY:{unique}")
            return 1.0, rules
        elif unique >= self.thresholds.unique_src_warning:
            rules.append(f"ELEVATED_SRC_DIVERSITY:{unique}")
            return 0.5, rules
        
        return 0.0, rules
    
    def _check_entropy(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """Kaynak IP entropy kontrolü (yüksek = rastgele IP = spoofing)"""
        entropy = features.src_ip_entropy
        rules = []
        
        if entropy >= self.thresholds.src_entropy_critical:
            rules.append(f"HIGH_SRC_ENTROPY:{entropy:.2f}")
            return 1.0, rules
        elif entropy >= self.thresholds.src_entropy_warning:
            rules.append(f"ELEVATED_SRC_ENTROPY:{entropy:.2f}")
            return 0.5, rules
        
        return 0.0, rules
    
    def _check_packet_size(self, features: FlowFeatures) -> Tuple[float, List[str]]:
        """Ortalama paket boyutu kontrolü"""
        avg_size = features.avg_packet_size
        rules = []
        
        # SYN paketleri küçüktür (~60 byte)
        if avg_size > 0 and avg_size < self.thresholds.avg_packet_size_min:
            rules.append(f"LOW_AVG_PACKET_SIZE:{avg_size:.0f}")
            return 0.6, rules
        
        return 0.0, rules
    
    def _determine_attack_type(self, features: FlowFeatures, 
                               triggered_rules: List[str]) -> AttackType:
        """Saldırı tipini belirle"""
        rule_str = ' '.join(triggered_rules)
        
        # SYN flood belirtileri
        # 1. SYN ratio yüksek
        # 2. Küçük paketler (SYN ~60 byte)
        # 3. Yüksek PPS
        if features.syn_ratio > 0.3:
            return AttackType.SYN_FLOOD
        
        if 'SYN' in rule_str:
            return AttackType.SYN_FLOOD
        
        # Küçük paket + yüksek hız = muhtemelen SYN flood
        if features.avg_packet_size < 100 and features.packets_per_second > 5000:
            return AttackType.SYN_FLOOD
        
        # ACK flood belirtileri
        if features.ack_count > features.syn_count * 2 and features.ack_count > 1000:
            return AttackType.ACK_FLOOD
        
        # Genel flood
        if 'HIGH_PPS' in rule_str or 'ELEVATED_PPS' in rule_str:
            return AttackType.SYN_FLOOD  # Varsayılan olarak SYN flood kabul et
        
        return AttackType.NONE
    
    def _determine_severity(self, confidence: float, 
                           triggered_rules: List[str]) -> str:
        """Saldırı şiddetini belirle"""
        # PPS değerini kontrol et
        pps_value = 0
        for rule in triggered_rules:
            if 'PPS:' in rule:
                try:
                    pps_value = float(rule.split(':')[1])
                except:
                    pass
        
        # PPS bazlı severity
        if pps_value > 30000 or confidence >= 0.9:
            return "critical"
        elif pps_value > 20000 or confidence >= 0.8:
            return "high"
        elif pps_value > 10000 or confidence >= 0.7:
            return "medium"
        elif len(triggered_rules) >= 2:
            return "low"
        return "none"
    
    def _handle_detection(self, result: DetectionResult) -> None:
        """Tespit sonucunu işle ve callback'leri çağır"""
        dpid = result.dpid
        prev_result = self._last_results.get(dpid)
        
        # Yeni saldırı başladı
        if result.is_attack and (not prev_result or not prev_result.is_attack):
            if self._on_attack_detected:
                self._on_attack_detected(result)
        
        # Saldırı bitti
        elif not result.is_attack and prev_result and prev_result.is_attack:
            if self._on_attack_ended:
                self._on_attack_ended(result)
    
    def set_on_attack_detected(self, callback) -> None:
        """Saldırı tespit edildiğinde çağrılacak fonksiyonu ayarla"""
        self._on_attack_detected = callback
    
    def set_on_attack_ended(self, callback) -> None:
        """Saldırı bittiğinde çağrılacak fonksiyonu ayarla"""
        self._on_attack_ended = callback
    
    def get_last_result(self, dpid: int) -> Optional[DetectionResult]:
        """Switch'in son tespit sonucunu döndür"""
        return self._last_results.get(dpid)
    
    def get_attack_history(self, dpid: int) -> List[DetectionResult]:
        """Switch'in saldırı geçmişini döndür"""
        return self._attack_history[dpid]
    
    def is_under_attack(self, dpid: int) -> bool:
        """Switch şu anda saldırı altında mı?"""
        result = self._last_results.get(dpid)
        return result.is_attack if result else False
    
    def get_active_attacks(self) -> Dict[int, DetectionResult]:
        """Aktif saldırı altındaki tüm switch'leri döndür"""
        return {
            dpid: result 
            for dpid, result in self._last_results.items() 
            if result.is_attack
        }
    
    def update_thresholds(self, **kwargs) -> None:
        """Eşikleri güncelle"""
        for key, value in kwargs.items():
            if hasattr(self.thresholds, key):
                setattr(self.thresholds, key, value)
    
    def set_baseline(self, dpid: int, features: FlowFeatures) -> None:
        """Normal trafik baseline'ı ayarla"""
        self._baseline[dpid] = {
            'pps': features.packets_per_second,
            'syn_ratio': features.syn_ratio,
            'avg_packet_size': features.avg_packet_size,
            'unique_src_ips': features.unique_src_ips
        }
    
    def reset(self, dpid: Optional[int] = None) -> None:
        """Tespit durumunu sıfırla"""
        if dpid is not None:
            self._last_results.pop(dpid, None)
            self._attack_history[dpid].clear()
        else:
            self._last_results.clear()
            self._attack_history.clear()

