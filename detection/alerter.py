#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Alerter
Alarm ve loglama sistemi

Bu modül:
- Saldırı alarmları oluşturur
- Log dosyasına kaydeder
- Konsola renkli çıktı verir
- İstatistik tutar
"""

import time
import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Callable
from enum import Enum
from datetime import datetime
from collections import defaultdict

from .detector import DetectionResult, AttackType


class AlertLevel(Enum):
    """Alarm seviyeleri"""
    INFO = "INFO"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """Alarm nesnesi"""
    alert_id: str
    timestamp: float
    level: AlertLevel
    dpid: int
    attack_type: AttackType
    message: str
    details: Dict
    
    def to_dict(self) -> Dict:
        """Sözlük olarak döndür"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp,
            'datetime': datetime.fromtimestamp(self.timestamp).isoformat(),
            'level': self.level.value,
            'dpid': self.dpid,
            'attack_type': self.attack_type.value,
            'message': self.message,
            'details': self.details
        }
    
    def to_json(self) -> str:
        """JSON string olarak döndür"""
        return json.dumps(self.to_dict(), indent=2)


class Alerter:
    """
    Alarm Yöneticisi
    
    Saldırı tespitlerini alarmlar haline getirir ve
    çeşitli kanallara bildirir.
    """
    
    # ANSI renk kodları
    COLORS = {
        AlertLevel.INFO: '\033[94m',      # Mavi
        AlertLevel.WARNING: '\033[93m',   # Sarı
        AlertLevel.ALERT: '\033[91m',     # Kırmızı
        AlertLevel.CRITICAL: '\033[95m',  # Mor
        'RESET': '\033[0m',
        'BOLD': '\033[1m'
    }
    
    def __init__(self, log_file: Optional[str] = None, 
                 enable_console: bool = True,
                 enable_colors: bool = True):
        """
        Args:
            log_file: Log dosyası yolu
            enable_console: Konsola yazdır
            enable_colors: Renkli çıktı
        """
        self.log_file = log_file
        self.enable_console = enable_console
        self.enable_colors = enable_colors
        
        # Alarm sayacı
        self._alert_counter = 0
        
        # Alarm geçmişi
        self._alerts: List[Alert] = []
        
        # İstatistikler
        self._stats = {
            'total_alerts': 0,
            'by_level': defaultdict(int),
            'by_attack_type': defaultdict(int),
            'by_dpid': defaultdict(int)
        }
        
        # Callback fonksiyonları
        self._callbacks: List[Callable[[Alert], None]] = []
        
        # Log dosyasını oluştur
        if self.log_file:
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
    
    def create_alert(self, detection: DetectionResult) -> Optional[Alert]:
        """
        Tespit sonucundan alarm oluştur.
        
        Args:
            detection: Tespit sonucu
            
        Returns:
            Alert veya None (saldırı yoksa)
        """
        if not detection.is_attack:
            return None
        
        # Alarm seviyesini belirle
        level = self._severity_to_level(detection.severity)
        
        # Mesaj oluştur
        message = self._create_message(detection)
        
        # Alarm ID oluştur
        self._alert_counter += 1
        alert_id = f"ALERT-{self._alert_counter:06d}"
        
        # Alarm oluştur
        alert = Alert(
            alert_id=alert_id,
            timestamp=detection.timestamp,
            level=level,
            dpid=detection.dpid,
            attack_type=detection.attack_type,
            message=message,
            details={
                'confidence': detection.confidence,
                'severity': detection.severity,
                'triggered_rules': detection.triggered_rules,
                **detection.details
            }
        )
        
        # Kaydet ve bildir
        self._process_alert(alert)
        
        return alert
    
    def _severity_to_level(self, severity: str) -> AlertLevel:
        """Şiddeti alarm seviyesine çevir"""
        mapping = {
            'critical': AlertLevel.CRITICAL,
            'high': AlertLevel.ALERT,
            'medium': AlertLevel.WARNING,
            'low': AlertLevel.INFO
        }
        return mapping.get(severity, AlertLevel.INFO)
    
    def _create_message(self, detection: DetectionResult) -> str:
        """Alarm mesajı oluştur"""
        attack_name = detection.attack_type.value.upper().replace('_', ' ')
        
        msg_parts = [
            f"{attack_name} detected on switch {detection.dpid}",
            f"Confidence: {detection.confidence:.1%}",
        ]
        
        # Önemli detayları ekle
        if 'pps' in detection.details:
            msg_parts.append(f"Rate: {detection.details['pps']:.0f} pps")
        
        if 'syn_ratio' in detection.details and detection.details['syn_ratio'] > 0:
            msg_parts.append(f"SYN ratio: {detection.details['syn_ratio']:.1%}")
        
        return " | ".join(msg_parts)
    
    def _process_alert(self, alert: Alert) -> None:
        """Alarmı işle"""
        # Listeye ekle
        self._alerts.append(alert)
        
        # İstatistikleri güncelle
        self._stats['total_alerts'] += 1
        self._stats['by_level'][alert.level.value] += 1
        self._stats['by_attack_type'][alert.attack_type.value] += 1
        self._stats['by_dpid'][alert.dpid] += 1
        
        # Konsola yazdır
        if self.enable_console:
            self._print_alert(alert)
        
        # Dosyaya yaz
        if self.log_file:
            self._log_alert(alert)
        
        # Callback'leri çağır
        for callback in self._callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def _print_alert(self, alert: Alert) -> None:
        """Alarmı konsola yazdır"""
        if self.enable_colors:
            color = self.COLORS.get(alert.level, '')
            reset = self.COLORS['RESET']
            bold = self.COLORS['BOLD']
        else:
            color = reset = bold = ''
        
        timestamp = datetime.fromtimestamp(alert.timestamp).strftime('%H:%M:%S')
        
        # Seviyeye göre sembol
        symbols = {
            AlertLevel.INFO: '[i]',
            AlertLevel.WARNING: '[!]',
            AlertLevel.ALERT: '[!!]',
            AlertLevel.CRITICAL: '[!!!]'
        }
        symbol = symbols.get(alert.level, '*')
        
        print(f"\n{color}{bold}{'='*70}{reset}")
        print(f"{color}{symbol} [{alert.level.value}] {timestamp} - {alert.alert_id}{reset}")
        print(f"{color}{bold}{alert.message}{reset}")
        print(f"{color}Triggered rules: {', '.join(alert.details.get('triggered_rules', []))}{reset}")
        print(f"{color}{'='*70}{reset}\n")
    
    def _log_alert(self, alert: Alert) -> None:
        """Alarmı dosyaya kaydet"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(alert.to_json() + '\n')
        except Exception as e:
            print(f"Error writing to log file: {e}")
    
    def add_callback(self, callback: Callable[[Alert], None]) -> None:
        """Alarm callback'i ekle"""
        self._callbacks.append(callback)
    
    def remove_callback(self, callback: Callable[[Alert], None]) -> None:
        """Alarm callback'ini kaldır"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
    
    def get_alerts(self, 
                   dpid: Optional[int] = None,
                   level: Optional[AlertLevel] = None,
                   attack_type: Optional[AttackType] = None,
                   since: Optional[float] = None) -> List[Alert]:
        """
        Filtrelenmiş alarmları döndür.
        
        Args:
            dpid: Switch ID filtresi
            level: Seviye filtresi
            attack_type: Saldırı tipi filtresi
            since: Bu timestamp'den sonraki alarmlar
            
        Returns:
            Filtrelenmiş alarm listesi
        """
        alerts = self._alerts
        
        if dpid is not None:
            alerts = [a for a in alerts if a.dpid == dpid]
        
        if level is not None:
            alerts = [a for a in alerts if a.level == level]
        
        if attack_type is not None:
            alerts = [a for a in alerts if a.attack_type == attack_type]
        
        if since is not None:
            alerts = [a for a in alerts if a.timestamp >= since]
        
        return alerts
    
    def get_recent_alerts(self, count: int = 10) -> List[Alert]:
        """Son N alarmı döndür"""
        return self._alerts[-count:]
    
    def get_stats(self) -> Dict:
        """İstatistikleri döndür"""
        return {
            'total_alerts': self._stats['total_alerts'],
            'by_level': dict(self._stats['by_level']),
            'by_attack_type': dict(self._stats['by_attack_type']),
            'by_dpid': dict(self._stats['by_dpid']),
            'first_alert': self._alerts[0].timestamp if self._alerts else None,
            'last_alert': self._alerts[-1].timestamp if self._alerts else None
        }
    
    def print_summary(self) -> None:
        """Özet yazdır"""
        stats = self.get_stats()
        
        print("\n" + "="*50)
        print("  ALERT SUMMARY")
        print("="*50)
        print(f"  Total alerts: {stats['total_alerts']}")
        print(f"\n  By Level:")
        for level, count in stats['by_level'].items():
            print(f"    {level}: {count}")
        print(f"\n  By Attack Type:")
        for atype, count in stats['by_attack_type'].items():
            print(f"    {atype}: {count}")
        print(f"\n  By Switch (dpid):")
        for dpid, count in stats['by_dpid'].items():
            print(f"    dpid={dpid}: {count}")
        print("="*50 + "\n")
    
    def clear(self) -> None:
        """Alarm geçmişini temizle"""
        self._alerts.clear()
        self._stats = {
            'total_alerts': 0,
            'by_level': defaultdict(int),
            'by_attack_type': defaultdict(int),
            'by_dpid': defaultdict(int)
        }


def create_default_alerter(log_dir: str = "logs") -> Alerter:
    """Varsayılan yapılandırmayla Alerter oluştur"""
    log_file = os.path.join(log_dir, "attack_alerts.json")
    return Alerter(log_file=log_file, enable_console=True, enable_colors=True)

