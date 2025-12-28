#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Config Module
YAML konfigürasyon dosyası okuyucu
"""

import os
import yaml
from typing import Any, Dict, Optional


class Config:
    """
    Singleton config yöneticisi.
    YAML dosyasından konfigürasyon yükler ve erişim sağlar.
    """
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls, config_path: str = "configs/config.yaml"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config(config_path)
        return cls._instance
    
    def _load_config(self, config_path: str) -> None:
        """YAML dosyasından konfigürasyonu yükler."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config dosyası bulunamadı: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Nokta notasyonu ile nested değerlere erişim.
        Örnek: config.get('topology.satellites.count')
        
        Args:
            key: Nokta ile ayrılmış anahtar yolu
            default: Varsayılan değer
        
        Returns:
            Bulunan değer veya varsayılan
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Bir bölümün tamamını döndürür.
        
        Args:
            section: Bölüm adı (topology, controller, detection, vb.)
        
        Returns:
            Bölüm içeriği
        """
        return self._config.get(section, {})
    
    @property
    def topology(self) -> Dict[str, Any]:
        """Topoloji konfigürasyonu"""
        return self.get_section('topology')
    
    @property
    def controller(self) -> Dict[str, Any]:
        """Controller konfigürasyonu"""
        return self.get_section('controller')
    
    @property
    def detection(self) -> Dict[str, Any]:
        """Tespit konfigürasyonu"""
        return self.get_section('detection')
    
    @property
    def attack(self) -> Dict[str, Any]:
        """Saldırı konfigürasyonu"""
        return self.get_section('attack')
    
    def __repr__(self) -> str:
        return f"Config({list(self._config.keys())})"


def load_config(config_path: str = "configs/config.yaml") -> Config:
    """Config singleton'ı yükler ve döndürür."""
    return Config(config_path)


if __name__ == "__main__":
    # Test
    config = Config()
    
    print("=== Config Test ===")
    print(f"Satellite count: {config.get('topology.satellites.count')}")
    print(f"Controller port: {config.get('controller.port')}")
    print(f"ML model type: {config.get('detection.ml_model.type')}")
    print(f"Topology section: {config.topology}")

