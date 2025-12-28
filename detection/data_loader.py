#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Dataset Loader
CICFlowMeter formatındaki TCP SYN flood dataset'lerini yükler

Desteklenen formatlar:
- CICFlowMeter CSV
- TCP-SYNC DATASET.csv
"""

import os
import pandas as pd
import numpy as np
from typing import Tuple, Optional, List, Dict


class DatasetLoader:
    """
    TCP SYN Flood Dataset Yükleyici
    
    CICFlowMeter formatındaki CSV dosyalarını yükler ve
    ML modeli için uygun formata dönüştürür.
    """
    
    # CICFlowMeter kolon eşlemeleri
    COLUMN_MAPPING = {
        # Bizim öznitelikler → CICFlowMeter kolonları
        'packets_per_second': 'Flow Pkts/s',
        'bytes_per_second': 'Flow Byts/s',
        'flow_count': None,  # Hesaplanacak
        'syn_ratio': None,   # SYN Flag Cnt / toplam flag'lerden
        'syn_ack_ratio': None,  # Hesaplanacak
        'small_packet_ratio': None,  # Hesaplanacak
        'unique_src_ips': None,  # Dataset'te yok
        'src_ip_entropy': None,  # Dataset'te yok
        'avg_packet_size': 'Pkt Len Mean',
        'total_dropped': None,  # Dataset'te yok
        'total_errors': None,   # Dataset'te yok
    }
    
    # Kullanılabilir CICFlowMeter kolonları
    CICFLOW_FEATURES = [
        'Flow Duration',
        'Tot Fwd Pkts',
        'Tot Bwd Pkts',
        'TotLen Fwd Pkts',
        'TotLen Bwd Pkts',
        'Fwd Pkt Len Max',
        'Fwd Pkt Len Min',
        'Fwd Pkt Len Mean',
        'Fwd Pkt Len Std',
        'Bwd Pkt Len Max',
        'Bwd Pkt Len Min',
        'Bwd Pkt Len Mean',
        'Bwd Pkt Len Std',
        'Flow Byts/s',
        'Flow Pkts/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Flow IAT Max',
        'Flow IAT Min',
        'Fwd IAT Tot',
        'Fwd IAT Mean',
        'Fwd IAT Std',
        'Fwd IAT Max',
        'Fwd IAT Min',
        'Bwd IAT Tot',
        'Bwd IAT Mean',
        'Bwd IAT Std',
        'Bwd IAT Max',
        'Bwd IAT Min',
        'Fwd PSH Flags',
        'Bwd PSH Flags',
        'Fwd URG Flags',
        'Bwd URG Flags',
        'Fwd Header Len',
        'Bwd Header Len',
        'Fwd Pkts/s',
        'Bwd Pkts/s',
        'Pkt Len Min',
        'Pkt Len Max',
        'Pkt Len Mean',
        'Pkt Len Std',
        'Pkt Len Var',
        'FIN Flag Cnt',
        'SYN Flag Cnt',
        'RST Flag Cnt',
        'PSH Flag Cnt',
        'ACK Flag Cnt',
        'URG Flag Cnt',
        'Down/Up Ratio',
        'Pkt Size Avg',
        'Fwd Seg Size Avg',
        'Bwd Seg Size Avg',
        'Init Fwd Win Byts',
        'Init Bwd Win Byts',
        'Fwd Act Data Pkts',
        'Fwd Seg Size Min',
        'Active Mean',
        'Active Std',
        'Active Max',
        'Active Min',
        'Idle Mean',
        'Idle Std',
        'Idle Max',
        'Idle Min',
    ]
    
    def __init__(self, csv_path: str):
        """
        Args:
            csv_path: CSV dosya yolu
        """
        self.csv_path = csv_path
        self.df = None
        self.label_column = 'Label'
        
    def load(self) -> pd.DataFrame:
        """CSV dosyasını yükle"""
        print(f"[DataLoader] Loading: {self.csv_path}")
        
        self.df = pd.read_csv(self.csv_path, low_memory=False)
        
        # Kolon isimlerini temizle (boşlukları kaldır)
        self.df.columns = self.df.columns.str.strip()
        
        print(f"[DataLoader] Loaded {len(self.df)} rows, {len(self.df.columns)} columns")
        print(f"[DataLoader] Labels: {self.df[self.label_column].value_counts().to_dict()}")
        
        return self.df
    
    def get_features_and_labels(self, feature_set: str = "custom") -> Tuple[np.ndarray, np.ndarray]:
        """
        Öznitelik matrisi ve etiketleri döndür.
        
        Args:
            feature_set: "custom" (bizim 11 öznitelik) veya "cicflow" (tüm CIC öznitelikleri)
            
        Returns:
            X, y: Öznitelik matrisi ve etiketler
        """
        if self.df is None:
            self.load()
        
        if feature_set == "custom":
            X = self._extract_custom_features()
        else:
            X = self._extract_cicflow_features()
        
        # Etiketleri sayısala çevir
        y = self._convert_labels()
        
        return X, y
    
    def _extract_custom_features(self) -> np.ndarray:
        """Bizim 11 özniteliği çıkar"""
        df = self.df
        
        # packets_per_second
        pps = df['Flow Pkts/s'].fillna(0).values
        
        # bytes_per_second
        bps = df['Flow Byts/s'].fillna(0).values
        
        # flow_count (sabit 1, her satır bir flow)
        flow_count = np.ones(len(df))
        
        # syn_ratio = SYN Flag Cnt / (SYN + ACK + FIN + RST + PSH)
        total_flags = (df['SYN Flag Cnt'].fillna(0) + 
                      df['ACK Flag Cnt'].fillna(0) + 
                      df['FIN Flag Cnt'].fillna(0) + 
                      df['RST Flag Cnt'].fillna(0) + 
                      df['PSH Flag Cnt'].fillna(0))
        syn_ratio = np.where(total_flags > 0, 
                            df['SYN Flag Cnt'].fillna(0) / total_flags, 
                            0)
        
        # syn_ack_ratio (ACK ile birlikte SYN olduğunda)
        # Basitleştirme: ACK / SYN
        syn_count = df['SYN Flag Cnt'].fillna(0)
        ack_count = df['ACK Flag Cnt'].fillna(0)
        syn_ack_ratio = np.where(syn_count > 0, ack_count / syn_count, 0)
        syn_ack_ratio = np.clip(syn_ack_ratio, 0, 1)
        
        # small_packet_ratio (küçük paket oranı)
        # Fwd Pkt Len Mean < 100 ise küçük paket
        avg_pkt_len = df['Pkt Len Mean'].fillna(0).values
        small_packet_ratio = np.where(avg_pkt_len < 100, 1.0, 
                                     np.where(avg_pkt_len < 200, 0.5, 0.1))
        
        # unique_src_ips (dataset'te yok, tahmini)
        # Flow duration kısa + yüksek pps = muhtemelen çok kaynak
        flow_duration = df['Flow Duration'].fillna(0).values
        unique_src_ips = np.where((flow_duration < 1000) & (pps > 1000), 
                                  100, 
                                  np.random.randint(1, 20, len(df)))
        
        # src_ip_entropy (tahmini)
        # Yüksek SYN ratio = muhtemelen yüksek entropy (spoofed IP)
        src_ip_entropy = 1.0 + syn_ratio * 5.0
        
        # avg_packet_size
        avg_packet_size = avg_pkt_len
        
        # dropped/errors (dataset'te yok, 0 varsay)
        total_dropped = np.zeros(len(df))
        total_errors = np.zeros(len(df))
        
        # Birleştir
        X = np.column_stack([
            pps,
            bps,
            flow_count,
            syn_ratio,
            syn_ack_ratio,
            small_packet_ratio,
            unique_src_ips,
            src_ip_entropy,
            avg_packet_size,
            total_dropped,
            total_errors
        ])
        
        # NaN ve inf değerleri temizle
        X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=0.0)
        
        print(f"[DataLoader] Extracted {X.shape[1]} custom features")
        
        return X
    
    def _extract_cicflow_features(self) -> np.ndarray:
        """Tüm CICFlowMeter özniteliklerini çıkar"""
        # Mevcut kolonları filtrele
        available = [col for col in self.CICFLOW_FEATURES if col in self.df.columns]
        
        X = self.df[available].fillna(0).values
        
        # NaN ve inf değerleri temizle
        X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=0.0)
        
        print(f"[DataLoader] Extracted {X.shape[1]} CICFlow features")
        
        return X
    
    def _convert_labels(self) -> np.ndarray:
        """Etiketleri 0/1 formatına çevir"""
        labels = self.df[self.label_column].str.strip().str.lower()
        
        # Normal = 0, Saldırı = 1
        y = np.where(labels == 'normal', 0, 1)
        
        n_normal = np.sum(y == 0)
        n_attack = np.sum(y == 1)
        print(f"[DataLoader] Labels: {n_normal} normal, {n_attack} attack")
        
        return y
    
    def get_stats(self) -> Dict:
        """Dataset istatistikleri"""
        if self.df is None:
            self.load()
        
        return {
            'total_rows': len(self.df),
            'columns': len(self.df.columns),
            'labels': self.df[self.label_column].value_counts().to_dict(),
            'numeric_columns': len(self.df.select_dtypes(include=[np.number]).columns)
        }


def load_tcp_syn_dataset(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    TCP SYN flood dataset'ini yükle.
    
    Args:
        csv_path: CSV dosya yolu
        
    Returns:
        X, y: Öznitelik matrisi ve etiketler
    """
    loader = DatasetLoader(csv_path)
    return loader.get_features_and_labels(feature_set="custom")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python data_loader.py <csv_path>")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    
    loader = DatasetLoader(csv_path)
    loader.load()
    
    print("\nStats:")
    for key, value in loader.get_stats().items():
        print(f"  {key}: {value}")
    
    X, y = loader.get_features_and_labels()
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Labels shape: {y.shape}")

