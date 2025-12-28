#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Machine Learning Detector
Makine öğrenmesi tabanlı saldırı tespit motoru

Bu modül:
- Random Forest sınıflandırıcı
- Gerçek zamanlı tahmin
- Model eğitimi ve kaydetme
"""

import os
import time
import pickle
import numpy as np
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from collections import deque

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. ML detection disabled.")

from .feature_extractor import FlowFeatures
from .detector import AttackType, DetectionResult


@dataclass
class MLConfig:
    """ML model konfigürasyonu"""
    model_type: str = "random_forest"  # random_forest, isolation_forest
    n_estimators: int = 100
    max_depth: int = 10
    min_samples_split: int = 5
    contamination: float = 0.1  # Isolation Forest için
    model_path: str = "models/attack_detector.pkl"
    scaler_path: str = "models/scaler.pkl"


class MLDetector:
    """
    Makine Öğrenmesi Tabanlı Saldırı Tespit
    
    Random Forest veya Isolation Forest kullanarak
    TCP flood saldırılarını tespit eder.
    """
    
    # Öznitelik isimleri
    FEATURE_NAMES = [
        'packets_per_second',
        'bytes_per_second',
        'flow_count',
        'syn_ratio',
        'syn_ack_ratio',
        'small_packet_ratio',
        'unique_src_ips',
        'src_ip_entropy',
        'avg_packet_size',
        'total_dropped',
        'total_errors'
    ]
    
    def __init__(self, config: Optional[MLConfig] = None):
        """
        Args:
            config: ML konfigürasyonu
        """
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn is required for ML detection")
        
        self.config = config or MLConfig()
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Eğitim verisi toplama
        self._training_data: List[Tuple[List[float], int]] = []
        self._collecting_data = False
        
        # Son tahminler (smoothing için)
        self._prediction_history: deque = deque(maxlen=5)
        
        # Callback'ler
        self._on_attack_detected = None
        self._on_attack_ended = None
        
        # Son sonuçlar
        self._last_results: Dict[int, DetectionResult] = {}
        
        # Model yükle (varsa)
        self._load_model()
    
    def _create_model(self):
        """Model oluştur"""
        if self.config.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=self.config.n_estimators,
                max_depth=self.config.max_depth,
                min_samples_split=self.config.min_samples_split,
                random_state=42,
                n_jobs=-1
            )
        elif self.config.model_type == "isolation_forest":
            self.model = IsolationForest(
                n_estimators=self.config.n_estimators,
                contamination=self.config.contamination,
                random_state=42,
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown model type: {self.config.model_type}")
    
    def _load_model(self) -> bool:
        """Kayıtlı modeli yükle"""
        try:
            if os.path.exists(self.config.model_path):
                with open(self.config.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                
                if os.path.exists(self.config.scaler_path):
                    with open(self.config.scaler_path, 'rb') as f:
                        self.scaler = pickle.load(f)
                
                self.is_trained = True
                print(f"[ML] Model loaded from {self.config.model_path}")
                return True
        except Exception as e:
            print(f"[ML] Failed to load model: {e}")
        
        return False
    
    def save_model(self) -> bool:
        """Modeli kaydet"""
        try:
            # Klasör oluştur
            model_dir = os.path.dirname(self.config.model_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir)
            
            with open(self.config.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            with open(self.config.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            print(f"[ML] Model saved to {self.config.model_path}")
            return True
        except Exception as e:
            print(f"[ML] Failed to save model: {e}")
            return False
    
    def extract_features_vector(self, features: FlowFeatures) -> np.ndarray:
        """FlowFeatures'dan öznitelik vektörü çıkar"""
        return np.array([
            features.packets_per_second,
            features.bytes_per_second,
            features.flow_count,
            features.syn_ratio,
            features.syn_ack_ratio,
            features.small_packet_ratio,
            features.unique_src_ips,
            features.src_ip_entropy,
            features.avg_packet_size,
            features.rx_dropped + features.tx_dropped,
            features.rx_errors + features.tx_errors
        ]).reshape(1, -1)
    
    def detect(self, features: FlowFeatures) -> DetectionResult:
        """
        ML ile saldırı tespiti yap.
        
        Args:
            features: Çıkarılan öznitelikler
            
        Returns:
            DetectionResult: Tespit sonucu
        """
        dpid = features.dpid
        
        # Minimum trafik kontrolü
        if features.packets_per_second < 100:
            return DetectionResult(
                dpid=dpid,
                timestamp=time.time(),
                is_attack=False,
                attack_type=AttackType.NONE,
                confidence=0.0,
                severity="none",
                details={'method': 'ml', 'reason': 'Low traffic'},
                triggered_rules=[]
            )
        
        # Model eğitilmemişse varsayılan sonuç
        if not self.is_trained or self.model is None:
            return DetectionResult(
                dpid=dpid,
                timestamp=time.time(),
                is_attack=False,
                attack_type=AttackType.NONE,
                confidence=0.0,
                severity="none",
                details={'method': 'ml', 'reason': 'Model not trained'},
                triggered_rules=['MODEL_NOT_TRAINED']
            )
        
        # Öznitelik vektörü çıkar
        X = self.extract_features_vector(features)
        
        # Normalize et
        X_scaled = self.scaler.transform(X)
        
        # Tahmin
        if self.config.model_type == "random_forest":
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            confidence = max(probabilities)
        else:  # Isolation Forest
            prediction = self.model.predict(X_scaled)[0]
            # -1 = anomaly (attack), 1 = normal
            prediction = 1 if prediction == -1 else 0
            score = self.model.score_samples(X_scaled)[0]
            confidence = abs(score)
        
        # Debug: Yüksek trafikte tahmin bilgisi
        if features.packets_per_second > 10000:
            print(f"[ML DEBUG] dpid={dpid} pps={features.packets_per_second:.0f} "
                  f"pred={prediction} conf={confidence:.2f} "
                  f"syn_ratio={features.syn_ratio:.2f}")
        
        # Smoothing (son 5 tahminin ortalaması)
        self._prediction_history.append(prediction)
        smoothed_prediction = sum(self._prediction_history) / len(self._prediction_history)
        
        # Saldırı tespiti: ML tahmini VEYA çok yüksek PPS
        is_attack = smoothed_prediction >= 0.5 or features.packets_per_second > 20000
        
        # Saldırı tipini belirle
        attack_type = self._determine_attack_type(features) if is_attack else AttackType.NONE
        
        # Severity
        severity = self._determine_severity(confidence, features)
        
        # Detaylar
        details = {
            'method': 'ml',
            'model': self.config.model_type,
            'raw_prediction': int(prediction),
            'smoothed': smoothed_prediction,
            'pps': features.packets_per_second,
            'syn_ratio': features.syn_ratio
        }
        
        triggered_rules = []
        if is_attack:
            triggered_rules.append(f"ML_PREDICTION:{prediction}")
            triggered_rules.append(f"CONFIDENCE:{confidence:.2f}")
            if features.packets_per_second > 10000:
                triggered_rules.append(f"HIGH_PPS:{features.packets_per_second:.0f}")
        
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
        
        # Callback'ler
        self._handle_detection(result)
        self._last_results[dpid] = result
        
        return result
    
    def _determine_attack_type(self, features: FlowFeatures) -> AttackType:
        """Saldırı tipini belirle"""
        if features.syn_ratio > 0.3:
            return AttackType.SYN_FLOOD
        if features.avg_packet_size < 100 and features.packets_per_second > 5000:
            return AttackType.SYN_FLOOD
        return AttackType.SYN_FLOOD  # Varsayılan
    
    def _determine_severity(self, confidence: float, features: FlowFeatures) -> str:
        """Severity belirle"""
        pps = features.packets_per_second
        
        if pps > 30000 or confidence > 0.95:
            return "critical"
        elif pps > 20000 or confidence > 0.85:
            return "high"
        elif pps > 10000 or confidence > 0.7:
            return "medium"
        return "low"
    
    def _handle_detection(self, result: DetectionResult) -> None:
        """Tespit sonucunu işle"""
        dpid = result.dpid
        prev_result = self._last_results.get(dpid)
        
        if result.is_attack and (not prev_result or not prev_result.is_attack):
            if self._on_attack_detected:
                self._on_attack_detected(result)
        elif not result.is_attack and prev_result and prev_result.is_attack:
            if self._on_attack_ended:
                self._on_attack_ended(result)
    
    def set_on_attack_detected(self, callback) -> None:
        """Saldırı callback'i ayarla"""
        self._on_attack_detected = callback
    
    def set_on_attack_ended(self, callback) -> None:
        """Saldırı sonu callback'i ayarla"""
        self._on_attack_ended = callback
    
    # ===== EĞİTİM FONKSİYONLARI =====
    
    def start_collecting(self, label: int) -> None:
        """
        Eğitim verisi toplamaya başla.
        
        Args:
            label: 0 = normal, 1 = attack
        """
        self._collecting_data = True
        self._current_label = label
        print(f"[ML] Started collecting data (label={label})")
    
    def stop_collecting(self) -> int:
        """Veri toplamayı durdur"""
        self._collecting_data = False
        count = len(self._training_data)
        print(f"[ML] Stopped collecting. Total samples: {count}")
        return count
    
    def add_training_sample(self, features: FlowFeatures, label: int) -> None:
        """Eğitim örneği ekle"""
        X = self.extract_features_vector(features).flatten().tolist()
        self._training_data.append((X, label))
    
    def train(self, X: np.ndarray = None, y: np.ndarray = None) -> Dict:
        """
        Modeli eğit.
        
        Args:
            X: Öznitelik matrisi (None ise toplanan veri kullanılır)
            y: Etiketler
            
        Returns:
            Eğitim metrikleri
        """
        # Veri hazırla
        if X is None:
            if not self._training_data:
                raise ValueError("No training data available")
            
            X = np.array([sample[0] for sample in self._training_data])
            y = np.array([sample[1] for sample in self._training_data])
        
        print(f"[ML] Training with {len(X)} samples...")
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Normalize
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Model oluştur ve eğit
        self._create_model()
        
        if self.config.model_type == "random_forest":
            self.model.fit(X_train_scaled, y_train)
            y_pred = self.model.predict(X_test_scaled)
        else:  # Isolation Forest
            self.model.fit(X_train_scaled)
            y_pred = self.model.predict(X_test_scaled)
            y_pred = np.array([1 if p == -1 else 0 for p in y_pred])
        
        # Metrikler
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        self.is_trained = True
        
        print(f"[ML] Training complete!")
        print(f"[ML] Accuracy: {metrics['accuracy']:.2%}")
        print(f"[ML] Precision: {metrics['precision']:.2%}")
        print(f"[ML] Recall: {metrics['recall']:.2%}")
        print(f"[ML] F1 Score: {metrics['f1']:.2%}")
        
        return metrics
    
    def generate_synthetic_data(self, n_normal: int = 500, n_attack: int = 500) -> Tuple[np.ndarray, np.ndarray]:
        """
        Sentetik eğitim verisi üret.
        
        Gerçekçi veri: Normal, sınırda ve saldırı örnekleri içerir.
        
        Args:
            n_normal: Normal örnek sayısı
            n_attack: Saldırı örnek sayısı
            
        Returns:
            X, y: Öznitelik matrisi ve etiketler
        """
        np.random.seed(42)
        
        # === NORMAL TRAFİK ===
        # Düşük aktivite (idle)
        n_idle = n_normal // 3
        idle_data = np.column_stack([
            np.random.uniform(1, 100, n_idle),          # pps: çok düşük
            np.random.uniform(100, 10000, n_idle),      # bps
            np.random.uniform(1, 5, n_idle),            # flow_count
            np.random.uniform(0.01, 0.1, n_idle),       # syn_ratio
            np.random.uniform(0.7, 0.95, n_idle),       # syn_ack_ratio
            np.random.uniform(0.05, 0.2, n_idle),       # small_packet_ratio
            np.random.uniform(1, 10, n_idle),           # unique_src_ips
            np.random.uniform(0.1, 1.5, n_idle),        # entropy
            np.random.uniform(300, 1200, n_idle),       # avg_packet_size
            np.random.uniform(0, 2, n_idle),            # dropped
            np.random.uniform(0, 1, n_idle)             # errors
        ])
        
        # Orta aktivite (normal browsing)
        n_medium = n_normal // 3
        medium_data = np.column_stack([
            np.random.uniform(100, 2000, n_medium),     # pps
            np.random.uniform(10000, 200000, n_medium), # bps
            np.random.uniform(5, 30, n_medium),         # flow_count
            np.random.uniform(0.1, 0.3, n_medium),      # syn_ratio
            np.random.uniform(0.5, 0.85, n_medium),     # syn_ack_ratio
            np.random.uniform(0.15, 0.4, n_medium),     # small_packet_ratio
            np.random.uniform(5, 30, n_medium),         # unique_src_ips
            np.random.uniform(1.0, 2.5, n_medium),      # entropy
            np.random.uniform(200, 800, n_medium),      # avg_packet_size
            np.random.uniform(0, 5, n_medium),          # dropped
            np.random.uniform(0, 2, n_medium)           # errors
        ])
        
        # Yüksek aktivite (busy but normal - video streaming, downloads)
        n_high = n_normal - n_idle - n_medium
        high_data = np.column_stack([
            np.random.uniform(2000, 8000, n_high),      # pps: yüksek ama normal
            np.random.uniform(200000, 800000, n_high),  # bps
            np.random.uniform(20, 60, n_high),          # flow_count
            np.random.uniform(0.15, 0.35, n_high),      # syn_ratio: hala düşük
            np.random.uniform(0.4, 0.75, n_high),       # syn_ack_ratio
            np.random.uniform(0.2, 0.5, n_high),        # small_packet_ratio
            np.random.uniform(10, 50, n_high),          # unique_src_ips
            np.random.uniform(1.5, 3.0, n_high),        # entropy
            np.random.uniform(150, 600, n_high),        # avg_packet_size
            np.random.uniform(0, 10, n_high),           # dropped
            np.random.uniform(0, 3, n_high)             # errors
        ])
        
        normal_data = np.vstack([idle_data, medium_data, high_data])
        
        # === SALDIRI TRAFİĞİ ===
        # Düşük yoğunluk saldırı (low-rate attack - zor tespit)
        n_low_attack = n_attack // 4
        low_attack_data = np.column_stack([
            np.random.uniform(3000, 8000, n_low_attack),    # pps: orta-yüksek
            np.random.uniform(100000, 400000, n_low_attack),
            np.random.uniform(15, 50, n_low_attack),
            np.random.uniform(0.5, 0.75, n_low_attack),     # syn_ratio: orta
            np.random.uniform(0.1, 0.35, n_low_attack),     # syn_ack_ratio: düşük
            np.random.uniform(0.6, 0.85, n_low_attack),
            np.random.uniform(30, 150, n_low_attack),
            np.random.uniform(2.5, 4.5, n_low_attack),
            np.random.uniform(50, 120, n_low_attack),
            np.random.uniform(5, 30, n_low_attack),
            np.random.uniform(2, 8, n_low_attack)
        ])
        
        # Orta yoğunluk saldırı
        n_med_attack = n_attack // 4
        med_attack_data = np.column_stack([
            np.random.uniform(10000, 25000, n_med_attack),  # pps: yüksek
            np.random.uniform(400000, 900000, n_med_attack),
            np.random.uniform(30, 80, n_med_attack),
            np.random.uniform(0.7, 0.9, n_med_attack),      # syn_ratio: yüksek
            np.random.uniform(0.02, 0.15, n_med_attack),    # syn_ack_ratio: çok düşük
            np.random.uniform(0.85, 0.98, n_med_attack),
            np.random.uniform(100, 400, n_med_attack),
            np.random.uniform(4.0, 6.5, n_med_attack),
            np.random.uniform(45, 75, n_med_attack),
            np.random.uniform(10, 60, n_med_attack),
            np.random.uniform(3, 15, n_med_attack)
        ])
        
        # Yüksek yoğunluk saldırı (flood mode)
        n_high_attack = n_attack // 4
        high_attack_data = np.column_stack([
            np.random.uniform(25000, 60000, n_high_attack), # pps: çok yüksek
            np.random.uniform(800000, 2000000, n_high_attack),
            np.random.uniform(50, 150, n_high_attack),
            np.random.uniform(0.85, 0.99, n_high_attack),   # syn_ratio: çok yüksek
            np.random.uniform(0.0, 0.05, n_high_attack),    # syn_ack_ratio: neredeyse 0
            np.random.uniform(0.95, 1.0, n_high_attack),
            np.random.uniform(200, 800, n_high_attack),
            np.random.uniform(5.5, 8.0, n_high_attack),
            np.random.uniform(40, 65, n_high_attack),
            np.random.uniform(20, 100, n_high_attack),
            np.random.uniform(5, 25, n_high_attack)
        ])
        
        # DDoS saldırısı (çok yüksek source diversity)
        n_ddos = n_attack - n_low_attack - n_med_attack - n_high_attack
        ddos_data = np.column_stack([
            np.random.uniform(40000, 100000, n_ddos),       # pps: aşırı
            np.random.uniform(1500000, 5000000, n_ddos),
            np.random.uniform(80, 200, n_ddos),
            np.random.uniform(0.8, 0.98, n_ddos),
            np.random.uniform(0.0, 0.03, n_ddos),
            np.random.uniform(0.97, 1.0, n_ddos),
            np.random.uniform(500, 2000, n_ddos),           # unique_src: çok fazla
            np.random.uniform(6.0, 10.0, n_ddos),           # entropy: çok yüksek
            np.random.uniform(40, 60, n_ddos),
            np.random.uniform(50, 200, n_ddos),
            np.random.uniform(10, 50, n_ddos)
        ])
        
        attack_data = np.vstack([low_attack_data, med_attack_data, high_attack_data, ddos_data])
        
        # Gürültü ekle (gerçekçilik için)
        normal_data += np.random.normal(0, 0.05, normal_data.shape) * normal_data
        attack_data += np.random.normal(0, 0.05, attack_data.shape) * attack_data
        
        # Negatif değerleri düzelt
        normal_data = np.maximum(normal_data, 0)
        attack_data = np.maximum(attack_data, 0)
        
        X = np.vstack([normal_data, attack_data])
        y = np.array([0] * len(normal_data) + [1] * len(attack_data))
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X = X[indices]
        y = y[indices]
        
        print(f"[ML] Generated {len(normal_data)} normal + {len(attack_data)} attack samples")
        print(f"[ML] Normal: idle({n_idle}) + medium({n_medium}) + high({n_high})")
        print(f"[ML] Attack: low({n_low_attack}) + medium({n_med_attack}) + high({n_high_attack}) + ddos({n_ddos})")
        
        return X, y
    
    def train_with_synthetic_data(self) -> Dict:
        """Sentetik veri ile eğit"""
        X, y = self.generate_synthetic_data()
        metrics = self.train(X, y)
        self.save_model()
        return metrics
    
    def train_from_csv(self, csv_path: str) -> Dict:
        """
        CSV dosyasından gerçek veri ile eğit.
        
        Args:
            csv_path: CSV dosya yolu (CICFlowMeter formatı)
            
        Returns:
            Eğitim metrikleri
        """
        from .data_loader import load_tcp_syn_dataset
        
        print(f"[ML] Loading dataset from: {csv_path}")
        X, y = load_tcp_syn_dataset(csv_path)
        
        print(f"[ML] Dataset loaded: {X.shape[0]} samples, {X.shape[1]} features")
        
        metrics = self.train(X, y)
        self.save_model()
        
        return metrics
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Öznitelik önem skorlarını döndür (Random Forest için)"""
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        importance = self.model.feature_importances_
        return dict(zip(self.FEATURE_NAMES, importance))


def create_ml_detector(model_type: str = "random_forest", 
                       train_if_needed: bool = True) -> MLDetector:
    """
    ML detector oluştur ve gerekirse eğit.
    
    Args:
        model_type: Model tipi (random_forest, isolation_forest)
        train_if_needed: Model yoksa sentetik veri ile eğit
        
    Returns:
        MLDetector instance
    """
    config = MLConfig(model_type=model_type)
    detector = MLDetector(config)
    
    if not detector.is_trained and train_if_needed:
        print("[ML] No trained model found. Training with synthetic data...")
        detector.train_with_synthetic_data()
    
    return detector

