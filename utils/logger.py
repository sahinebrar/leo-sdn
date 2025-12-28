#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LEO SDN Attack Detection - Logger Module
Merkezi loglama yapılandırması
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logging(log_file: str = "logs/sdn_attack.log", 
                  level: str = "INFO",
                  max_size_mb: int = 10,
                  backup_count: int = 5) -> None:
    """
    Loglama sistemini yapılandırır.
    
    Args:
        log_file: Log dosyası yolu
        level: Log seviyesi (DEBUG, INFO, WARNING, ERROR)
        max_size_mb: Maksimum dosya boyutu (MB)
        backup_count: Yedek dosya sayısı
    """
    # Log klasörünü oluştur
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Log seviyesini ayarla
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (rotating)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    İsimlendirilmiş logger döndürür.
    
    Args:
        name: Logger ismi (genellikle __name__)
    
    Returns:
        logging.Logger: Yapılandırılmış logger
    """
    return logging.getLogger(name)


class ColoredFormatter(logging.Formatter):
    """Terminal için renkli log formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


if __name__ == "__main__":
    # Test
    setup_logging(level="DEBUG")
    logger = get_logger("test")
    
    logger.debug("Debug mesajı")
    logger.info("Info mesajı")
    logger.warning("Warning mesajı")
    logger.error("Error mesajı")

