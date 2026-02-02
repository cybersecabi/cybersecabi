import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
import yaml

class Config:
    def __init__(self):
        self.config_dir = Path.home() / ".aegis"
        self.config_file = self.config_dir / "config.yaml"
        self.data_dir = self.config_dir / "data"
        self.reports_dir = self.config_dir / "reports"
        self._config: Dict[str, Any] = {}
        
        self._ensure_dirs()
        self._load_config()
    
    def _ensure_dirs(self):
        self.config_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
    
    def _load_config(self):
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = self._default_config()
            self.save()
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            "threads": 50,
            "timeout": 30,
            "output_format": "table",
            "verbose": False,
            "recon": {
                "ports": "top1000",
                "scan_type": "syn",
                "os_detection": False
            },
            "vuln": {
                "check_cves": True,
                "severity_filter": None,
                "exploit_db": False
            },
            "web": {
                "follow_redirects": True,
                "ssl_verify": True,
                "user_agent": "Aegis-Security-Scanner/1.0"
            },
            "watch": {
                "interval": 5,
                "alert_threshold": 3
            },
            "api_keys": {
                "shodan": None,
                "virustotal": None,
                "censys": None
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def save(self):
        with open(self.config_file, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False)
    
    def get_db_path(self, name: str) -> Path:
        return self.data_dir / f"{name}.db"

config = Config()
