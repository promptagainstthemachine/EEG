"""
EEG - Configuration Loader
Loads YAML configs from rules/dynamic directory.
"""

import os
import yaml
from typing import Dict, Any, Optional


CONFIG_DIR = os.path.join(os.path.dirname(__file__), "rules", "dynamic")

_cache: Dict[str, Dict[str, Any]] = {}
_thresholds: Optional[Dict[str, Any]] = None


class ConfigLoader:
    """Load and cache YAML configuration files."""

    @staticmethod
    def load(config_name: str) -> Dict[str, Any]:
        """
        Load a config file by name.
        
        Args:
            config_name: Name of config file (without .yaml extension)
            
        Returns:
            Parsed YAML as dictionary
        """
        if config_name in _cache:
            return _cache[config_name]
        
        config_path = os.path.join(CONFIG_DIR, f"{config_name}.yaml")
        
        if not os.path.isfile(config_path):
            _cache[config_name] = {}
            return {}
        
        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}
                _cache[config_name] = data
                return data
        except Exception:
            _cache[config_name] = {}
            return {}

    @staticmethod
    def get_threshold(key: str, default: Any = None) -> Any:
        """
        Get a threshold value using dot-notation key.
        
        Args:
            key: Dot-separated path (e.g., "aws.guardrail.min_strength")
            default: Default value if key not found
            
        Returns:
            Threshold value or default
        """
        global _thresholds
        
        if _thresholds is None:
            _thresholds = ConfigLoader.load("thresholds")
        
        parts = key.split(".")
        current = _thresholds
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        
        return current

    @staticmethod
    def get_check(cloud: str, check_id: str) -> Optional[Dict[str, Any]]:
        """Get a dynamic check definition by cloud and check ID."""
        config = ConfigLoader.load(f"{cloud}_dynamic")
        for check in config.get("checks", []):
            if check.get("id") == check_id:
                return check
        return None

    @staticmethod
    def is_check_enabled(cloud: str, check_id: str) -> bool:
        """Return whether a dynamic check is enabled in config."""
        check = ConfigLoader.get_check(cloud, check_id)
        if check is None:
            return True
        return bool(check.get("enabled", True))

    @staticmethod
    def clear_cache():
        """Clear the config cache (useful for testing)."""
        global _cache, _thresholds
        _cache = {}
        _thresholds = None


def get_threshold(key: str, default: Any = None) -> Any:
    """Convenience function for getting thresholds."""
    return ConfigLoader.get_threshold(key, default)
