"""
CipherNet Settings Service
Handles persistent configuration management using JSON.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict


DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": "charcoal-rose",
    "refresh_rate": 2.0,
    "resolve_hostnames": False,
    "show_loopback": False,
    "enable_scapy": False,
    "ids_auto_start": False,
    "ids_intensity": "Medium",
    "max_logs": 1000,
    "sound_alerts": False,
    "default_crypto_algo": "AES-256-GCM",
}

VALID_THEMES = ("charcoal-rose", "cyber-neon", "gruvbox-dark")


class SettingsService:
    """Manages application settings stored in a JSON configuration file."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            # Default to ciphernet/config/settings.json relative to this file
            base_dir = Path(__file__).resolve().parent.parent
            self.config_path = base_dir / "config" / "settings.json"
        else:
            self.config_path = Path(config_path)

        self._settings: Dict[str, Any] = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> Dict[str, Any]:
        """Loads settings from JSON file or creates defaults if missing."""
        try:
            if self.config_path.exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        # Merge with defaults so new keys are present
                        merged = dict(DEFAULT_SETTINGS)
                        merged.update(loaded)
                        # Normalize theme to only the 2 supported themes
                        if merged.get("theme") not in VALID_THEMES:
                            merged["theme"] = "cyber-neon"
                        self._settings = merged
                        return self._settings
        except Exception:
            # Fall back to default settings on read/parse error
            pass

        self._settings = dict(DEFAULT_SETTINGS)
        self.save()
        return self._settings

    def save(self) -> bool:
        """Persists current settings to the JSON configuration file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self._settings, f, indent=2)
            return True
        except Exception:
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a single setting value."""
        return self._settings.get(key, default)

    def set(self, key: str, value: Any, auto_save: bool = True) -> None:
        """Updates a single setting value and optionally persists it."""
        self._settings[key] = value
        if auto_save:
            self.save()

    def update(self, updates: Dict[str, Any], auto_save: bool = True) -> None:
        """Batch update settings."""
        self._settings.update(updates)
        if auto_save:
            self.save()

    def reset_to_defaults(self) -> Dict[str, Any]:
        """Resets all configuration values to defaults."""
        self._settings = dict(DEFAULT_SETTINGS)
        self.save()
        return self._settings

    @property
    def all(self) -> Dict[str, Any]:
        """Returns a copy of all current settings."""
        return dict(self._settings)
