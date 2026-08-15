#!/usr/bin/env python3
# ==============================================================================
# Project: logwall — Cross-Distro & Cross-Panel Server Firewall Automation
# Module: lib/py/config_loader.py
# Purpose: Reads /etc/logwall.conf into a plain dict so every Python engine honours
#          the central configuration instead of silently falling back to hardcoded
#          defaults.
# Reference: docs/DESIGN.md §13 (Centralized Configuration)
# ==============================================================================

import os

DEFAULT_CONF_PATH = "/etc/logwall.conf"


def _strip_value(raw):
    """Strips surrounding quotes and trailing inline comments from a conf value."""
    raw = raw.strip()
    if not raw:
        return ""

    if raw[0] in ("'", '"'):
        quote = raw[0]
        end = raw.find(quote, 1)
        if end != -1:
            return raw[1:end]
        return raw[1:]

    # Unquoted value: an inline comment starts at the first '#'
    hash_pos = raw.find("#")
    if hash_pos != -1:
        raw = raw[:hash_pos]
    return raw.strip()


def load_config(path=None):
    """
    Parses the shell-style KEY=VALUE configuration file.

    Precedence (lowest to highest):
      1. values found in the config file
      2. matching environment variables (the CLI exports them via `set -a`)
    """
    path = path or os.environ.get("LOGWALL_CONF", DEFAULT_CONF_PATH)
    config = {}

    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    if key.startswith("export "):
                        key = key[7:].strip()
                    if key:
                        config[key] = _strip_value(value)
        except OSError:
            pass

    # Environment wins: the Bash CLI already sourced the same file with `set -a`,
    # and an operator may override a single key for one run.
    for key in list(config.keys()):
        env_value = os.environ.get(key)
        if env_value is not None and env_value != "":
            config[key] = env_value

    return config


def get_int(config, key, default):
    try:
        return int(str(config.get(key, default)).strip())
    except (TypeError, ValueError):
        return default


def get_bool(config, key, default=False):
    value = str(config.get(key, "1" if default else "0")).strip().lower()
    return value in ("1", "yes", "true", "on")


def get_path(config, key, default):
    value = str(config.get(key, "") or "").strip()
    return value if value else default
