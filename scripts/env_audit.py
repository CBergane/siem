#!/usr/bin/env python3
"""
Basic environment audit to validate .env against .env.example.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"

# Placeholder values that should never be committed or used.
UNSAFE_VALUES = {
    "changeme",
    "change_me",
    "change-me",
    "changemeinproduction",
    "password",
    "1234",
}


def parse_env(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def is_unsafe(value: str) -> bool:
    normalized = value.strip().lower()
    simplified = "".join(ch for ch in normalized if ch.isalnum())
    return normalized in UNSAFE_VALUES or simplified in UNSAFE_VALUES


def main() -> int:
    errors = []
    warnings = []

    example_env = parse_env(ENV_EXAMPLE)
    env = parse_env(ENV_FILE)

    if not example_env:
        errors.append(f"Missing or empty {ENV_EXAMPLE.name}; cannot determine required keys.")
    if not env:
        errors.append(f"Missing or empty {ENV_FILE.name}; copy {ENV_EXAMPLE.name} and fill in values.")

    for key in example_env:
        if key not in env:
            errors.append(f"Missing key in .env: {key}")
            continue

        value = env[key]
        if value == "":
            errors.append(f"Empty value for {key}")
        elif is_unsafe(value):
            errors.append(f"Unsafe placeholder value for {key}")

    if ENV_FILE.exists():
        mode = stat.S_IMODE(os.stat(ENV_FILE).st_mode)
        if mode != 0o600:
            warnings.append(f"{ENV_FILE.name} permissions are {oct(mode)} (recommend 0o600).")

    if errors:
        print("Errors:")
        for msg in errors:
            print(f"- {msg}")
    if warnings:
        print("Warnings:")
        for msg in warnings:
            print(f"- {msg}")
    if not errors and not warnings:
        print("Environment looks good.")

    if errors:
        return 3
    if warnings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
