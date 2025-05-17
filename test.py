# Windows Application Vulnerability Detection Agent

import os
import hashlib
import psutil
import winreg
import requests
import json
import time

# === Module 1: System Snapshot ===
def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash....
