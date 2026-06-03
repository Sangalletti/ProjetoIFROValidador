"""WSGI entry point for the Validador Educacional Brasil Flask application."""

import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import app as application  # noqa: E402


app = application
