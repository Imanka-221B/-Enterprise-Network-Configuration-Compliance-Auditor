import os
import sys

# Project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Tell ENCCA that it is running on Vercel.
os.environ.setdefault("VERCEL", "1")

# Import the existing Flask application.
from app import app

# WSGI entry point used by Vercel.
application = app