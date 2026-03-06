"""
wsgi.py — explicit WSGI entry point for gunicorn
Ensures Python path includes the backend directory.
"""
import sys
import os

# Make sure the backend directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == "__main__":
    app.run()
