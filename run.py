#!/usr/bin/env python
"""
VulnForge — Quick-start launcher.
Run this from the project root:
    python run.py
"""
import uvicorn
import os

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
