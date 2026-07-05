#!/usr/bin/env python
"""
VulnForge — Quick-start launcher.
Run this from the project root:
    python run.py

Also works if accidentally run from inside backend/:
    python ../run.py
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    # Always work from the project root (two levels up from this script
    # if it was called from backend/, or one level if from project root)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    sys.path.insert(0, script_dir)

    print("=" * 50)
    print("  VulnForge — Red Team Dashboard")
    print("  -> http://localhost:8000")
    print("=" * 50)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
