#!/usr/bin/env bash
# deploy.sh — Deployment script for the FIM application.
# CRITICAL: This file is integrity-monitored.
# Unauthorised changes here could introduce malicious deployment steps.

set -e

echo "=============================="
echo " FIM Deployment Script v1.0.0"
echo "=============================="

# Step 1: Pull latest code
echo "[1/4] Pulling latest source..."
git pull origin main

# Step 2: Install dependencies
echo "[2/4] Installing dependencies..."
pip install -r requirements.txt --quiet

# Step 3: Run integrity pre-check
echo "[3/4] Running pre-deployment integrity scan..."
python File_Integrity_Monitor.py --cli-check

# Step 4: Start application
echo "[4/4] Starting application..."
streamlit run File_Integrity_Monitor.py &

echo ""
echo "Deployment complete. App running at http://localhost:8501"
