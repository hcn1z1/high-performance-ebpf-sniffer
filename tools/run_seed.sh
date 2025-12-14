#!/bin/bash
set -e

echo "Step 1: Downloading Data..."
echo "This may take a few minutes..."
python3 download_threat_data.py

echo "Step 2: Seeding Qdrant..."
# Ensure directory exists
mkdir -p tools/data
# Run seeder
./seeder -csv tools/data/combined_ja4_db.csv -addr $QDRANT_ADDR
