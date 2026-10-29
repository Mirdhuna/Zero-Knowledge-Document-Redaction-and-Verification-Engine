#!/usr/bin/env bash
# ==============================================================================
# Zero-Knowledge Document Redaction and Verification Engine
# Build & Launch Script (Linux / macOS)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================================="
echo "Zero-Knowledge Document Redaction & Verification Engine"
echo "=================================================================="

if ! command -v javac &> /dev/null; then
    echo "Error: javac (JDK 21+) is not found on your PATH."
    exit 1
fi

JAVA_VER=$(javac -version 2>&1 | awk '{print $2}' | cut -d'.' -f1)
echo "Detected Java Compiler version: $JAVA_VER"

echo "Compiling Java source files..."
mkdir -p out
javac -d out $(find src core -name "*.java")

echo "Starting Application on Event Dispatch Thread..."
java -cp out com.zeroknowledge.frontend.MainFrame "$@"
