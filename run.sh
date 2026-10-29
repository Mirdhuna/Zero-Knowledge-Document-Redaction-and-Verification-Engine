#!/usr/bin/env bash
# ==============================================================================
# Zero-Knowledge Document Redaction and Verification Engine
# Build, Test & Launch Script (Linux / macOS - Java 21)
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

echo "Compiling Java 21 source files..."
mkdir -p out
javac -encoding UTF-8 -d out $(find src core test -name "*.java")

if [ "${1:-}" = "--test" ]; then
    echo "Running Backend, OCR, PDF Redaction & Integration Test Suites..."
    java -cp out com.zeroknowledge.app.Main
    java -cp out test.IntegrationTest
    java -cp out test.GuiHeadlessTest
    exit 0
fi

echo "Starting Desktop Application on Event Dispatch Thread..."
java -cp out com.zeroknowledge.frontend.MainFrame "$@"
