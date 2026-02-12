#!/bin/bash

# WS-Strike Build Script — No Gradle Required
# Just needs: Java JDK 17+ (javac and jar)

set -e

echo "⚡ WS-Strike Builder"
echo "===================="

# Check Java
if ! command -v javac &> /dev/null; then
    echo "❌ javac not found. Install Java JDK:"
    echo "   sudo apt install openjdk-17-jdk"
    exit 1
fi

JAVA_VER=$(javac -version 2>&1 | grep -oP '\d+' | head -1)
echo "✓ Java version: $JAVA_VER"

# Download Montoya API if not present
API_JAR="montoya-api.jar"
if [ ! -f "$API_JAR" ]; then
    echo "⬇ Downloading Burp Montoya API..."
    wget -q -O "$API_JAR" "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar"
    if [ $? -ne 0 ]; then
        echo "❌ Download failed. Download manually:"
        echo "   https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2023.12.1/montoya-api-2023.12.1.jar"
        echo "   Save as montoya-api.jar in this folder"
        exit 1
    fi
    echo "✓ Montoya API downloaded"
else
    echo "✓ Montoya API found"
fi

# Clean
rm -rf build
mkdir -p build/classes

# Compile
echo "🔨 Compiling..."
javac -cp "$API_JAR" \
      -d build/classes \
      src/main/java/wsstrike/*.java

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed"
    exit 1
fi

echo "✓ Compiled $(ls build/classes/wsstrike/*.class | wc -l) classes"

# Package
echo "📦 Packaging JAR..."
cd build/classes
jar cf ../../ws-strike.jar wsstrike/
cd ../..

echo ""
echo "✅ BUILD SUCCESSFUL"
echo ""
echo "   Output: ws-strike.jar"
echo ""
echo "   Load in Burp:"
echo "   1. Extensions → Installed → Add"
echo "   2. Type: Java"
echo "   3. File: $(pwd)/ws-strike.jar"
echo ""
