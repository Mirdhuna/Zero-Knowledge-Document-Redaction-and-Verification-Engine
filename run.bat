@echo off
REM ==============================================================================
REM Zero-Knowledge Document Redaction and Verification Engine
REM Build & Launch Script (Windows)
REM ==============================================================================

echo ==================================================================
echo Zero-Knowledge Document Redaction and Verification Engine
echo ==================================================================

where javac >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: javac (JDK 21+) is not found on your PATH.
    pause
    exit /b 1
)

if not exist out mkdir out

echo Compiling Java source files...
dir /s /B src\*.java core\*.java > sources.txt
javac -d out @sources.txt
del sources.txt

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo Starting Application on Event Dispatch Thread...
java -cp out com.zeroknowledge.frontend.MainFrame %*
