@echo off
REM ==============================================================================
REM Zero-Knowledge Document Redaction and Verification Engine
REM Build, Test & Launch Script (Windows - Java 21)
REM ==============================================================================

echo ==================================================================
echo Zero-Knowledge Document Redaction and Verification Engine
echo ==================================================================

where javac >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: javac ^(JDK 21+^) is not found on your PATH.
    exit /b 1
)

if not exist out mkdir out

echo Compiling Java 21 source files...
dir /s /B src\*.java core\*.java test\*.java > sources.txt
javac -encoding UTF-8 -d out @sources.txt
set BUILD_STATUS=%ERRORLEVEL%
del sources.txt

if %BUILD_STATUS% NEQ 0 (
    echo Compilation failed.
    exit /b 1
)

if /I "%~1"=="--test" (
    echo Running Backend, OCR, PDF Redaction ^& Integration Test Suites...
    java -cp out com.zeroknowledge.app.Main
    if %ERRORLEVEL% NEQ 0 exit /b 1
    java -cp out test.IntegrationTest
    if %ERRORLEVEL% NEQ 0 exit /b 1
    java -cp out test.GuiHeadlessTest
    exit /b %ERRORLEVEL%
)

echo Starting Desktop Application on Event Dispatch Thread...
java -cp out com.zeroknowledge.frontend.MainFrame %*
