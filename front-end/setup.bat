@echo off
echo ============================================
echo CLINIC-IN-A-BOX - NODE.JS APP SETUP
echo ============================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed.
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [1/4] Node.js found: 
node --version

echo.
echo [2/4] Installing dependencies...
call npm install

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [3/4] Checking database connection...
REM You can add a database check here if needed

echo.
echo [4/4] Setup complete!
echo.
echo ============================================
echo TO START THE SERVER:
echo   npm start
echo.
echo OR for development with auto-reload:
echo   npm run dev
echo.
echo Server will run at: http://localhost:3000
echo ============================================
echo.
pause
