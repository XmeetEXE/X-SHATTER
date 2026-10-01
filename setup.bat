@echo off
REM X-SHATTER setup — checks for Node.js >= 20 (zero npm dependencies needed).
where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js is not installed. Get it from https://nodejs.org/ ^(^>= 20^).
  exit /b 1
)
for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node.split('.')[0]"') do set MAJOR=%%v
if %MAJOR% LSS 20 (
  echo ERROR: Node.js ^>= 20 required.
  exit /b 1
)
node --version
echo OK: no npm install needed (zero dependencies).
echo.
echo CLI:        node src\cli.js --help
echo Dashboard:  node server.js   -^>  http://127.0.0.1:4174/
echo Tests:      node --test "test\*.test.js"
