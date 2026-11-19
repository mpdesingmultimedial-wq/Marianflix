@echo off
title Marianflix Web Server
cd /d "%~dp0"
echo Iniciando servidor Marianflix Web en http://localhost:3080 ...
start "" "http://localhost:3080"
node server.js
pause
