# CryptoNote Simple Startup Script
Write-Host "🔐 Starting CryptoNote Server..." -ForegroundColor Green

Set-Location server
$env:NODE_ENV = "development"
$env:MONGO_URI = "mongodb://127.0.0.1:27017/cryptonote"
$env:PORT = "5001"

Write-Host "Server will be available at: http://localhost:5001" -ForegroundColor Yellow
node server-minimal.js
