Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Write-Output "=== SMC Storage ECS 部署 ==="

# 安装 Node.js
if (-not (Test-Path "C:\Program Files\nodejs\node.exe")) {
    Write-Output "[1/6] Installing Node.js..."
    Invoke-WebRequest -Uri "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi" -OutFile "$env:TEMP\node.msi"
    Start-Process msiexec.exe -Wait -ArgumentList "/i $env:TEMP\node.msi /quiet"
}
$env:Path = "C:\Program Files\nodejs;" + $env:Path

# git clone 代码
Write-Output "[2/6] Cloning code..."
cd C:\
if (Test-Path "C:\smc-storage") { Remove-Item "C:\smc-storage" -Recurse -Force }
git clone https://github.com/ljtatm5-crypto/smx.git smc-storage 2>$null

# 安装依赖
Write-Output "[3/6] npm install..."
cd C:\smc-storage\smc-transit
npm install

# 防火墙
Write-Output "[4/6] Opening firewall..."
netsh advfirewall firewall add rule name="SMC-3456" dir=in action=allow protocol=tcp localport=3456 2>$null

# PM2 持久化
Write-Output "[5/6] Setting up PM2..."
npm install -g pm2
pm2 kill 2>$null
pm2 start server.js --name smc-storage
pm2 save
pm2 startup | iex

# 定时自动更新
Write-Output "[6/6] Setting up auto-update..."
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"cd C:\smc-storage; git pull; cd smc-transit; npm install; pm2 restart smc-storage`""
$taskTrigger = New-ScheduledTaskTrigger -Daily -At "03:00"
Register-ScheduledTask -TaskName "SMC-AutoUpdate" -Action $taskAction -Trigger $taskTrigger -User "SYSTEM" -Force | Out-Null

Write-Output "`n=== 部署完成 ==="
Write-Output "服务: http://8.163.64.2:3456"
Write-Output "健康: http://8.163.64.2:3456/api/health"
Write-Output "更新: git push 后运行: cd C:\smc-storage\smc-transit; git pull; pm2 restart smc-storage"