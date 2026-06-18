$ErrorActionPreference = "Continue"
Write-Output "=== SMC ECS 部署 ==="

$env:Path = "C:\Program Files\nodejs;" + $env:Path

$projDir = "C:\smc-storage"
Write-Output "[1] 项目目录: $projDir"
if (Test-Path "$projDir\server.js") {
    Write-Output "  server.js 存在"
} else {
    Write-Output "  下载 server.js..."
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ljtatm5-crypto/smx/source/smc-transit/server.js" -OutFile "$projDir\server.js"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ljtatm5-crypto/smx/source/smc-transit/package.json" -OutFile "$projDir\package.json"
}

Write-Output "[2] npm install..."
Set-Location $projDir
npm install

Write-Output "[3] 防火墙..."
netsh advfirewall firewall add rule name="SMC-3456" dir=in action=allow protocol=tcp localport=3456 2>$null

Write-Output "[4] PM2..."
npm install -g pm2
$pm2Path = "$env:APPDATA\npm\pm2.cmd"
if (Test-Path $pm2Path) {
    & $pm2Path stop smc-storage 2>$null
    & $pm2Path delete smc-storage 2>$null
    & $pm2Path start "$projDir\server.js" --name smc-storage
    & $pm2Path save
    Write-Output "  PM2 启动成功"
} else {
    $altPath = "$env:LOCALAPPDATA\..\Roaming\npm\pm2.cmd"
    if (Test-Path $altPath) {
        & $altPath start "$projDir\server.js" --name smc-storage
        & $altPath save
        Write-Output "  PM2 启动成功 (alt path)"
    } else {
        Write-Output "  找不到 pm2，直接用 node 启动"
        Start-Process node -ArgumentList $projDir\server.js -WindowStyle Hidden
    }
}

Write-Output "[5] 开机自启..."
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `$env:Path='C:\Program Files\nodejs;'+`$env:Path; node C:\smc-storage\server.js"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "SMC-Storage-Startup" -Action $action -Trigger $trigger -User "SYSTEM" -Force | Out-Null

Write-Output ""
Write-Output "=== 完成 ==="
Write-Output "http://8.163.64.2:3456/api/health"