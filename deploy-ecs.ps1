# SMC 部署脚本 - 在阿里云 ECS 上运行
# 下载方式: 在 ECS 的 PowerShell 中粘贴整段即可

# 装 Node.js
Invoke-WebRequest -Uri "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi" -OutFile "$env:TEMP\node.msi"
Start-Process msiexec.exe -Wait -ArgumentList "/i $env:TEMP\node.msi /quiet"
$env:Path = "C:\Program Files\nodejs;" + $env:Path

# 拉代码
mkdir C:\smc-storage -Force; cd C:\smc-storage
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ljtatm5-crypto/smx/source/smc-transit/server.js" -OutFile server.js
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ljtatm5-crypto/smx/source/smc-transit/package.json" -OutFile package.json

# 安装依赖
npm install

# 开防火墙
netsh advfirewall firewall add rule name="SMC" dir=in action=allow protocol=tcp localport=3456

# 启动
node server.js
