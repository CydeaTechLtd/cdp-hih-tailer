#Install Python and scapy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe" -OutFile "c:/temp/python-3.7.0.exe"

c:/temp/python-3.7.0.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
pip install scapy
#Installing SysMon
# Variables

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$sysMon64 = 'SysMon64'
$sysMon32 = 'SysMon'
$configFile = 'sysmonconfig.xml'
$OSArch = Get-WmiObject win32_operatingsystem | Select-Object osarchitecture
# Detect Existing Installs
if (Get-Service -Name $sysMon64 -ErrorAction SilentlyContinue) {
  # Found SysMon64
  Write-Host 'SysMon 64bit found'
  # Stop Service / Uninstall / Cleanup Files
  Get-Service -Name $sysMon64 | Stop-Service -Force
  Start-Sleep -Seconds 3
  Start-Process -FilePath "$env:SystemRoot\$sysMon64.exe" -ArgumentList "-u" -Wait
  Start-Sleep -Seconds 3
  Remove-Item -Path "$env:SystemRoot\$sysMon64.exe"
  Remove-Item -Path "$env:SystemRoot\$sysMon32.exe"
  Remove-Item -Path "$env:SystemRoot\$configFile"
  Start-Sleep -Seconds 3
}
elseif (Get-Service -Name $sysMon32 -ErrorAction SilentlyContinue) {
  # Found SysMon32
  Write-Host 'SysMon 32bit found'
  # Stop Service / Uninstall / Cleanup Files
  Get-Service -Name $sysMon32 | Stop-Service -Force
  Start-Sleep -Seconds 3
  Start-Process -FilePath "$env:SystemRoot\$sysMon32.exe" -ArgumentList "-u" -Wait
  Start-Sleep -Seconds 3
  Remove-Item -Path "$env:SystemRoot\$sysMon64.exe"
  Remove-Item -Path "$env:SystemRoot\$sysMon32.exe"
  Remove-Item -Path "$env:SystemRoot\$configFile"
  Start-Sleep -Seconds 3
}
# Copy Files and Install (excludes non sys-mon files)
Get-ChildItem -Path "$ScriptDir" -Exclude *.txt, *.ps1, *.cmd | Select-Object -ExpandProperty FullName |
Copy-Item -Destination "$env:SystemRoot\" -Force
if ($OSArch.osarchitecture -eq '64-bit') {
  Start-Process -FilePath "$env:SystemRoot\$sysMon64.exe" -ArgumentList "-accepteula -i $env:SystemRoot\$configFile"
}
else {
  Start-Process -FilePath "$env:SystemRoot\$sysMon32.exe" -ArgumentList "-accepteula -i $env:SystemRoot\$configFile"
}