#Install Python and scapy
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
choco install git.install -y
choco install nssm -y
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.7.0/python-3.7.0-amd64.exe" -OutFile "c:/ProgramData/python-3.7.0.exe"
refreshenv
c:/ProgramData/python-3.7.0-amd64.exe /quiet InstallAllUsers=0 PrependPath=1 Include_test=0
#c:/ProgramData/python-3.7.0-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
refreshenv
pip install scapy
refreshenv
#Installing SysMon
# Variables
#Installing git
#Install-Module posh-git -Scope CurrentUser -Force
#Import-Module posh-git
#Add-PoshGitToProfile -AllHosts

$SysmonURI = "https://download.sysinternals.com/files/Sysmon.zip"
$TempFolder = "$env:SystemRoot"
$LocalFilePath = "$TempFolder\sysmon.zip"
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$sysMon64 = 'SysMon64'
$sysMon32 = 'SysMon'
$configFile = 'sysmonconfig.xml'
Invoke-WebRequest -Uri $SysmonURI -OutFile $LocalFilePath
Expand-Archive -Path $LocalFilePath -DestinationPath $TempFolder
$OSArch = Get-WmiObject win32_operatingsystem | Select-Object osarchitecture
#Detect Existing Installs
<#
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
  Stop Service / Uninstall / Cleanup Files
  Get-Service -Name $sysMon32 | Stop-Service -Force
  Start-Sleep -Seconds 3
 Start-Process -FilePath "$env:SystemRoot\$sysMon32.exe" -ArgumentList "-u" -Wait
  Start-Sleep -Seconds 3
 Remove-Item -Path "$env:SystemRoot\$sysMon64.exe"
  Remove-Item -Path "$env:SystemRoot\$sysMon32.exe"
  Remove-Item -Path "$env:SystemRoot\$configFile"
  Start-Sleep -Seconds 3
}
#>
# Copy Files and Install (excludes non sys-mon files)
Get-ChildItem -Path "$ScriptDir" -Exclude *.txt, *.ps1, *.cmd | Select-Object -ExpandProperty FullName |
Copy-Item -Destination "$env:SystemRoot\" -Force
#rm -r sysmon-modular
cd $env:SystemRoot
git clone https://github.com/olafhartong/sysmon-modular.git
cd sysmon-modular
. .\Merge-SysmonXml.ps1
Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml
cp sysmonconfig.xml $env:SystemRoot
cd $env:SystemRoot
if ($OSArch.osarchitecture -eq '64-bit') {
  Start-Process -FilePath "$env:SystemRoot\$sysMon64.exe" -ArgumentList "-accepteula -i $env:SystemRoot\$configFile"
}
else {
  Start-Process -FilePath "$env:SystemRoot\$sysMon32.exe" -ArgumentList "-accepteula -i $env:SystemRoot\$configFile"
}
cd $HOME\Downloads
git clone https://github.com/CydeaTechLtd/cdp-hih-tailer
pip install -r requirements.txt
#Services
nssm install "sysmontailor" %LOCALAPPDATA%\Python37\pythonw.exe "$HOME\Downloads\cdp-hih-tailer\Sysmon_Tailor.py"
nssm set sysmontailor Start SERVICE_DELAYED_AUTO_START
#nssm set sysmontailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "file_watcher" "C:\Windows\System32\WindowsPowerShell\v1\powershell.exe" "$HOME\Downloads\cdp-hih-tailer\file_watcher.ps1"
nssm set file_watcher Start SERVICE_DELAYED_AUTO_START
#nssm set file_watcehr AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "scapytailor" "%LOCALAPPDATA%\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\Scapy_Tailor.py"
nssm set scapytailor Start SERVICE_DELAYED_AUTO_START
#nssm set scapytailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "filetailor" "%LOCALAPPDATA%\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\File_Tailor.py"
nssm set filetailor Start SERVICE_DELAYED_AUTO_START
#nssm set filetailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "readfile" "%LOCALAPPDATA%\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\Read_Logs_From_File.py"#nssm set readfile AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm set readfile Start SERVICE_DELAYED_AUTO_START
#nssm set readfile AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "monitor" "C:\Windows\System32\WindowsPowerShell\v1\powershell.exe" "$HOME\Downloads\cdp-hih-tailer\startup_service_monitor.ps1"
nssm set monitor Start SERVICE_DELAYED_AUTO_START

 #>