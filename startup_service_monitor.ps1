#STARTUP watcher
$triggered = New-JobTrigger -AtStartup -RandomDelay 00:00:30
Register-ScheduledJob -Trigger $triggered -FilePath SHOME\startup_service_monitor.ps1 -Name WatcherService

$triggered1 = New-JobTrigger -AtStartup -RandomDelay 00:00:30
Register-ScheduledJob -Trigger $triggered1 -FilePath $HOME\Downloads\cdp-hih-tailer\file_watcher.ps1 -Name File_handler
#$ipV4 = Test-Connection -ComputerName (hostname) -Count 1  | Select IPV4Address

refreshevn


#Environment variables
[Environment]::SetEnvironmentVariable("SIEM_PORT","5170","Machine") 
[Environment]::SetEnvironmentVariable("SIEM","58.65.161.140","Machine")
[Environment]::SetEnvironmentVariable("EVTX_LOGS_PATH","C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx","Machine") 
#[Environment]::SetEnvironmentVariable("CERTIFICATE_PATH","C:\Users\ijlal\Downloads\cdp-hih-tailer\ssl\cert.pem","Machine") 
#[Environment]::SetEnvironmentVariable("CERTIFICATE_PASSWORD","cydea123","Machine") 
[Environment]::SetEnvironmentVariable("SYSMON_LOG_FILE","$HOME\Downloads\cdp-hih-tailer\sysmon.json","Machine")
[Environment]::SetEnvironmentVariable("SCAP Y_LOG_FILE","$HOME\Downloads\cdp-hih-tailer\scapy.json","Machine")
[Environment]::SetEnvironmentVariable("SERVER_ADDRESS","localhost","Machine") 
[Environment]::SetEnvironmentVariable("FILE_LOGS","$HOME\Downloads\cdp-hih-tailer\FileWatcher_Log.json","Machine")
[Environment]::SetEnvironmentVariable("FILE_LOGS_PATH","$HOME\Downloads\cdp-hih-tailer\FileWatcher_Log.txt","Machine")
[Environment]::SetEnvironmentVariable("organization","9c663c60-150a-468d-aa72-54778049a177","Machine")
#[Environment]::SetEnvironmentVariable("CERTIFICATE_PATH","C:\Users\ijlal\Downloads\cdp-hih-tailer\ssl\cert.pem","Machine") 
#[Environment]::SetEnvironmentVariable("CERTIFICATE_PASSWORD","cydea123","Machine") 	
cd $HOME\Downloads
git clone https://github.com/CydeaTechLtd/cdp-hih-tailer
cd cdp-hih-tailer
pip install -r requirements.txt
#Services
nssm install "sysmontailor" "C:\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\Sysmon_Tailor.py"
nssm set sysmontailor Start SERVICE_DELAYED_AUTO_START
#nssm set sysmontailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "file_watcher" "C:\Windows\System32\WindowsPowerShell\v1\powershell.exe" "$HOME\Downloads\cdp-hih-tailer\file_watcher.ps1"
nssm set file_watcher Start SERVICE_DELAYED_AUTO_START
#nssm set file_watcehr AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "scapytailor" "C:\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\Scapy_Tailor.py"
nssm set scapytailor Start SERVICE_DELAYED_AUTO_START
#nssm set scapytailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "filetailor" "C:\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\File_Tailor.py"
nssm set filetailor Start SERVICE_DELAYED_AUTO_START
#nssm set filetailor AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "readfile" "C:\Python37\pythonw.exe" "$HOME\Downloads\cdp-hih-tailer\Read_Logs_From_File.py"#nssm set readfile AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm set readfile Start SERVICE_DELAYED_AUTO_START
#nssm set readfile AppDirectory "$HOME\Downloads\cdp-hih-tailer"
nssm install "watcher" "C:\Windows\System32\WindowsPowerShell\v1\powershell.exe" "$HOME\Downloads\cdp-hih-tailer\startup_service_monitor.ps1"
nssm set monitor Start SERVICE_DELAYED_AUTO_START

 #>

#Service creation
#cd C:\Users\ijlal\Downloads\cdp-hih-tailer
#pyinstaller.exe -F --hidden-import=json,ssl,scapy,logging C:\Users\ijlal\Downloads\cdp-hih-tailer\Scapy_Tailor.py
#sc.exe create scapytailor binpath=C:\Users\ijlal\Downloads\cdp-hih-tailer\dist\Scapy_Tailor.exe start=auto

#cd C:\Users\ijlal\Downloads\cdp-hih-tailer
#pyinstaller.exe -F --hidden-import=json,python-evtx,ssl,socket,xmltodict,evtx,os,time,logging C:\Users\ijlal\Downloads\cdp-hih-tailer\Sysmon_Tailor.py
#sc.exe create sysmontailor binpath=C:\Users\ijlal\Downloads\cdp-hih-tailer\dist\Sysmon_Tailor.exe start=auto

#cd C:\Users\ijlal\Downloads\cdp-hih-tailer
#pyinstaller.exe -F --hidden-import=tailer,json,os,socket,logging,ssl C:\Users\ijlal\Downloads\cdp-hih-tailer\File_Tailor.py
#sc.exe create filetailor binpath=C:\Users\ijlal\Downloads\cdp-hih-tailer\dist\File_Tailor.exe start=auto

#cd C:\Users\ijlal\Downloads\cdp-hih-tailer
#pyinstaller.exe -F --hidden-import=json,os,socket,logging,ssl,schedule C:\Users\ijlal\Downloads\cdp-hih-tailer\Reading_Logs_From_File.py
#sc.exe create readfile binpath=C:\Users\ijlal\Downloads\cdp-hih-tailer\dist\Scapy_Tailor.exe start=auto
# This Script Check the Status of Sysmon64
# If Script is STOPPED it START it and IF Script is RUNNING then it just say "Service in Running"
$A = get-service Sysmon64
$sysmontailor= get-service sysmontailor
$filetailor= get-service filetailor
$scapytailor= get-service scapytailor
$readfile= get-service readfile
$file_watcher= get-service file_watcher
if ($A.Status -eq "Stopped") {$A.start()} elseIf ($A.status -eq "Running") {Write-Host -ForegroundColor Yellow $A.name "is running"}
if ($sysmontailor.Status -eq "Stopped") {$sysmontailor.start()} elseIf ($sysmontailor.status -eq "Running") {Write-Host -ForegroundColor Yellow $sysmontailor.name "is running"}
if ($scapytailor.Status -eq "Stopped") {$scapytailor.start()} elseIf ($scapytailor.status -eq "Running") {Write-Host -ForegroundColor Yellow $scapytailor.name "is running"}
if ($filetailor.Status -eq "Stopped") {$filetailor.start()} elseIf ($filetailor.status -eq "Running") {Write-Host -ForegroundColor Yellow $filetailor.name "is running"}
if ($readfile.Status -eq "Stopped") {$readfile.start()} elseIf ($readfile.status -eq "Running") {Write-Host -ForegroundColor Yellow $readfile.name "is running"}
if ($file_watcher.Status -eq "Stopped") {$file_watcher.start()} elseIf ($file_watcher.status -eq "Running") {Write-Host -ForegroundColor Yellow $file_watcher.name "is running"}

