; Inno Setup script — Security Monitor Desktop
; Compile with: ISCC.exe installer.iss
; Inno Setup 6+: https://jrsoftware.org/isinfo.php

#define AppName      "Security Monitor"
#define AppVersion   "1.0.0"
#define AppPublisher "Samuel Akpoghene Otobo"
#define AppExeName   "SecurityMonitor.exe"
#define SourceDir    "dist\SecurityMonitor"

[Setup]
AppId={{A3F2C1B0-9E4D-47A8-8F2C-D6E0B1C2A3F4}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL=
AppSupportURL=
AppUpdatesURL=
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
LicenseFile=
OutputDir=dist\installer
OutputBaseFilename=SecurityMonitor_Setup_{#AppVersion}
SetupIconFile=ddos.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0

; Require Npcap for Scapy raw packet capture
[Messages]
WelcomeLabel1=Welcome to {#AppName} Setup
WelcomeLabel2=This will install {#AppName} {#AppVersion} on your computer.%n%nIMPORTANT: Npcap is required for live network packet capture.%n%nClick Next to continue.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";     Description: "Create a desktop shortcut";          GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "startmenuicon";   Description: "Create a Start Menu shortcut";       GroupDescription: "Shortcuts:"
Name: "startupicon";     Description: "Run Security Monitor at Windows startup"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; All files from the PyInstaller --onedir output
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; App icon for shortcuts
Source: "ddos.ico"; DestDir: "{app}"; Flags: ignoreversion

; .env.example so users know what API keys to configure
Source: ".env.example"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Dirs]
; Create writable data dirs in AppData (logs, blocked IPs, geo cache)
Name: "{localappdata}\SecurityMonitor"; Permissions: everyone-modify

[Icons]
Name: "{group}\{#AppName}";                    Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ddos.ico"
Name: "{group}\Uninstall {#AppName}";          Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";              Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ddos.ico"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}";              Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Run]
; Launch the app after install (as administrator — required for Scapy)
Filename: "{app}\{#AppExeName}";
    Description: "Launch {#AppName} now";
    Flags: nowait postinstall skipifsilent runasoriginaluser;

[Registry]
; Add to Windows "Programs and Features" list
Root: HKLM; Subkey: "SOFTWARE\{#AppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[UninstallDelete]
; Clean up generated runtime files on uninstall
Type: filesandordirs; Name: "{app}\*.log"
Type: filesandordirs; Name: "{app}\fim_baseline.json"
Type: filesandordirs; Name: "{app}\blocked_ips.json"
Type: filesandordirs; Name: "{app}\geo_cache.json"
Type: filesandordirs; Name: "{app}\network_map.html"
Type: filesandordirs; Name: "{localappdata}\SecurityMonitor"

[Code]
// Check if Npcap is installed; warn if not (Scapy will not work without it)
function NpcapInstalled: Boolean;
var
  NpcapKey: String;
begin
  NpcapKey := 'SOFTWARE\Npcap';
  Result := RegKeyExists(HKLM, NpcapKey) or RegKeyExists(HKLM64, NpcapKey);
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpWelcome then
  begin
    if not NpcapInstalled then
    begin
      MsgBox(
        'Npcap is not installed on this computer.' + #13#10 + #13#10 +
        'Security Monitor requires Npcap for live packet capture (DDoS detection, ARP monitoring, DNS analysis, etc.).' + #13#10 + #13#10 +
        'Please download and install Npcap from:' + #13#10 +
        'https://npcap.com/#download' + #13#10 + #13#10 +
        'The application will install, but packet-based detectors will be unavailable until Npcap is installed.',
        mbInformation, MB_OK
      );
    end;
  end;
end;
