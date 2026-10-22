; ArpCut — Windows installer (Inno Setup 6)
;
; A friendly wizard for non-technical users: installs ArpCut to Program Files,
; optionally installs a licensed Npcap OEM driver, creates shortcuts,
; and requests administrator rights (ArpCut needs them for raw network access).
; On uninstall it flushes any leftover arpcut_* firewall rules.
;
; Build:  iscc /DMyAppVersion=2.0.0 packaging\windows\arpcut.iss
; Expects: dist\ArpCut-<version>.exe  (from `python build.py` on Windows)
; Optional licensed driver: /DBundleNpcapOEM and vendor\npcap-oem.exe

#ifndef MyAppVersion
  #define MyAppVersion "2.0.0"
#endif
#define MyAppName "ArpCut"
#define MyAppExe "ArpCut.exe"
#define MyAppPublisher "ArpCut"
#define MyAppURL "https://github.com/Mvgnu/ArpCut"

; Redistribution and /S require Npcap OEM. Default builds contain no Npcap;
; users install it from https://npcap.com/#download. To bundle a licensed OEM
; redistribution package, explicitly pass /DBundleNpcapOEM at compile time.
#define NpcapVendor "vendor\npcap-oem.exe"
#ifdef BundleNpcapOEM
  #if !FileExists(AddBackslash(SourcePath) + NpcapVendor)
    #error BundleNpcapOEM requires vendor\npcap-oem.exe
  #endif
  #define HaveNpcap
#endif

[Setup]
AppId={{7C3A2F10-ARPC-4C0T-9A11-ARPCUT000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExe}
OutputDir=..\..\dist
OutputBaseFilename=ArpCut-{#MyAppVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; ArpCut needs admin for raw sockets / firewall rules.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\..\dist\ArpCut-{#MyAppVersion}.exe"; DestDir: "{app}"; DestName: "{#MyAppExe}"; Flags: ignoreversion
#ifdef HaveNpcap
Source: "{#NpcapVendor}"; DestDir: "{tmp}"; DestName: "npcap-oem.exe"; Flags: deleteafterinstall; Check: NpcapMissing
#endif

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
#ifdef HaveNpcap
; Silently install Npcap in WinPcap-compatible mode if it isn't already present.
Filename: "{tmp}\npcap-oem.exe"; Parameters: "/S /winpcap_mode=yes"; StatusMsg: "Installing the Npcap capture driver..."; Check: NpcapMissing; Flags: waituntilterminated
#endif
Filename: "{app}\{#MyAppExe}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Flush any ArpCut firewall rules left behind (runs before files are removed).
Filename: "{app}\{#MyAppExe}"; Parameters: "--flush-firewall"; Flags: runhidden; RunOnceId: "FlushArpcutRules"

[Code]
function NpcapMissing: Boolean;
begin
  { Npcap installs its service under this registry key. }
  Result := not RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap');
end;
