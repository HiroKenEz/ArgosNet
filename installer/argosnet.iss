; Script d'installeur Inno Setup pour ArgosNet.
;
; Génère un « ArgosNet-Setup-<version>.exe » à partir du dossier autonome produit par
; Nuitka (--standalone). Prérequis : avoir d'abord compilé l'application et renommé le
; binaire (voir DISTRIBUTION.md §2), de sorte que build_nuitka\run.dist\ArgosNet.exe
; existe.
;
; Compilation de l'installeur (Inno Setup 6, gratuit) :
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\argosnet.iss
; ou via l'IDE Inno Setup (Compile). Le setup produit se trouve dans installer\Output\.
;
; Chemins relatifs à l'emplacement de ce script (dossier installer\).

#define MyAppName "ArgosNet"
#define MyAppVersion "0.1.0"          ; à garder en phase avec argosnet/__init__.py
#define MyAppPublisher "ArgosNet"
#define MyAppURL "https://github.com/HiroKenEz/ArgosNet"
#define MyAppExeName "ArgosNet.exe"
#define MyDistDir "..\build_nuitka\run.dist"
#define MyIcon "..\argosnet\resources\argosnet.ico"

[Setup]
AppId={{A9F3C7E1-4B2D-4E56-9C1A-7F0E2D1B3C45}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=ArgosNet-Setup-{#MyAppVersion}
SetupIconFile={#MyIcon}
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; La capture/scan exige les privilèges administrateur ; installation pour tous les
; utilisateurs dans Program Files.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Tout le dossier autonome Nuitka (exécutable + DLL + données embarquées).
Source: "{#MyDistDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Proposer de lancer l'application à la fin de l'installation.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
