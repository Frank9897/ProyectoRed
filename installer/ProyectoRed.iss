; Instalador de ProyectoRed para Windows x64
;
; Requiere haber ejecutado publicar-windows.bat.
;
; Npcap no se incluye en el repositorio porque la edicion gratuita
; no concede derechos generales de redistribucion. Con una licencia
; Npcap OEM, el instalador OEM puede incorporarse localmente en:
; installer\dependencies\npcap-oem.exe

#define AppName "ProyectoRed"
#define AppVersion "0.1.0"
#define AppPublisher "ProyectoRed"
#define AppExeName "ProyectoRed.Web.exe"
#define PublishDir "..\dist\windows-x64"

[Setup]
AppId={{8F9D7A1B-3A4A-4A1C-9F4C-4F2D9B5C7E21}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\ProyectoRed
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=dist
OutputBaseFilename=ProyectoRed-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExeName}

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\ProyectoRed"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\ProyectoRed"; Filename: "{app}\{#AppExeName}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Iniciar ProyectoRed"; Flags: nowait postinstall skipifsilent

; Cuando exista un instalador Npcap OEM con derechos de redistribucion,
; puede ejecutarse antes de ProyectoRed descomentando y adaptando:
; Filename: "{tmp}\npcap-oem.exe"; Parameters: "/S"; StatusMsg: "Instalando Npcap..."; Flags: waituntilterminated

[Code]
function NpcapInstalado(): Boolean;
begin
  Result :=
    RegKeyExists(
      HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Services\npcap');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and not NpcapInstalado() then
  begin
    MsgBox(
      'ProyectoRed fue instalado correctamente.' + #13#10#13#10 +
      'No se detecto Npcap en Windows. La aplicacion web puede abrirse,' +
      ' pero la captura Ethernet no funcionara hasta instalar Npcap.' + #13#10#13#10 +
      'Despues de instalar Npcap, vuelva a ejecutar ProyectoRed.',
      mbInformation,
      MB_OK);
  end;
end;