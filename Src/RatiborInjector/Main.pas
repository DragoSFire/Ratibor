unit Main;

interface

uses
  Windows, SysUtils, Classes, Controls, Forms, StdCtrls, ExtCtrls,
  HookAPI, ProcessAPI, MappingAPI, Ratibor, RegistryUtils;

type
  TMainForm = class(TForm)
    ProcessIDEdit: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    SelfProcessIDButton: TButton;
    TargetProcessEdit: TEdit;
    InjectToAllProcessesCheckBox: TCheckBox;
    InjectButton: TButton;
    UnInjectButton: TButton;
    HideCheckbox: TCheckBox;
    FlushCheckbox: TCheckBox;
    ConvertProcessNameToProcessIdButton: TButton;
    RadioGroup: TRadioGroup;
    ProcessNameEdit: TEdit;
    SaveButton: TButton;
    procedure SelfProcessIDButtonClick(Sender: TObject);
    procedure InjectToAllProcessesCheckBoxClick(Sender: TObject);
    procedure InjectButtonClick(Sender: TObject);
    procedure UnInjectButtonClick(Sender: TObject);
    procedure ConvertProcessNameToProcessIdButtonClick(Sender: TObject);
    procedure SaveButtonClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  end;

var
  MainForm: TMainForm;


implementation

{$R *.dfm}


var
  MappingObject: THandle = 0; // Дескриптор файлового отображения

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

procedure TMainForm.FormCreate(Sender: TObject);
begin
  ProcessIDEdit.Text := ReadStringFromRegistry('HookAPI', 'ProtectedID', IntToStr(GetCurrentProcessID));
  ProcessNameEdit.Text := ReadStringFromRegistry('HookAPI', 'TargetProcessName', 'Taskmgr.exe');
  TargetProcessEdit.Text := ReadStringFromRegistry('HookAPI', 'TargetProcessID', '0');
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TMainForm.SaveButtonClick(Sender: TObject);
begin
  SaveStringToRegistry('HookAPI', 'ProtectedID', ProcessIDEdit.Text);
  SaveStringToRegistry('HookAPI', 'TargetProcessName', ProcessNameEdit.Text);
  SaveStringToRegistry('HookAPI', 'TargetProcessID', TargetProcessEdit.Text);
  MessageBox(Handle, 'Настройки успешно сохранены!', 'Успешно!', MB_ICONASTERISK);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

procedure TMainForm.ConvertProcessNameToProcessIdButtonClick(Sender: TObject);
var
  ProcessInfo: PROCESS_INFO;
  TlHelp32ProcessInfo: TProcessInfo;
begin
  TlHelp32ProcessInfo := GetTlHelp32ProcessInfo(WideStringToString(ProcessNameEdit.Text, 0));
  GetProcessInfo(TlHelp32ProcessInfo.ProcessID, ProcessInfo);
  TargetProcessEdit.Text := IntToStr(ProcessInfo.ID);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TMainForm.InjectToAllProcessesCheckBoxClick(Sender: TObject);
begin
  TargetProcessEdit.Enabled := not InjectToAllProcessesCheckBox.Checked;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TMainForm.SelfProcessIDButtonClick(Sender: TObject);
begin
  ProcessIDEdit.Text := IntToStr(GetCurrentProcessID);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

procedure TMainForm.InjectButtonClick(Sender: TObject);
var
  HookInfo: THookInfo;
begin
  // Настраиваем структуру перехвата:
  HookInfo.ProtectedProcess := StrToInt(ProcessIDEdit.Text);
  HookInfo.HideProcess := HideCheckbox.Checked;
  HookInfo.FlushProcessInfo := FlushCheckbox.Checked;
  HookInfo.InvalidateProcessID := RadioGroup.ItemIndex;

  // Записываем структуру в отображаемую память:
  MappingObject := SetDefenceParameters(HookInfo, MappingObject);

  // Запускаем защиту:
  if InjectToAllProcessesCheckBox.Checked then
  begin
    StartDefence;
  end
  else
  begin
    {$IFDEF CPUX64}
      InjectDLL64(
                   StrToInt(TargetProcessEdit.Text),
                   PAnsiChar(WideStringToString(ExtractFilePath(Application.ExeName), 0) + '\' + LibName)
                  );
    {$ELSE}
      InjectDLL32(
                   StrToInt(TargetProcessEdit.Text),
                   PAnsiChar(WideStringToString(ExtractFilePath(Application.ExeName), 0) + '\' + LibName)
                  );
    {$ENDIF}
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure TMainForm.UnInjectButtonClick(Sender: TObject);
begin
  // Останавливаем защиту:
  StopDefence;

  // Выгружаем библиотеку:
  if not InjectToAllProcessesCheckBox.Checked then
  begin
    {$IFDEF CPUX64}
      UnloadDLL64(StrToInt(TargetProcessEdit.Text), PAnsiChar(LibName));
    {$ELSE}
      UnloadDLL32(StrToInt(TargetProcessEdit.Text), PAnsiChar(LibName));
    {$ENDIF}
  end;

  // Закрываем файловое отображение:
  CloseFileMapping(MappingObject);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

end.
