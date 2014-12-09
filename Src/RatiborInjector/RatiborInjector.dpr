program RatiborInjector;

uses
  Vcl.Forms,
  Main in 'Main.pas' {MainForm},
  CodepageAPI in 'CodepageAPI.pas',
  Ratibor in 'Ratibor.pas',
  RegistryUtils in 'RegistryUtils.pas',
  MappingAPI in '..\# Common Modules\MappingAPI.pas',
  HookAPI in '..\# Common Modules\HookAPI\HookAPI.pas',
  MicroDAsm in '..\# Common Modules\HookAPI\MicroDAsm.pas',
  ProcessAPI in '..\# Common Modules\ProcessAPI.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
