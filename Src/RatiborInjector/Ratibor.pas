unit Ratibor;

interface

uses
  MappingAPI;

type
  THookInfo = packed record
    ProtectedProcess    : LongWord;
    HideProcess         : Boolean;
    FlushProcessInfo    : Boolean;
    InvalidateProcessID : Byte;
  end;

const
  ORIGINAL_PROCESS_ID                  = 0;
  INVALIDATE_PROCESS_ID                = 1;
  SET_PROCESS_ID_TO_CURRENT_PROCESS_ID = 2;
  RANDOMIZE_PROCESS_ID                 = 3;

function SetDefenceParameters(
                               const HookInfo: THookInfo;
                               MappingObject: THandle = 0
                              ): THandle;

const
  {$IFDEF CPUX64}
    LibName = 'RatiborLib64.dll';
  {$ELSE}
    LibName = 'RatiborLib32.dll';
  {$ENDIF}

procedure StartDefence; stdcall; external LibName;
procedure StopDefence; stdcall; external LibName;

implementation

function SetDefenceParameters(const HookInfo: THookInfo; MappingObject: THandle = 0): THandle;
var
  MappedMemory: Pointer;
begin
  if MappingObject <> 0 then CloseFileMapping(MappingObject);

  Result := CreateFileMapping('HookAPI', SizeOf(HookInfo));
  if Result = 0 then Exit;

  MappedMemory := GetMappedMemory(Result);

  WriteMemory(@HookInfo, MappedMemory, 0, SizeOf(HookInfo));
  FreeMappedMemory(MappedMemory);
end;

end.
