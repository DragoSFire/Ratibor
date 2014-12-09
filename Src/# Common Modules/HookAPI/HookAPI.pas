unit HookAPI;

interface

{$DEFINE RTL_READ_WRITE} // Использовать Move вместо NtRead[Write]VirtualMemory
{$DEFINE USE_LDASM}      // Использовать дизассемблер длин

uses
  Windows, TlHelp32, PSAPI {$IFDEF USE_LDASM}, MicroDAsm{$ENDIF};


const
  SE_DEBUG_NAME         = 'SeDebugPrivilege';
  SE_SHUTDOWN_NAME      = 'SeShutdownPrivilege';
  THREAD_SUSPEND_RESUME = $0002;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

{$IFDEF CPUX64}
// Структура для х64:
type
  TFarJump = packed record
    MovR11Op  : Word;                 //                   49 BB | mov r11
    MovR11Arg : Pointer;              // 88 77 66 55 44 33 22 11 | qword $1122334455667788
    JmpR11Op  : array [0..2] of Byte; //                41 FF E3 | jmp r11
  end;

  NativeInt  = Int64;
  NativeUInt = UInt64;
{$ELSE}
// Структура для х32:
type
  TFarJump = packed record
    JmpOp  : Byte;    //          E9 | jmp
    JmpArg : Pointer; // 44 33 22 11 | dword $11223344
  end;

  NativeInt  = Integer;
  NativeUInt = LongWord;
{$ENDIF}

type
  TOriginalBlock = Pointer;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Установка привилегий:
function NTSetPrivilege(sPrivilege: string; bEnabled: Boolean): Boolean;

// Внедрение библиотеки:
function InjectDll32(ProcessID: LongWord; ModulePath: PAnsiChar): Boolean;
function InjectDll64(ProcessID: LongWord; ModulePath: PAnsiChar): Boolean;

// Выгрузка библиотеки:
function UnloadDll32(ProcessID: LongWord; ModuleName: PAnsiChar): Boolean;
function UnloadDll64(ProcessID: LongWord; ModuleName: PAnsiChar): Boolean;

// Для DLL:
procedure StopThreads;
procedure RunThreads;
function  SetHook(OriginalProcAddress: Pointer; NewProcAddress: Pointer; out OriginalBlock: TOriginalBlock; SuspendThreads: Boolean = True): Boolean;
function UnHook(OriginalProcAddress: Pointer; var OriginalBlock: TOriginalBlock; SuspendThreads: Boolean = True): Boolean;
function  HookEmAll(out GlobalHookHandle: THandle): Boolean;
procedure UnHookEmAll(var GlobalHookHandle: THandle);

// Инъекция шелл-кода напрямую:
procedure InjectFunction(ProcessID: LongWord; InjectedFunction: Pointer; InjectedFunctionSize: NativeUInt);

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


implementation

type
  NTSTATUS = LongWord;

function NtWriteVirtualMemory(
                               hProcess: THandle;
                               BaseAddress: Pointer;
                               Buffer: Pointer;
                               BufferLength: NativeUInt;
                               out ReturnLength: NativeUInt
                              ): NTSTATUS; stdcall; external 'ntdll.dll';


function NtReadVirtualMemory(
                              hProcess: THandle;
                              BaseAddress: Pointer;
                              Buffer: Pointer;
                              BufferSize: NativeUInt;
                              out ReturnLength: NativeUInt
                             ): NTSTATUS; stdcall; external 'ntdll.dll';


function OpenThread(
                     dwDesiredAccess: LongWord;
                     bInheritHandle: LongBool;
                     dwThreadId: LongWord
                    ): LongWord; stdcall; external 'kernel32.dll';


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


// Установка привилегий для работы с чужими процессами:
function NTSetPrivilege(sPrivilege: string; bEnabled: Boolean): Boolean;
var
  hToken: THandle;
  TokenPriv: TOKEN_PRIVILEGES;
  PrevTokenPriv: TOKEN_PRIVILEGES;
  ReturnLength: Cardinal;
begin
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, hToken) then
  begin
    if LookupPrivilegeValue(nil, PChar(sPrivilege), TokenPriv.Privileges[0].Luid) then
    begin
      TokenPriv.PrivilegeCount := 1;
      case bEnabled of
        True: TokenPriv.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
        False: TokenPriv.Privileges[0].Attributes := 0;
      end;
      ReturnLength := 0;
      PrevTokenPriv := TokenPriv;
      AdjustTokenPrivileges(hToken, False, TokenPriv, SizeOf(PrevTokenPriv),
      PrevTokenPriv, ReturnLength);
    end;
    CloseHandle(hToken);
  end;
  Result := GetLastError = ERROR_SUCCESS;
end;


(* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Оригинальная функция:
procedure LoadHookLib32;
const
  HookLib: PAnsiChar = 'HookLib.dll';
asm
  push HookLib
  call LoadLibraryA

  xor eax, eax
  push eax
  call ExitThread
end;

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *)

// Инъекция в 32х-битные процессы:
function InjectDll32(ProcessID: LongWord; ModulePath: PAnsiChar): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: LongWord;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: LongWord;

  DataOffset: LongWord;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    // GMH* = GetModuleHandle:  { 11 байт }
    GMHPushCommand: Byte;
    GMHPushArgument: LongWord;
    GMHCallCommand: Word;
    GMHCallAddr: LongWord;

    TestEaxEaxCommand: Word;    { 8 байт }
    JnzCommand: Word;
    JnzArgument: Pointer;

    // LL* = LoadLibrary:       { 11 байт }
    LLPushCommand: Byte;
    LLPushArgument: LongWord;
    LLCallCommand: Word;
    LLCallAddr: LongWord;

    // ET* = ExitThread:        { 11 байт }
    ETPushCommand: Byte;
    ETPushArgument: LongWord;
    ETCallCommand: Word;
    ETCallAddr: LongWord;

    AddrGetModuleHandle: LongWord;
    AddrLoadLibrary: LongWord;
    AddrExitThread: LongWord;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;

  // Расчёт относительно адреса для прыжка в х32 ( 85 0F [ Относительный адрес ] )
  function GetRelativeJmp32Address(Source, Destination: Pointer): Pointer; inline;
  begin
    Result := Pointer(NativeInt(Destination) - NativeInt(Source) - 5);
  end;

  // Получает путь к папке:
  function ExtractFilePath(Path: AnsiString): AnsiString; inline;
  var
    I: LongWord;
    PathLen: LongWord;
  begin
    PathLen := Length(Path);
    I := PathLen;
    while (I <> 0) and (Path[I] <> '\') and (Path[I] <> '/') do Dec(I);
    Result := Copy(Path, 0, I);
  end;

begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

  // Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := LongWord(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

  DataOffset := Code + 41;

// GetModuleHandleA:
  Inject.GMHPushCommand := $68;
  Inject.GMHPushArgument := DataOffset + 12 + Cardinal(Length(ExtractFilePath(ModulePath)));
  Inject.GMHCallCommand := $15FF;
  Inject.GMHCallAddr := DataOffset;

  Inject.TestEaxEaxCommand := $C085;
  Inject.JnzCommand := $850F;
  Inject.JnzArgument := GetRelativeJmp32Address(Pointer(NativeUInt(Code) + 14), Pointer(NativeUInt(Code) + 30));

// LoadLibraryA:
  Inject.LLPushCommand  := $68;
  Inject.LLPushArgument := DataOffset + 12;
  Inject.LLCallCommand  := $15FF;
  Inject.LLCallAddr     := DataOffset + 4;

// ExitThread:
  Inject.ETPushCommand  := $68;
  Inject.ETPushArgument := 0;
  Inject.ETCallCommand  := $15FF;
  Inject.ETCallAddr     := DataOffset + 8;

  hKernel32 := GetModuleHandle('kernel32.dll');
  Inject.AddrGetModuleHandle := LongWord(GetProcAddress(hKernel32, 'GetModuleHandleA'));
  Inject.AddrLoadLibrary := LongWord(GetProcAddress(hKernel32, 'LoadLibraryA'));
  Inject.AddrExitThread  := LongWord(GetProcAddress(hKernel32, 'ExitThread'));

  Move(ModulePath^, Inject.LibraryName, Length(ModulePath));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Выгрузка библиотеки из 32х-битных процессов:
function UnloadDll32(ProcessID: LongWord; ModuleName: PAnsiChar): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: LongWord;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: LongWord;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    // GMH* = GetModuleHandle:
    GMHPushCommand: Byte;
    GMHPushArgument: LongWord;
    GMHCallCommand: Word;
    GMHCallAddr: LongWord;

    // FL* = FreeLibrary:
    FLPushEax: Byte;
    FLCallCommand: Word;
    FLCallAddr: LongWord;

    // ET* = ExitThread:
    ETPushCommand: Byte;
    ETPushArgument: LongWord;
    ETCallCommand: Word;
    ETCallAddr: LongWord;

    AddrGetModuleHandle: LongWord;
    AddrFreeLibrary: LongWord;
    AddrExitThread: LongWord;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

  // Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := LongWord(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// GetModuleHandleA:
  Inject.GMHPushCommand  := $68;
  Inject.GMHPushArgument := Code + 41;
  Inject.GMHCallCommand  := $15FF;
  Inject.GMHCallAddr     := Code + 29;

// FreeLibrary:
  Inject.FLPushEax     := $50;
  Inject.FLCallCommand := $15FF;
  Inject.FLCallAddr    := Code + 33;

// ExitThread:
  Inject.ETPushCommand  := $68;
  Inject.ETPushArgument := 0;
  Inject.ETCallCommand  := $15FF;
  Inject.ETCallAddr     := Code + 37;

  hKernel32 := GetModuleHandle('kernel32.dll');
  Inject.AddrGetModuleHandle := LongWord(GetProcAddress(hKernel32, 'GetModuleHandleA'));
  Inject.AddrFreeLibrary := LongWord(GetProcAddress(hKernel32, 'FreeLibrary'));
  Inject.AddrExitThread  := LongWord(GetProcAddress(hKernel32, 'ExitThread'));

  Move(ModuleName^, Inject.LibraryName, Length(ModuleName));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;


(* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
{
  Передача параметров в х64-функции:

  RCX - первый параметр
  RDX - второй параметр
  R8 - третий параметр
  R9 - четвёртый параметр

  Остальное через стек в соответствии с соглашением о вызове

  Стек необходимо выравнивать при входе в функцию:
  asm
    push rbp
    sub rsp, $20
    mov rbp, rsp

    ...

    lea rsp, [rbp+$20]
    pop rbp
    ret
  end;
}

// Оригинальная функция:
procedure LoadHookLib64;
const
  HookLib: PAnsiChar = 'HookLib.dll';
asm
  push rbp
  sub rsp, $20
  mov rbp, rsp

  mov rcx, HookLibName
  call GetModuleHandleA

  test rax, rax
  jnz @Exit

  mov rcx, HookLib
  call LoadLibraryA

@Exit:
  mov rcx, $0000000000000000
  call ExitThread

  lea rsp, [rbp+$20]
  pop rbp
  ret
end;

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *)


// Инъекция в 64х-битные процессы:
function InjectDll64(ProcessID: LongWord; ModulePath: PAnsiChar): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: UInt64;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: NativeUInt;

  DataOffset: UInt64;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    AlignStackAtStart: UInt64;    { 8 байт }

    // GMH* = GetModuleHandle:    { 28 байт }
    GMHMovRaxCommand: Word;
    GMHMovRaxArgument: UInt64;
    GMHMovRaxData: array [0..2] of Byte;
    GMHMovRcxCommand: Word;
    GMHMovRcxArgument: UInt64;
    GMHCallRax: array [0..2] of Byte;

                                  { 13 байт }
    TestRaxRaxCommand: array [0..2] of Byte;
    JnzCommand: Word;
    JnzArgument: LongWord;

    // LL* = LoadLibrary:         { 28 байт }
    LLMovRaxCommand: Word;
    LLMovRaxArgument: UInt64;
    LLMovRaxData: array [0..2] of Byte;
    LLMovRcxCommand: Word;
    LLMovRcxArgument: UInt64;
    LLCallRax: array [0..2] of Byte;

    // ET* = ExitThread:          { 28 байт }
    ETMovRaxCommand: Word;
    ETMovRaxArgument: UInt64;
    ETMovRaxData: array [0..2] of Byte;
    ETMovRcxCommand: Word;
    ETMovRcxArgument: UInt64;
    ETCallRax: array [0..2] of Byte;

    AlignStackAtEnd: UInt64;      { 8 байт }

    NopAlignByte: Byte;

    AddrGetModuleHandle: UInt64;
    AddrLoadLibrary: UInt64;
    AddrExitThread: UInt64;
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;

  // Расчёт относительно адреса для прыжка в х32 ( 85 0F [ Относительный адрес ] )
  function GetRelativeJmp32Address(Source, Destination: Pointer): Pointer; inline;
  begin
    Result := Pointer(NativeInt(Destination) - NativeInt(Source) - 5);
  end;

  // Получает путь к папке:
  function ExtractFilePath(Path: AnsiString): AnsiString; inline;
  var
    I: LongWord;
    PathLen: LongWord;
  begin
    PathLen := Length(Path);
    I := PathLen;
    while (I <> 0) and (Path[I] <> '\') and (Path[I] <> '/') do Dec(I);
    Result := Copy(Path, 0, I);
  end;

begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

// Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := UInt64(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

  DataOffset := Code + 104;

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtStart := $E5894820EC834855;

{
   + - - - - - - - - - - - +
   |  RAX - адрес функции  |
   |  RCX - параметры      |
   + - - - - - - - - - - - +
}

// GetModuleHandleA:
  Inject.GMHMovRaxCommand := $B848;
  Inject.GMHMovRaxArgument := DataOffset; // Code + смещение до адреса GetModuleHandleA

  Inject.GMHMovRaxData[0] := $48; //  ---+
  Inject.GMHMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.GMHMovRaxData[2] := $00; //  ---+

  Inject.GMHMovRcxCommand := $B948;
  Inject.GMHMovRcxArgument := DataOffset + 24 + Cardinal(Length(ExtractFilePath(ModulePath))); // Code + смещение до начала пути к библиотеке

  Inject.GMHCallRax[0] := $48;
  Inject.GMHCallRax[1] := $FF;
  Inject.GMHCallRax[2] := $D0;


  Inject.TestRaxRaxCommand[0] := $48; // ---+
  Inject.TestRaxRaxCommand[1] := $85; // ---+---> test RAX, RAX
  Inject.TestRaxRaxCommand[2] := $C0; // ---+

  Inject.JnzCommand := $850F; // jnz @ExitThread
  Inject.JnzArgument := LongWord(GetRelativeJmp32Address(Pointer(NativeUInt(Code) + 46), Pointer(NativeUInt(Code) + 77)));


// LoadLibraryA:
  Inject.LLMovRaxCommand := $B848;
  Inject.LLMovRaxArgument := DataOffset + 8; // Code + смещение до адреса LoadLibraryA

  Inject.LLMovRaxData[0] := $48; //  ---+
  Inject.LLMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.LLMovRaxData[2] := $00; //  ---+

  Inject.LLMovRcxCommand := $B948;
  Inject.LLMovRcxArgument := DataOffset + 24; // Code + смещение до начала пути к библиотеке

  Inject.LLCallRax[0] := $48;
  Inject.LLCallRax[1] := $FF;
  Inject.LLCallRax[2] := $D0;

// ExitThread:
  Inject.ETMovRaxCommand := $B848;
  Inject.ETMovRaxArgument := DataOffset + 16; // Code + смещение до адреса ExitThread

  Inject.ETMovRaxData[0] := $48; //  ---+
  Inject.ETMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.ETMovRaxData[2] := $00; //  ---+

  Inject.ETMovRcxCommand := $B948;
  Inject.ETMovRcxArgument := $0000000000000000; // ExitCode = 0

  Inject.ETCallRax[0] := $48;
  Inject.ETCallRax[1] := $FF;
  Inject.ETCallRax[2] := $D0;

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtEnd := $90C3C35D20658D48;

  Inject.NopAlignByte := $90;

// Записываем адреса библиотек:
  hKernel32 := LoadLibrary('kernel32.dll');
  Inject.AddrGetModuleHandle := UInt64(GetProcAddress(hKernel32, 'GetModuleHandleA'));
  Inject.AddrLoadLibrary := UInt64(GetProcAddress(hKernel32, 'LoadLibraryA'));
  Inject.AddrExitThread  := UInt64(GetProcAddress(hKernel32, 'ExitThread'));

  Move(ModulePath^, Inject.LibraryName, Length(ModulePath));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Выгрузка библиотеки из 64х-битных процессов:
function UnloadDll64(ProcessID: LongWord; ModuleName: PAnsiChar): Boolean;
var
  ProcessHandle: NativeUInt;
  Memory: Pointer;
  Code: UInt64;
  BytesWritten: NativeUInt;
  ThreadId: LongWord;
  hThread: LongWord;
  hKernel32: NativeUInt;

  // Структура машинного кода инициализации и запуска библиотеки:
  Inject: packed record
    AlignStackAtStart: UInt64;            // 8

    // GMH* = GetModuleHandle:
    GMHMovRaxCommand: Word;               // 2
    GMHMovRaxArgument: UInt64;            // 8
    GMHMovRaxData: array [0..2] of Byte;  // 3
    GMHMovRcxCommand: Word;               // 2
    GMHMovRcxArgument: UInt64;            // 8
    GMHCallRax: array [0..2] of Byte;     // 3

    // FL* = FreeLibrary:
    FLMovRcxRax: array [0..2] of Byte;    // 3
    FLMovRaxCommand: Word;                // 2
    FLMovRaxArgument: UInt64;             // 8
    FLMovRaxData: array [0..2] of Byte;   // 3
    FLCallRax: array [0..2] of Byte;      // 3

    // ET* = ExitThread:
    ETMovRaxCommand: Word;                // 2
    ETMovRaxArgument: UInt64;             // 8
    ETMovRaxData: array [0..2] of Byte;   // 3
    ETMovRcxCommand: Word;                // 2
    ETMovRcxArgument: UInt64;             // 8
    ETCallRax: array [0..2] of Byte;      // 3

    AlignStackAtEnd: UInt64;              // 8

    AddrGetModuleHandle: UInt64;          // 8
    AddrFreeLibrary: UInt64;              // 8
    AddrExitThread: UInt64;               // 8
    LibraryName: array [0..MAX_PATH] of AnsiChar;
  end;
begin
  Result := false;

  ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if ProcessHandle = 0 then Exit;

// Выделяем память в контексте процесса, куда запишем код вызова библиотеки перехватчика:
  Memory := VirtualAllocEx(ProcessHandle, nil, SizeOf(Inject), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if Memory = nil then Exit;

  Code := UInt64(Memory);
  FillChar(Inject, SizeOf(Inject), #0);

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtStart := $E5894820EC834855;

{
   + - - - - - - - - - - - +
   |  RAX - адрес функции  |
   |  RCX - параметры      |
   + - - - - - - - - - - - +
}

// GetModuleHandleA:
  Inject.GMHMovRaxCommand := $B848;
  Inject.GMHMovRaxArgument := Code + 87; // Code + смещение до адреса GetModuleHandleA

  Inject.GMHMovRaxData[0] := $48; //  ---+
  Inject.GMHMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.GMHMovRaxData[2] := $00; //  ---+

  Inject.GMHMovRcxCommand := $B948;
  Inject.GMHMovRcxArgument := Code + 111; // Code + смещение до начала имени библиотеки

  Inject.GMHCallRax[0] := $48;
  Inject.GMHCallRax[1] := $FF;
  Inject.GMHCallRax[2] := $D0;

// FreeLibrary:
  Inject.FLMovRcxRax[0] := $48; //  ---+
  Inject.FLMovRcxRax[1] := $89; //  ---+--->  mov RCX, RAX
  Inject.FLMovRcxRax[2] := $C1; //  ---+

  Inject.FLMovRaxCommand := $B848;
  Inject.FLMovRaxArgument := Code + 95; // Code + смещение до адреса FreeLibrary

  Inject.FLMovRaxData[0] := $48; //  ---+
  Inject.FLMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.FLMovRaxData[2] := $00; //  ---+

  Inject.FLCallRax[0] := $48;
  Inject.FLCallRax[1] := $FF;
  Inject.FLCallRax[2] := $D0;

// ExitThread:
  Inject.ETMovRaxCommand := $B848;
  Inject.ETMovRaxArgument := Code + 103; // Code + смещение до адреса ExitThread

  Inject.ETMovRaxData[0] := $48; //  ---+
  Inject.ETMovRaxData[1] := $8B; //  ---+--->  mov RAX, [RAX]
  Inject.ETMovRaxData[2] := $00; //  ---+

  Inject.ETMovRcxCommand := $B948;
  Inject.ETMovRcxArgument := $0000000000000000; // ExitCode = 0

  Inject.ETCallRax[0] := $48;
  Inject.ETCallRax[1] := $FF;
  Inject.ETCallRax[2] := $D0;

// Выравниваем 64х-битный стек:
  Inject.AlignStackAtEnd := $90C3C35D20658D48;


// Записываем адреса библиотек:
  hKernel32 := LoadLibrary('kernel32.dll');
  Inject.AddrGetModuleHandle := UInt64(GetProcAddress(hKernel32, 'GetModuleHandleA'));
  Inject.AddrFreeLibrary := UInt64(GetProcAddress(hKernel32, 'FreeLibrary'));
  Inject.AddrExitThread  := UInt64(GetProcAddress(hKernel32, 'ExitThread'));

  Move(ModuleName^, Inject.LibraryName, Length(ModuleName));

//  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -

  // Записываем машинный код в выделенную память:
  if NtWriteVirtualMemory(ProcessHandle, Memory, @Inject, SizeOf(Inject), BytesWritten) <> 0 then Exit;

  // Выполняем машинный код в отдельном потоке:
  hThread := CreateRemoteThread(ProcessHandle, nil, 0, Memory, nil, 0, ThreadId);

  if hThread = 0 then
  begin
    VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);
    EmptyWorkingSet(ProcessHandle);
    CloseHandle(ProcessHandle);
    Exit;
  end;

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(ProcessHandle, Memory, 0, MEM_RELEASE);

  CloseHandle(hThread);
  EmptyWorkingSet(ProcessHandle);
  CloseHandle(ProcessHandle);

  Result := True;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Инъекция кода напрямую из программы:
procedure InjectFunction(ProcessID: LongWord; InjectedFunction: Pointer; InjectedFunctionSize: NativeUInt);
var
  hProcess: NativeUInt;
  RemoteThreadBaseAddress: Pointer;
  BytesWritten: NativeUInt;
  RemoteThreadHandle: NativeUInt;
  RemoteThreadID: LongWord;
begin
  hProcess := OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
  if hProcess = 0 then
  begin
    MessageBox(0, 'Не удалось открыть процесс для записи!', 'Ошибка!', MB_ICONERROR);
    Exit;
  end;

  // Создаём память в процессе:
  RemoteThreadBaseAddress := VirtualAllocEx(hProcess, nil, InjectedFunctionSize, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE);

  // Пишем в память наш код:
  NtWriteVirtualMemory(hProcess, RemoteThreadBaseAddress, InjectedFunction, InjectedFunctionSize, BytesWritten);
  if InjectedFunctionSize <> BytesWritten then
  begin
    MessageBox(0, 'Не удалось записать код в память удалённого процесса!', 'Ошибка!', MB_ICONERROR);
    VirtualFreeEx(hProcess, RemoteThreadBaseAddress, InjectedFunctionSize, MEM_RELEASE);
    Exit;
  end;

  RemoteThreadHandle := CreateRemoteThread(hProcess, nil, 0, RemoteThreadBaseAddress, nil, 0, RemoteThreadID);
  if RemoteThreadHandle = 0 then
  begin
    MessageBox(0, 'Не удалось запустить поток в удалённом процессе!', 'Ошибка!', MB_ICONERROR);
    VirtualFreeEx(hProcess, RemoteThreadBaseAddress, InjectedFunctionSize, MEM_RELEASE);
    Exit;
  end;
end;





//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//                      #######    ####      ####
//                       ##   ##    ##        ##
//                       ##   ##    ##        ##
//                       ##   ##    ##   #    ##   #
//                      #######    #######   #######
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH



// Заморозить все потоки процесса, кроме текущего:
procedure StopThreads;
var
  TlHelpHandle, CurrentThread, ThreadHandle, CurrentProcess: LongWord;
  ThreadEntry32: TThreadEntry32;
begin
  CurrentThread := GetCurrentThreadId;
  CurrentProcess := GetCurrentProcessId;
  TlHelpHandle := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if TlHelpHandle <> INVALID_HANDLE_VALUE then
  begin
    ThreadEntry32.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(TlHelpHandle, ThreadEntry32) then
    repeat
      if (ThreadEntry32.th32ThreadID <> CurrentThread) and (ThreadEntry32.th32OwnerProcessID = CurrentProcess) then
      begin
        ThreadHandle := OpenThread(THREAD_SUSPEND_RESUME, false, ThreadEntry32.th32ThreadID);
        if ThreadHandle > 0 then
        begin
          SuspendThread(ThreadHandle);
          CloseHandle(ThreadHandle);
        end;
      end;
    until not Thread32Next(TlHelpHandle, ThreadEntry32);

    CloseHandle(TlHelpHandle);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Запустить все потоки процесса, кроме текущего:
procedure RunThreads;
var
  TlHelpHandle, CurrentThread, ThreadHandle, CurrentProcess: LongWord;
  ThreadEntry32: TThreadEntry32;
begin
  CurrentThread := GetCurrentThreadId;
  CurrentProcess := GetCurrentProcessId;
  TlHelpHandle := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if TlHelpHandle <> INVALID_HANDLE_VALUE then
  begin
    ThreadEntry32.dwSize := SizeOf(TThreadEntry32);
    if Thread32First(TlHelpHandle, ThreadEntry32) then
    repeat
      if (ThreadEntry32.th32ThreadID <> CurrentThread) and (ThreadEntry32.th32OwnerProcessID = CurrentProcess) then
      begin
        ThreadHandle := OpenThread(THREAD_SUSPEND_RESUME, false, ThreadEntry32.th32ThreadID);
        if ThreadHandle > 0 then
        begin
          ResumeThread(ThreadHandle);
          CloseHandle(ThreadHandle);
        end;
      end;
    until not Thread32Next(TlHelpHandle, ThreadEntry32);

    CloseHandle(TlHelpHandle);
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Установка перехватчика:
function SetHook(OriginalProcAddress: Pointer; NewProcAddress: Pointer; out OriginalBlock: TOriginalBlock; SuspendThreads: Boolean = True): Boolean;
var
{$IFNDEF RTL_READ_WRITE}
  ReadBytes, WrittenBytes: NativeUInt;
{$ENDIF}

{$IFDEF USE_LDASM}
  Instruction: TInstruction;
  RequiredBufferSize: Byte; // Размер буфера для помещения целого числа инструкций
{$ENDIF}

  BufferSize: Byte;
  FarJump: TFarJump;
  OldProtect: Cardinal;

  // Расчёт относительно адреса для прыжка в х32 ( E9 [ Относительный адрес ] )
  function GetRelativeJmp32Address(Source, Destination: Pointer): Pointer; inline;
  begin
    Result := Pointer(NativeInt(Destination) - NativeInt(Source) - 5);
  end;

  // Сдвиг указателя:
  function GetShiftedPointer(Base: Pointer; Offset: NativeInt): Pointer; inline;
  begin
    Result := Pointer(NativeInt(Base) + Offset);
  end;

const
  ProtectSize = 64;

begin
  Result := False;
  if OriginalProcAddress = nil then Exit;

{$IFDEF CPUX64}
  // x64:
  { 49 BB [8 байт адреса] 41 FF E3 }
  FarJump.MovR11Op  := $BB49;          //  --+
  FarJump.MovR11Arg := NewProcAddress; //  --+-->  mov R11, NewProcAddress
  FarJump.JmpR11Op[0] := $41;          //
  FarJump.JmpR11Op[1] := $FF;          //  |---->  jmp R11
  FarJump.JmpR11Op[2] := $E3;          //
{$ELSE}
  // х32:
  { E9 [4 байта адреса относительно следующей инструкции] }
  FarJump.JmpOp  := $E9;                     //  --+
  FarJump.JmpArg := GetRelativeJmp32Address( //  --+-->  jmp dword NewProcAddress
                                             OriginalProcAddress,
                                             NewProcAddress
                                            );
{$ENDIF}

  if SuspendThreads then StopThreads;

  {$IFDEF USE_LDASM}
    // Снимаем защиту на чтение/запись:
    VirtualProtect(OriginalProcAddress, ProtectSize, PAGE_EXECUTE_READWRITE, @OldProtect);

    // Рассчитываем необходимый размер буфера:
    RequiredBufferSize := 0;
    while RequiredBufferSize < SizeOf(TFarJump) do
    begin
      Inc(
           RequiredBufferSize,
           LDasm(
                  Pointer(NativeUInt(OriginalProcAddress) + RequiredBufferSize),
                  {$IFDEF CPUX64}True{$ELSE}False{$ENDIF},
                  Instruction
                 )
          );
    end;

    // Выделяем память под оригинальное начало функции с прыжком на продолжение:
    BufferSize := RequiredBufferSize + SizeOf(TFarJump);
    GetMem(OriginalBlock, BufferSize);
    FillChar(OriginalBlock^, BufferSize, #0);

    {$IFDEF RTL_READ_WRITE}
      // Сохраняем целое число инструкций:
      Move(OriginalProcAddress^, OriginalBlock^, RequiredBufferSize);

      // Записываем прыжок на новую функцию:
      Move(FarJump, OriginalProcAddress^, SizeOf(TFarJump));

      Result := True;
    {$ELSE}
      // Сохраняем целое число инструкций:
      NtReadVirtualMemory(GetCurrentProcess, OriginalProcAddress, OriginalBlock, RequiredBufferSize, ReadBytes);

      // Записываем прыжок на новую функцию:
      NtWriteVirtualMemory(GetCurrentProcess, OriginalProcAddress, @FarJump, SizeOf(TFarJump), WrittenBytes);
      Result := WrittenBytes <> 0;
    {$ENDIF}

    // Восстанавливаем защиту на чтение/запись:
    VirtualProtect(OriginalProcAddress, ProtectSize, OldProtect, @OldProtect);

    // Рассчитываем смещение в оригинальном блоке, куда потом запишем прыжок на продолжение:
    {$IFDEF CPUX64}
      FarJump.MovR11Arg := Pointer(NativeUInt(OriginalProcAddress) + RequiredBufferSize);
    {$ELSE}
      FarJump.JmpArg := GetRelativeJmp32Address(
                                                 GetShiftedPointer(OriginalBlock, RequiredBufferSize),
                                                 GetShiftedPointer(OriginalProcAddress, RequiredBufferSize)
                                                );
    {$ENDIF}

    // Записываем в конец оригинального блока прыжок на продолжение оригинальной функции:
    {$IFDEF RTL_READ_WRITE}
      Move(FarJump, GetShiftedPointer(OriginalBlock, RequiredBufferSize)^, SizeOf(TFarJump));
    {$ELSE}
      NtWriteVirtualMemory(GetCurrentProcess, GetShiftedPointer(OriginalBlock, RequiredBufferSize), @FarJump, SizeOf(TFarJump), WrittenBytes);
    {$ENDIF}

    // Назначаем оригинальному блоку права на исполнение:
    VirtualProtect(OriginalBlock, BufferSize, PAGE_EXECUTE_READWRITE, @OldProtect);


  {$ELSE}

    // Выделяем память под оригинальное начало функции:
    BufferSize := SizeOf(TFarJump);
    GetMem(OriginalBlock, BufferSize);
    FillChar(OriginalBlock^, BufferSize, #0);

    // Снимаем защиту на чтение/запись:
    VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), PAGE_EXECUTE_READWRITE, @OldProtect);

    {$IFDEF RTL_READ_WRITE}
      Move(OriginalProcAddress^, OriginalBlock^, SizeOf(FarJump));
      Move(FarJump, OriginalProcAddress^, SizeOf(FarJump));
      Result := True;
    {$ELSE}
      NtReadVirtualMemory(GetCurrentProcess, OriginalProcAddress, OriginalBlock, SizeOf(FarJump), ReadBytes);
      NtWriteVirtualMemory(GetCurrentProcess, OriginalProcAddress, @FarJump, SizeOf(FarJump), WrittenBytes);
      Result := WrittenBytes <> 0;
    {$ENDIF}

    // Восстанавливаем защиту на чтение/запись:
    VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), OldProtect, @OldProtect);
  {$ENDIF}

  if SuspendThreads then RunThreads;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Снятие перехвата:
function UnHook(OriginalProcAddress: Pointer; var OriginalBlock: TOriginalBlock; SuspendThreads: Boolean = True): Boolean;
var
{$IFNDEF RTL_READ_WRITE}
  WrittenBytes: NativeUInt;
{$ENDIF}
  OldProtect: Cardinal;
begin
  Result := False;
  if (OriginalProcAddress = nil) or (OriginalBlock = nil) then Exit;


  if SuspendThreads then StopThreads;

  VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), PAGE_EXECUTE_READWRITE, @OldProtect);

  {$IFDEF RTL_READ_WRITE}
    Move(OriginalBlock^, OriginalProcAddress^, SizeOf(TFarJump));
    Result := True;
  {$ELSE}
    NtWriteVirtualMemory(GetCurrentProcess, OriginalProcAddress, OriginalBlock, SizeOf(TFarJump), WrittenBytes);
    Result := WrittenBytes <> 0;
  {$ENDIF}

  VirtualProtect(OriginalProcAddress, SizeOf(TFarJump), OldProtect, @OldProtect);

  FreeMem(OriginalBlock);
  OriginalBlock := nil;

  if SuspendThreads then RunThreads;
end;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH


function MessageHandler(Code: Integer; wParam: Integer; lParam: Integer): Integer; stdcall;
begin
  Result := CallNextHookEx(0, Code, wParam, lParam);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function HookEmAll(out GlobalHookHandle: THandle): Boolean;
begin
  GlobalHookHandle := SetWindowsHookEx(WH_GETMESSAGE, @MessageHandler, hInstance, 0);
  Result := GlobalHookHandle <> 0;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

procedure UnHookEmAll(var GlobalHookHandle: THandle);
begin
  UnhookWindowsHookEx(GlobalHookHandle);
  GlobalHookHandle := 0;
end;

end.
