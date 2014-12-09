library RatiborLib;

{$SETPEFLAGS $0002 or $0004 or $0008 or $0010 or $0020 or $0200 or $0400 or $0800 or $1000}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}

uses
  Windows,
  HookAPI in '..\# Common Modules\HookAPI\HookAPI.pas',
  MappingAPI in '..\# Common Modules\MappingAPI.pas',
  ProcessAPI in '..\# Common Modules\ProcessAPI.pas',
  MicroDAsm in '..\# Common Modules\HookAPI\MicroDAsm.pas';

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//                    Необходимые структуры NativeAPI
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

type
  UNICODE_STRING = record
    Length        : Word;
    MaximumLength : Word;
    Buffer        : Pointer;
  end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  UNICODE_STRING64 = record
    Length        : Word;
    MaximumLength : Word;
    Fill          : LongWord;
    Buffer        : Pointer;
  end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  // 32х-битная структура, возвращаемая NtQuerySystemInformation:
  SYSTEM_PROCESS_INFORMATION32 = record
    NextEntryOffset              : ULONG;
    NumberOfThreads              : ULONG;
    WorkingSetPrivateSize        : LARGE_INTEGER;
    HardFaultCount               : ULONG;
    NumberOfThreadsHighWatermark : ULONG;
    CycleTime                    : ULONGLONG;
    CreateTime                   : LARGE_INTEGER;
    UserTime                     : LARGE_INTEGER;
    KernelTime                   : LARGE_INTEGER;
    ImageName                    : UNICODE_STRING;
    BasePriority                 : LONG;
    UniqueProcessId              : ULONG;
    InheritedFromUniqueProcessId : ULONG;
    HandleCount                  : ULONG;
    SessionId                    : ULONG;
    UniqueProcessKey             : ULONG_PTR;
    PeakVirtualSize              : SIZE_T;
    VirtualSize                  : SIZE_T;
    PageFaultCount               : ULONG;
    PeakWorkingSetSize           : SIZE_T;
    WorkingSetSize               : SIZE_T;
    QuotaPeakPagedPoolUsage      : SIZE_T;
    QuotaPagedPoolUsage          : SIZE_T;
    QuotaPeakNonPagedPoolUsage   : SIZE_T;
    QuotaNonPagedPoolUsage       : SIZE_T;
    PagefileUsage                : SIZE_T;
    PeakPagefileUsage            : SIZE_T;
    PrivatePageCount             : SIZE_T;
    ReadOperationCount           : LARGE_INTEGER;
    WriteOperationCount          : LARGE_INTEGER;
    OtherOperationCount          : LARGE_INTEGER;
    ReadTransferCount            : LARGE_INTEGER;
    WriteTransferCount           : LARGE_INTEGER;
    OtherTransferCount           : LARGE_INTEGER;
  end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  // 64х-битная структура, возвращаемая NtQuerySystemInformation:
  SYSTEM_PROCESS_INFORMATION64 = record
    NextEntryOffset              : ULONG;
    NumberOfThreads              : ULONG;
    WorkingSetPrivateSize        : LARGE_INTEGER;
    HardFaultCount               : ULONG;
    NumberOfThreadsHighWatermark : ULONG;
    CycleTime                    : ULONGLONG;
    CreateTime                   : LARGE_INTEGER;
    UserTime                     : LARGE_INTEGER;
    KernelTime                   : LARGE_INTEGER;
    ImageName                    : UNICODE_STRING64;
    BasePriority                 : UINT64;
    UniqueProcessID              : UINT64;
    InheritedFromUniqueProcessId : UINT64;
    HandleCount                  : UINT64;
    SessionId                    : UINT64;
    UniqueProcessKey             : UINT64;
    PeakVirtualSize              : UINT64;
    VirtualSize                  : UINT64;
    PageFaultCount               : UINT64;
    PeakWorkingSetSize           : UINT64;
    WorkingSetSize               : UINT64;
    QuotaPeakPagedPoolUsage      : UINT64;
    QuotaPagedPoolUsage          : UINT64;
    QuotaPeakNonPagedPoolUsage   : UINT64;
    QuotaNonPagedPoolUsage       : UINT64;
    PagefileUsage                : UINT64;
    PeakPagefileUsage            : UINT64;
    PrivatePageCount             : UINT64;
    ReadOperationCount           : LARGE_INTEGER;
    WriteOperationCount          : LARGE_INTEGER;
    OtherOperationCount          : LARGE_INTEGER;
    ReadTransferCount            : LARGE_INTEGER;
    WriteTransferCount           : LARGE_INTEGER;
    OtherTransferCount           : LARGE_INTEGER;
  end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  // Тип выдаваемой информации для NtQuerySystemInformation:
  SYSTEM_INFORMATION_CLASS = (
                               SystemBasicInformation,
                               SystemProcessorInformation,
                               SystemPerformanceInformation,
                               SystemTimeOfDayInformation,
                               SystemPathInformation,
                               SystemProcessInformation,
                               SystemCallCountInformation,
                               SystemDeviceInformation,
                               SystemProcessorPerformanceInformation,
                               SystemFlagsInformation,
                               SystemCallTimeInformation,
                               SystemModuleInformation,
                               SystemLocksInformation,
                               SystemStackTraceInformation,
                               SystemPagedPoolInformation,
                               SystemNonPagedPoolInformation,
                               SystemHandleInformation,
                               SystemObjectInformation,
                               SystemPageFileInformation,
                               SystemVdmInstemulInformation,
                               SystemVdmBopInformation,
                               SystemFileCacheInformation,
                               SystemPoolTagInformation,
                               SystemInterruptInformation,
                               SystemDpcBehaviorInformation,
                               SystemFullMemoryInformation,
                               SystemLoadGdiDriverInformation,
                               SystemUnloadGdiDriverInformation,
                               SystemTimeAdjustmentInformation,
                               SystemSummaryMemoryInformation,
                               SystemMirrorMemoryInformation,
                               SystemPerformanceTraceInformation,
                               SystemObsolete0,
                               SystemExceptionInformation,
                               SystemCrashDumpStateInformation,
                               SystemKernelDebuggerInformation
                              );

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  {$IFDEF CPUX64}
    SYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION64;
    PSYSTEM_PROCESS_INFORMATION = ^SYSTEM_PROCESS_INFORMATION64;
  {$ELSE}
    SYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION32;
    PSYSTEM_PROCESS_INFORMATION = ^SYSTEM_PROCESS_INFORMATION32;
  {$ENDIF}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  NTSTATUS = LongWord;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//                           Настройки перехвата
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

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


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

var
  GlobalHookHandle: THandle = 0;     // Хэндл глобального хука
  OriginalCall: Boolean = False;     // Флаг вызова оригинальной функции
  NtQuerySystemInformation: Pointer; // Указатель на функцию в ntdll.dll

  // Указатель на блок с оригинальным началом функции и прыжком на продолжение:
  TrueNtQuerySystemInformation: function(
                                          SystemInformationClass: LongWord;
                                          SystemInformation: Pointer;
                                          SystemInformationLength: ULONG;
                                          ReturnLength: PULONG
                                         ): NTSTATUS; stdcall;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Сдвиг указателя:
function GetShiftedPointer(Base: Pointer; Offset: NativeInt): Pointer; inline;
begin
  Result := Pointer(NativeInt(Base) + Offset);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//                      Обработчик перехваченной функции
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Перехваченная функция:
function HookedNtQuerySystemInformation(
                                         SystemInformationClass: LongWord;
                                         SystemInformation: PSYSTEM_PROCESS_INFORMATION;
                                         SystemInformationLength: ULONG;
                                         ReturnLength: PULONG
                                        ): NTSTATUS; stdcall;
var
  SystemInfo: PSYSTEM_PROCESS_INFORMATION;
  NextProcess: PSYSTEM_PROCESS_INFORMATION;
  HookInfo: ^THookInfo;
begin
  Result := TrueNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

  // Проверяем случаи, когда изменять результат не надо:
  if OriginalCall or (Result <> 0) then Exit;
  if SystemInformationClass <> LongWord(SystemProcessInformation) then Exit;

  // Получаем параметры перехвата в отображённой памяти:
  HookInfo := GetMappedMemory('HookAPI');
  if HookInfo = nil then Exit;

  SystemInfo := SystemInformation;

  // Проходимся по всем процессам:
  while SystemInfo.NextEntryOffset <> 0 do
  begin
    NextProcess := PSYSTEM_PROCESS_INFORMATION(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset);

    // Если следующий элемент - наш защищаемый процесс или наследованный от него...:
    if (NextProcess.UniqueProcessId = HookInfo.ProtectedProcess) or
       (NextProcess.InheritedFromUniqueProcessId = HookInfo.ProtectedProcess)
    then
    begin
      // ...то скрываем его:
      if HookInfo.HideProcess then
      begin
        if NextProcess.NextEntryOffset <> 0 then
          SystemInfo.NextEntryOffset := NextProcess.NextEntryOffset + SystemInfo.NextEntryOffset
        else
          SystemInfo.NextEntryOffset := 0;

        Continue;
      end;

      // Или чистим всю структуру:
      if HookInfo.FlushProcessInfo then
        FillChar(
                  GetShiftedPointer(
                                     NextProcess,
                                     SizeOf(SystemInfo.NextEntryOffset)
                                    )^,
                  SizeOf(SYSTEM_PROCESS_INFORMATION) - SizeOf(SystemInfo.NextEntryOffset),
                  #0
                 );

      // Или меняем ProcessID:
      case HookInfo.InvalidateProcessID of
        INVALIDATE_PROCESS_ID                : NextProcess.UniqueProcessID := 9999;
        SET_PROCESS_ID_TO_CURRENT_PROCESS_ID : NextProcess.UniqueProcessID := GetCurrentProcessID;
        RANDOMIZE_PROCESS_ID                 : NextProcess.UniqueProcessID := Random(9999);
      end;
    end;

    SystemInfo := Pointer(NativeUInt(SystemInfo) + SystemInfo.NextEntryOffset);
  end;

  // Освобождаем отображённую память:
  FreeMappedMemory(HookInfo);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//                    Функции запуска и остановки защиты
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Запуск защиты:
procedure StartDefence; stdcall; export;
begin
  if GlobalHookHandle = 0 then HookEmAll(GlobalHookHandle);
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Остановка защиты:
procedure StopDefence; stdcall; export;
begin
  if GlobalHookHandle <> 0 then UnHookEmAll(GlobalHookHandle);
end;

//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//                   Обработка загрузки и выгрузки библиотеки
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

// Инициализация библиотеки:
procedure DLLMain(dwReason: LongWord);
var
  HookInfo: ^THookInfo;
  ProcessBasicInfo: TProcessBasicInfo;
begin
  case dwReason of
    DLL_PROCESS_ATTACH:
    begin
      // Получаем параметры в отображённой памяти:
      HookInfo := GetMappedMemory('HookAPI');
      if HookInfo = nil then Exit;

      // Получаем информацию о текущем процессе:
      GetProcessBasicInfo(GetCurrentProcessID, ProcessBasicInfo);

      // Если внедняемся в защищаемый процесс или наследованный от него, то ничего не перехватываем:
      if (HookInfo.ProtectedProcess = ProcessBasicInfo.UniqueProcessId) or
         (HookInfo.ProtectedProcess = ProcessBasicInfo.InheritedFromUniqueProcessId)
      then
      begin
        FreeMappedMemory(HookInfo);
        Exit;
      end;
      FreeMappedMemory(HookInfo);

      // Задаём необходимые привилегии:
      NtSetPrivilege(SE_DEBUG_NAME, True);

      // Перехватываем NtQuerySystemInformation:
      NtQuerySystemInformation := GetProcAddress(GetModuleHandle('ntdll.dll'), 'NtQuerySystemInformation');
      OriginalCall := True;
      SetHook(NtQuerySystemInformation, @HookedNtQuerySystemInformation, @TrueNtQuerySystemInformation);
      OriginalCall := False;
    end;

    DLL_PROCESS_DETACH:
    begin
      // Снимаем перехват:
      OriginalCall := True;
      UnHook(NtQuerySystemInformation, @TrueNtQuerySystemInformation);
      OriginalCall := False;

      if GlobalHookHandle <> 0 then UnHookEmAll(GlobalHookHandle);
    end;
  end;
end;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

exports StartDefence;
exports StopDefence;

begin
  DllProc := @DLLMain;
  DllProc(DLL_PROCESS_ATTACH);
end.

