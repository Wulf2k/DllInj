#include "Project.h"
#include "DllMain.h"
#include "Unloader.h"
#include "Console.h"

#include <atlstr.h>
#include <d3d9.h>
#include <d3dx9.h>
#include <fstream>
#include <iomanip>
#include <Minhook.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>
#include <wchar.h>
#include <WinBase.h>
#include <Windows.h>
#include <windowsx.h>

#pragma comment(lib, "libMinHook.lib")

using namespace std;

DLLEXPORT void Initialize();
DLLEXPORT void Run();
DLLEXPORT void Cleanup();
DLLEXPORT void __cdecl  hotkeyThread(void*);

BOOL WINAPI OnConsoleSignal(DWORD dwCtrlType);

HANDLE hHotkeyThread;

#define ADDPTR(ptr, add) PVOID((PBYTE(ptr) + size_t(add)))
#define SUBPTR(ptr, add) PVOID((PBYTE(ptr) - size_t(add)))
#define DEREF(ptr, add, type) *static_cast<type*>(ADDPTR(ptr,add))

bool bRunning = false;


HANDLE kernel32Handle;
HANDLE user32Handle;


//Kernel32 Hooks
typedef HRESULT(WINAPI* tkernel32_CreateFileW)(LPCTSTR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HRESULT WINAPI hkernel32_CreateFileW(LPCTSTR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
tkernel32_CreateFileW okernel32_CreateFileW = NULL;


//User32 Hooks
typedef HRESULT(WINAPI* tuser32_MessageBoxW)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
HRESULT WINAPI huser32_MessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
tuser32_MessageBoxW ouser32_MessageBoxW = NULL;


struct sKernel32Functions
{
	DWORD kernel32_CreateFileWAddress;
};
sKernel32Functions Kernel32Functions;
enum Kernel32VTable
{
	kernel32_BaseThreadInitThunk,			// 1 (0x1)
	kernel32_InterlockedPushListSList,			// 2 (0x2)
	kernel32_AcquireSRWLockExclusive,			// 3 (0x3)
	kernel32_AcquireSRWLockShared,			// 4 (0x4)
	kernel32_ActivateActCtx,			// 5 (0x5)
	kernel32_AddAtomA,			// 6 (0x6)
	kernel32_AddAtomW,			// 7 (0x7)
	kernel32_AddConsoleAliasA,			// 8 (0x8)
	kernel32_AddConsoleAliasW,			// 9 (0x9)
	kernel32_AddDllDirectory,			// 10 (0xa)
	kernel32_AddIntegrityLabelToBoundaryDescriptor,			// 11 (0xb)
	kernel32_AddLocalAlternateComputerNameA,			// 12 (0xc)
	kernel32_AddLocalAlternateComputerNameW,			// 13 (0xd)
	kernel32_AddRefActCtx,			// 14 (0xe)
	kernel32_AddSIDToBoundaryDescriptor,			// 15 (0xf)
	kernel32_AddSecureMemoryCacheCallback,			// 16 (0x10)
	kernel32_AddVectoredContinueHandler,			// 17 (0x11)
	kernel32_AddVectoredExceptionHandler,			// 18 (0x12)
	kernel32_AdjustCalendarDate,			// 19 (0x13)
	kernel32_AllocConsole,			// 20 (0x14)
	kernel32_AllocateUserPhysicalPages,			// 21 (0x15)
	kernel32_AllocateUserPhysicalPagesNuma,			// 22 (0x16)
	kernel32_ApplicationRecoveryFinished,			// 23 (0x17)
	kernel32_ApplicationRecoveryInProgress,			// 24 (0x18)
	kernel32_AreFileApisANSI,			// 25 (0x19)
	kernel32_AssignProcessToJobObject,			// 26 (0x1a)
	kernel32_AttachConsole,			// 27 (0x1b)
	kernel32_BackupRead,			// 28 (0x1c)
	kernel32_BackupSeek,			// 29 (0x1d)
	kernel32_BackupWrite,			// 30 (0x1e)
	kernel32_BaseCheckAppcompatCache,			// 31 (0x1f)
	kernel32_BaseCheckAppcompatCacheEx,			// 32 (0x20)
	kernel32_BaseCheckRunApp,			// 33 (0x21)
	kernel32_BaseCleanupAppcompatCacheSupport,			// 34 (0x22)
	kernel32_BaseDllReadWriteIniFile,			// 35 (0x23)
	kernel32_BaseDumpAppcompatCache,			// 36 (0x24)
	kernel32_BaseFlushAppcompatCache,			// 37 (0x25)
	kernel32_BaseFormatObjectAttributes,			// 38 (0x26)
	kernel32_BaseFormatTimeOut,			// 39 (0x27)
	kernel32_BaseGenerateAppCompatData,			// 40 (0x28)
	kernel32_BaseGetNamedObjectDirectory,			// 41 (0x29)
	kernel32_BaseInitAppcompatCacheSupport,			// 42 (0x2a)
	kernel32_BaseIsAppcompatInfrastructureDisabled,			// 43 (0x2b)
	kernel32_BaseQueryModuleData,			// 44 (0x2c)
	kernel32_BaseSetLastNTError,			// 45 (0x2d)
	kernel32_BaseUpdateAppcompatCache,			// 46 (0x2e)
	kernel32_BaseVerifyUnicodeString,			// 47 (0x2f)
	kernel32_Basep8BitStringToDynamicUnicodeString,			// 48 (0x30)
	kernel32_BasepAllocateActivationContextActivationBlock,			// 49 (0x31)
	kernel32_BasepAnsiStringToDynamicUnicodeString,			// 50 (0x32)
	kernel32_BasepCheckAppCompat,			// 51 (0x33)
	kernel32_BasepCheckBadapp,			// 52 (0x34)
	kernel32_BasepCheckWinSaferRestrictions,			// 53 (0x35)
	kernel32_BasepFreeActivationContextActivationBlock,			// 54 (0x36)
	kernel32_BasepFreeAppCompatData,			// 55 (0x37)
	kernel32_BasepMapModuleHandle,			// 56 (0x38)
	kernel32_Beep,			// 57 (0x39)
	kernel32_BeginUpdateResourceA,			// 58 (0x3a)
	kernel32_BeginUpdateResourceW,			// 59 (0x3b)
	kernel32_BindIoCompletionCallback,			// 60 (0x3c)
	kernel32_BuildCommDCBA,			// 61 (0x3d)
	kernel32_BuildCommDCBAndTimeoutsA,			// 62 (0x3e)
	kernel32_BuildCommDCBAndTimeoutsW,			// 63 (0x3f)
	kernel32_BuildCommDCBW,			// 64 (0x40)
	kernel32_CallNamedPipeA,			// 65 (0x41)
	kernel32_CallNamedPipeW,			// 66 (0x42)
	kernel32_CallbackMayRunLong,			// 67 (0x43)
	kernel32_CancelDeviceWakeupRequest,			// 68 (0x44)
	kernel32_CancelIo,			// 69 (0x45)
	kernel32_CancelIoEx,			// 70 (0x46)
	kernel32_CancelSynchronousIo,			// 71 (0x47)
	kernel32_CancelThreadpoolIo,			// 72 (0x48)
	kernel32_CancelTimerQueueTimer,			// 73 (0x49)
	kernel32_CancelWaitableTimer,			// 74 (0x4a)
	kernel32_ChangeTimerQueueTimer,			// 75 (0x4b)
	kernel32_CheckElevation,			// 76 (0x4c)
	kernel32_CheckElevationEnabled,			// 77 (0x4d)
	kernel32_CheckForReadOnlyResource,			// 78 (0x4e)
	kernel32_CheckNameLegalDOS8Dot3A,			// 79 (0x4f)
	kernel32_CheckNameLegalDOS8Dot3W,			// 80 (0x50)
	kernel32_CheckRemoteDebuggerPresent,			// 81 (0x51)
	kernel32_ClearCommBreak,			// 82 (0x52)
	kernel32_ClearCommError,			// 83 (0x53)
	kernel32_CloseConsoleHandle,			// 84 (0x54)
	kernel32_CloseHandle,			// 85 (0x55)
	kernel32_ClosePrivateNamespace,			// 86 (0x56)
	kernel32_CloseProfileUserMapping,			// 87 (0x57)
	kernel32_CloseThreadpool,			// 88 (0x58)
	kernel32_CloseThreadpoolCleanupGroup,			// 89 (0x59)
	kernel32_CloseThreadpoolCleanupGroupMembers,			// 90 (0x5a)
	kernel32_CloseThreadpoolIo,			// 91 (0x5b)
	kernel32_CloseThreadpoolTimer,			// 92 (0x5c)
	kernel32_CloseThreadpoolWait,			// 93 (0x5d)
	kernel32_CloseThreadpoolWork,			// 94 (0x5e)
	kernel32_CmdBatNotification,			// 95 (0x5f)
	kernel32_CommConfigDialogA,			// 96 (0x60)
	kernel32_CommConfigDialogW,			// 97 (0x61)
	kernel32_CompareCalendarDates,			// 98 (0x62)
	kernel32_CompareFileTime,			// 99 (0x63)
	kernel32_CompareStringA,			// 100 (0x64)
	kernel32_CompareStringEx,			// 101 (0x65)
	kernel32_CompareStringOrdinal,			// 102 (0x66)
	kernel32_CompareStringW,			// 103 (0x67)
	kernel32_ConnectNamedPipe,			// 104 (0x68)
	kernel32_ConsoleMenuControl,			// 105 (0x69)
	kernel32_ContinueDebugEvent,			// 106 (0x6a)
	kernel32_ConvertCalDateTimeToSystemTime,			// 107 (0x6b)
	kernel32_ConvertDefaultLocale,			// 108 (0x6c)
	kernel32_ConvertFiberToThread,			// 109 (0x6d)
	kernel32_ConvertNLSDayOfWeekToWin32DayOfWeek,			// 110 (0x6e)
	kernel32_ConvertSystemTimeToCalDateTime,			// 111 (0x6f)
	kernel32_ConvertThreadToFiber,			// 112 (0x70)
	kernel32_ConvertThreadToFiberEx,			// 113 (0x71)
	kernel32_CopyContext,			// 114 (0x72)
	kernel32_CopyFileA,			// 115 (0x73)
	kernel32_CopyFileExA,			// 116 (0x74)
	kernel32_CopyFileExW,			// 117 (0x75)
	kernel32_CopyFileTransactedA,			// 118 (0x76)
	kernel32_CopyFileTransactedW,			// 119 (0x77)
	kernel32_CopyFileW,			// 120 (0x78)
	kernel32_CopyLZFile,			// 121 (0x79)
	kernel32_CreateActCtxA,			// 122 (0x7a)
	kernel32_CreateActCtxW,			// 123 (0x7b)
	kernel32_CreateBoundaryDescriptorA,			// 124 (0x7c)
	kernel32_CreateBoundaryDescriptorW,			// 125 (0x7d)
	kernel32_CreateConsoleScreenBuffer,			// 126 (0x7e)
	kernel32_CreateDirectoryA,			// 127 (0x7f)
	kernel32_CreateDirectoryExA,			// 128 (0x80)
	kernel32_CreateDirectoryExW,			// 129 (0x81)
	kernel32_CreateDirectoryTransactedA,			// 130 (0x82)
	kernel32_CreateDirectoryTransactedW,			// 131 (0x83)
	kernel32_CreateDirectoryW,			// 132 (0x84)
	kernel32_CreateEventA,			// 133 (0x85)
	kernel32_CreateEventExA,			// 134 (0x86)
	kernel32_CreateEventExW,			// 135 (0x87)
	kernel32_CreateEventW,			// 136 (0x88)
	kernel32_CreateFiber,			// 137 (0x89)
	kernel32_CreateFiberEx,			// 138 (0x8a)
	kernel32_CreateFileA,			// 139 (0x8b)
	kernel32_CreateFileMappingA,			// 140 (0x8c)
	kernel32_CreateFileMappingNumaA,			// 141 (0x8d)
	kernel32_CreateFileMappingNumaW,			// 142 (0x8e)
	kernel32_CreateFileMappingW,			// 143 (0x8f)
	kernel32_CreateFileTransactedA,			// 144 (0x90)
	kernel32_CreateFileTransactedW,			// 145 (0x91)
	kernel32_CreateFileW,			// 146 (0x92)
	kernel32_CreateHardLinkA,			// 147 (0x93)
	kernel32_CreateHardLinkTransactedA,			// 148 (0x94)
	kernel32_CreateHardLinkTransactedW,			// 149 (0x95)
	kernel32_CreateHardLinkW,			// 150 (0x96)
	kernel32_CreateIoCompletionPort,			// 151 (0x97)
	kernel32_CreateJobObjectA,			// 152 (0x98)
	kernel32_CreateJobObjectW,			// 153 (0x99)
	kernel32_CreateJobSet,			// 154 (0x9a)
	kernel32_CreateMailslotA,			// 155 (0x9b)
	kernel32_CreateMailslotW,			// 156 (0x9c)
	kernel32_CreateMemoryResourceNotification,			// 157 (0x9d)
	kernel32_CreateMutexA,			// 158 (0x9e)
	kernel32_CreateMutexExA,			// 159 (0x9f)
	kernel32_CreateMutexExW,			// 160 (0xa0)
	kernel32_CreateMutexW,			// 161 (0xa1)
	kernel32_CreateNamedPipeA,			// 162 (0xa2)
	kernel32_CreateNamedPipeW,			// 163 (0xa3)
	kernel32_CreatePipe,			// 164 (0xa4)
	kernel32_CreatePrivateNamespaceA,			// 165 (0xa5)
	kernel32_CreatePrivateNamespaceW,			// 166 (0xa6)
	kernel32_CreateProcessA,			// 167 (0xa7)
	kernel32_CreateProcessAsUserW,			// 168 (0xa8)
	kernel32_CreateProcessInternalA,			// 169 (0xa9)
	kernel32_CreateProcessInternalW,			// 170 (0xaa)
	kernel32_CreateProcessW,			// 171 (0xab)
	kernel32_CreateRemoteThread,			// 172 (0xac)
	kernel32_CreateRemoteThreadEx,			// 173 (0xad)
	kernel32_CreateSemaphoreA,			// 174 (0xae)
	kernel32_CreateSemaphoreExA,			// 175 (0xaf)
	kernel32_CreateSemaphoreExW,			// 176 (0xb0)
	kernel32_CreateSemaphoreW,			// 177 (0xb1)
	kernel32_CreateSocketHandle,			// 178 (0xb2)
	kernel32_CreateSymbolicLinkA,			// 179 (0xb3)
	kernel32_CreateSymbolicLinkTransactedA,			// 180 (0xb4)
	kernel32_CreateSymbolicLinkTransactedW,			// 181 (0xb5)
	kernel32_CreateSymbolicLinkW,			// 182 (0xb6)
	kernel32_CreateTapePartition,			// 183 (0xb7)
	kernel32_CreateThread,			// 184 (0xb8)
	kernel32_CreateThreadpool,			// 185 (0xb9)
	kernel32_CreateThreadpoolCleanupGroup,			// 186 (0xba)
	kernel32_CreateThreadpoolIo,			// 187 (0xbb)
	kernel32_CreateThreadpoolTimer,			// 188 (0xbc)
	kernel32_CreateThreadpoolWait,			// 189 (0xbd)
	kernel32_CreateThreadpoolWork,			// 190 (0xbe)
	kernel32_CreateTimerQueue,			// 191 (0xbf)
	kernel32_CreateTimerQueueTimer,			// 192 (0xc0)
	kernel32_CreateToolhelp32Snapshot,			// 193 (0xc1)
	kernel32_CreateWaitableTimerA,			// 194 (0xc2)
	kernel32_CreateWaitableTimerExA,			// 195 (0xc3)
	kernel32_CreateWaitableTimerExW,			// 196 (0xc4)
	kernel32_CreateWaitableTimerW,			// 197 (0xc5)
	kernel32_CtrlRoutine,			// 198 (0xc6)
	kernel32_DeactivateActCtx,			// 199 (0xc7)
	kernel32_DebugActiveProcess,			// 200 (0xc8)
	kernel32_DebugActiveProcessStop,			// 201 (0xc9)
	kernel32_DebugBreak,			// 202 (0xca)
	kernel32_DebugBreakProcess,			// 203 (0xcb)
	kernel32_DebugSetProcessKillOnExit,			// 204 (0xcc)
	kernel32_DecodePointer,			// 205 (0xcd)
	kernel32_DecodeSystemPointer,			// 206 (0xce)
	kernel32_DefineDosDeviceA,			// 207 (0xcf)
	kernel32_DefineDosDeviceW,			// 208 (0xd0)
	kernel32_DelayLoadFailureHook,			// 209 (0xd1)
	kernel32_DeleteAtom,			// 210 (0xd2)
	kernel32_DeleteBoundaryDescriptor,			// 211 (0xd3)
	kernel32_DeleteCriticalSection,			// 212 (0xd4)
	kernel32_DeleteFiber,			// 213 (0xd5)
	kernel32_DeleteFileA,			// 214 (0xd6)
	kernel32_DeleteFileTransactedA,			// 215 (0xd7)
	kernel32_DeleteFileTransactedW,			// 216 (0xd8)
	kernel32_DeleteFileW,			// 217 (0xd9)
	kernel32_DeleteProcThreadAttributeList,			// 218 (0xda)
	kernel32_DeleteTimerQueue,			// 219 (0xdb)
	kernel32_DeleteTimerQueueEx,			// 220 (0xdc)
	kernel32_DeleteTimerQueueTimer,			// 221 (0xdd)
	kernel32_DeleteVolumeMountPointA,			// 222 (0xde)
	kernel32_DeleteVolumeMountPointW,			// 223 (0xdf)
	kernel32_DeviceIoControl,			// 224 (0xe0)
	kernel32_DisableThreadLibraryCalls,			// 225 (0xe1)
	kernel32_DisableThreadProfiling,			// 226 (0xe2)
	kernel32_DisassociateCurrentThreadFromCallback,			// 227 (0xe3)
	kernel32_DisconnectNamedPipe,			// 228 (0xe4)
	kernel32_DnsHostnameToComputerNameA,			// 229 (0xe5)
	kernel32_DnsHostnameToComputerNameW,			// 230 (0xe6)
	kernel32_DosDateTimeToFileTime,			// 231 (0xe7)
	kernel32_DosPathToSessionPathA,			// 232 (0xe8)
	kernel32_DosPathToSessionPathW,			// 233 (0xe9)
	kernel32_DuplicateConsoleHandle,			// 234 (0xea)
	kernel32_DuplicateHandle,			// 235 (0xeb)
	kernel32_EnableThreadProfiling,			// 236 (0xec)
	kernel32_EncodePointer,			// 237 (0xed)
	kernel32_EncodeSystemPointer,			// 238 (0xee)
	kernel32_EndUpdateResourceA,			// 239 (0xef)
	kernel32_EndUpdateResourceW,			// 240 (0xf0)
	kernel32_EnterCriticalSection,			// 241 (0xf1)
	kernel32_EnumCalendarInfoA,			// 242 (0xf2)
	kernel32_EnumCalendarInfoExA,			// 243 (0xf3)
	kernel32_EnumCalendarInfoExEx,			// 244 (0xf4)
	kernel32_EnumCalendarInfoExW,			// 245 (0xf5)
	kernel32_EnumCalendarInfoW,			// 246 (0xf6)
	kernel32_EnumDateFormatsA,			// 247 (0xf7)
	kernel32_EnumDateFormatsExA,			// 248 (0xf8)
	kernel32_EnumDateFormatsExEx,			// 249 (0xf9)
	kernel32_EnumDateFormatsExW,			// 250 (0xfa)
	kernel32_EnumDateFormatsW,			// 251 (0xfb)
	kernel32_EnumLanguageGroupLocalesA,			// 252 (0xfc)
	kernel32_EnumLanguageGroupLocalesW,			// 253 (0xfd)
	kernel32_EnumResourceLanguagesA,			// 254 (0xfe)
	kernel32_EnumResourceLanguagesExA,			// 255 (0xff)
	kernel32_EnumResourceLanguagesExW,			// 256 (0x100)
	kernel32_EnumResourceLanguagesW,			// 257 (0x101)
	kernel32_EnumResourceNamesA,			// 258 (0x102)
	kernel32_EnumResourceNamesExA,			// 259 (0x103)
	kernel32_EnumResourceNamesExW,			// 260 (0x104)
	kernel32_EnumResourceNamesW,			// 261 (0x105)
	kernel32_EnumResourceTypesA,			// 262 (0x106)
	kernel32_EnumResourceTypesExA,			// 263 (0x107)
	kernel32_EnumResourceTypesExW,			// 264 (0x108)
	kernel32_EnumResourceTypesW,			// 265 (0x109)
	kernel32_EnumSystemCodePagesA,			// 266 (0x10a)
	kernel32_EnumSystemCodePagesW,			// 267 (0x10b)
	kernel32_EnumSystemFirmwareTables,			// 268 (0x10c)
	kernel32_EnumSystemGeoID,			// 269 (0x10d)
	kernel32_EnumSystemLanguageGroupsA,			// 270 (0x10e)
	kernel32_EnumSystemLanguageGroupsW,			// 271 (0x10f)
	kernel32_EnumSystemLocalesA,			// 272 (0x110)
	kernel32_EnumSystemLocalesEx,			// 273 (0x111)
	kernel32_EnumSystemLocalesW,			// 274 (0x112)
	kernel32_EnumTimeFormatsA,			// 275 (0x113)
	kernel32_EnumTimeFormatsEx,			// 276 (0x114)
	kernel32_EnumTimeFormatsW,			// 277 (0x115)
	kernel32_EnumUILanguagesA,			// 278 (0x116)
	kernel32_EnumUILanguagesW,			// 279 (0x117)
	kernel32_EnumerateLocalComputerNamesA,			// 280 (0x118)
	kernel32_EnumerateLocalComputerNamesW,			// 281 (0x119)
	kernel32_EraseTape,			// 282 (0x11a)
	kernel32_EscapeCommFunction,			// 283 (0x11b)
	kernel32_ExitProcess,			// 284 (0x11c)
	kernel32_ExitThread,			// 285 (0x11d)
	kernel32_ExitVDM,			// 286 (0x11e)
	kernel32_ExpandEnvironmentStringsA,			// 287 (0x11f)
	kernel32_ExpandEnvironmentStringsW,			// 288 (0x120)
	kernel32_ExpungeConsoleCommandHistoryA,			// 289 (0x121)
	kernel32_ExpungeConsoleCommandHistoryW,			// 290 (0x122)
	kernel32_FatalAppExitA,			// 291 (0x123)
	kernel32_FatalAppExitW,			// 292 (0x124)
	kernel32_FatalExit,			// 293 (0x125)
	kernel32_FileTimeToDosDateTime,			// 294 (0x126)
	kernel32_FileTimeToLocalFileTime,			// 295 (0x127)
	kernel32_FileTimeToSystemTime,			// 296 (0x128)
	kernel32_FillConsoleOutputAttribute,			// 297 (0x129)
	kernel32_FillConsoleOutputCharacterA,			// 298 (0x12a)
	kernel32_FillConsoleOutputCharacterW,			// 299 (0x12b)
	kernel32_FindActCtxSectionGuid,			// 300 (0x12c)
	kernel32_FindActCtxSectionStringA,			// 301 (0x12d)
	kernel32_FindActCtxSectionStringW,			// 302 (0x12e)
	kernel32_FindAtomA,			// 303 (0x12f)
	kernel32_FindAtomW,			// 304 (0x130)
	kernel32_FindClose,			// 305 (0x131)
	kernel32_FindCloseChangeNotification,			// 306 (0x132)
	kernel32_FindFirstChangeNotificationA,			// 307 (0x133)
	kernel32_FindFirstChangeNotificationW,			// 308 (0x134)
	kernel32_FindFirstFileA,			// 309 (0x135)
	kernel32_FindFirstFileExA,			// 310 (0x136)
	kernel32_FindFirstFileExW,			// 311 (0x137)
	kernel32_FindFirstFileNameTransactedW,			// 312 (0x138)
	kernel32_FindFirstFileNameW,			// 313 (0x139)
	kernel32_FindFirstFileTransactedA,			// 314 (0x13a)
	kernel32_FindFirstFileTransactedW,			// 315 (0x13b)
	kernel32_FindFirstFileW,			// 316 (0x13c)
	kernel32_FindFirstStreamTransactedW,			// 317 (0x13d)
	kernel32_FindFirstStreamW,			// 318 (0x13e)
	kernel32_FindFirstVolumeA,			// 319 (0x13f)
	kernel32_FindFirstVolumeMountPointA,			// 320 (0x140)
	kernel32_FindFirstVolumeMountPointW,			// 321 (0x141)
	kernel32_FindFirstVolumeW,			// 322 (0x142)
	kernel32_FindNLSString,			// 323 (0x143)
	kernel32_FindNLSStringEx,			// 324 (0x144)
	kernel32_FindNextChangeNotification,			// 325 (0x145)
	kernel32_FindNextFileA,			// 326 (0x146)
	kernel32_FindNextFileNameW,			// 327 (0x147)
	kernel32_FindNextFileW,			// 328 (0x148)
	kernel32_FindNextStreamW,			// 329 (0x149)
	kernel32_FindNextVolumeA,			// 330 (0x14a)
	kernel32_FindNextVolumeMountPointA,			// 331 (0x14b)
	kernel32_FindNextVolumeMountPointW,			// 332 (0x14c)
	kernel32_FindNextVolumeW,			// 333 (0x14d)
	kernel32_FindResourceA,			// 334 (0x14e)
	kernel32_FindResourceExA,			// 335 (0x14f)
	kernel32_FindResourceExW,			// 336 (0x150)
	kernel32_FindResourceW,			// 337 (0x151)
	kernel32_FindStringOrdinal,			// 338 (0x152)
	kernel32_FindVolumeClose,			// 339 (0x153)
	kernel32_FindVolumeMountPointClose,			// 340 (0x154)
	kernel32_FlsAlloc,			// 341 (0x155)
	kernel32_FlsFree,			// 342 (0x156)
	kernel32_FlsGetValue,			// 343 (0x157)
	kernel32_FlsSetValue,			// 344 (0x158)
	kernel32_FlushConsoleInputBuffer,			// 345 (0x159)
	kernel32_FlushFileBuffers,			// 346 (0x15a)
	kernel32_FlushInstructionCache,			// 347 (0x15b)
	kernel32_FlushProcessWriteBuffers,			// 348 (0x15c)
	kernel32_FlushViewOfFile,			// 349 (0x15d)
	kernel32_FoldStringA,			// 350 (0x15e)
	kernel32_FoldStringW,			// 351 (0x15f)
	kernel32_FormatMessageA,			// 352 (0x160)
	kernel32_FormatMessageW,			// 353 (0x161)
	kernel32_FreeConsole,			// 354 (0x162)
	kernel32_FreeEnvironmentStringsA,			// 355 (0x163)
	kernel32_FreeEnvironmentStringsW,			// 356 (0x164)
	kernel32_FreeLibrary,			// 357 (0x165)
	kernel32_FreeLibraryAndExitThread,			// 358 (0x166)
	kernel32_FreeLibraryWhenCallbackReturns,			// 359 (0x167)
	kernel32_FreeResource,			// 360 (0x168)
	kernel32_FreeUserPhysicalPages,			// 361 (0x169)
	kernel32_GenerateConsoleCtrlEvent,			// 362 (0x16a)
	kernel32_GetACP,			// 363 (0x16b)
	kernel32_GetActiveProcessorCount,			// 364 (0x16c)
	kernel32_GetActiveProcessorGroupCount,			// 365 (0x16d)
	kernel32_GetApplicationRecoveryCallback,			// 366 (0x16e)
	kernel32_GetApplicationRestartSettings,			// 367 (0x16f)
	kernel32_GetAtomNameA,			// 368 (0x170)
	kernel32_GetAtomNameW,			// 369 (0x171)
	kernel32_GetBinaryType,			// 370 (0x172)
	kernel32_GetBinaryTypeA,			// 371 (0x173)
	kernel32_GetBinaryTypeW,			// 372 (0x174)
	kernel32_GetCPInfo,			// 373 (0x175)
	kernel32_GetCPInfoExA,			// 374 (0x176)
	kernel32_GetCPInfoExW,			// 375 (0x177)
	kernel32_GetCalendarDateFormat,			// 376 (0x178)
	kernel32_GetCalendarDateFormatEx,			// 377 (0x179)
	kernel32_GetCalendarDaysInMonth,			// 378 (0x17a)
	kernel32_GetCalendarDifferenceInDays,			// 379 (0x17b)
	kernel32_GetCalendarInfoA,			// 380 (0x17c)
	kernel32_GetCalendarInfoEx,			// 381 (0x17d)
	kernel32_GetCalendarInfoW,			// 382 (0x17e)
	kernel32_GetCalendarMonthsInYear,			// 383 (0x17f)
	kernel32_GetCalendarSupportedDateRange,			// 384 (0x180)
	kernel32_GetCalendarWeekNumber,			// 385 (0x181)
	kernel32_GetComPlusPackageInstallStatus,			// 386 (0x182)
	kernel32_GetCommConfig,			// 387 (0x183)
	kernel32_GetCommMask,			// 388 (0x184)
	kernel32_GetCommModemStatus,			// 389 (0x185)
	kernel32_GetCommProperties,			// 390 (0x186)
	kernel32_GetCommState,			// 391 (0x187)
	kernel32_GetCommTimeouts,			// 392 (0x188)
	kernel32_GetCommandLineA,			// 393 (0x189)
	kernel32_GetCommandLineW,			// 394 (0x18a)
	kernel32_GetCompressedFileSizeA,			// 395 (0x18b)
	kernel32_GetCompressedFileSizeTransactedA,			// 396 (0x18c)
	kernel32_GetCompressedFileSizeTransactedW,			// 397 (0x18d)
	kernel32_GetCompressedFileSizeW,			// 398 (0x18e)
	kernel32_GetComputerNameA,			// 399 (0x18f)
	kernel32_GetComputerNameExA,			// 400 (0x190)
	kernel32_GetComputerNameExW,			// 401 (0x191)
	kernel32_GetComputerNameW,			// 402 (0x192)
	kernel32_GetConsoleAliasA,			// 403 (0x193)
	kernel32_GetConsoleAliasExesA,			// 404 (0x194)
	kernel32_GetConsoleAliasExesLengthA,			// 405 (0x195)
	kernel32_GetConsoleAliasExesLengthW,			// 406 (0x196)
	kernel32_GetConsoleAliasExesW,			// 407 (0x197)
	kernel32_GetConsoleAliasW,			// 408 (0x198)
	kernel32_GetConsoleAliasesA,			// 409 (0x199)
	kernel32_GetConsoleAliasesLengthA,			// 410 (0x19a)
	kernel32_GetConsoleAliasesLengthW,			// 411 (0x19b)
	kernel32_GetConsoleAliasesW,			// 412 (0x19c)
	kernel32_GetConsoleCP,			// 413 (0x19d)
	kernel32_GetConsoleCharType,			// 414 (0x19e)
	kernel32_GetConsoleCommandHistoryA,			// 415 (0x19f)
	kernel32_GetConsoleCommandHistoryLengthA,			// 416 (0x1a0)
	kernel32_GetConsoleCommandHistoryLengthW,			// 417 (0x1a1)
	kernel32_GetConsoleCommandHistoryW,			// 418 (0x1a2)
	kernel32_GetConsoleCursorInfo,			// 419 (0x1a3)
	kernel32_GetConsoleCursorMode,			// 420 (0x1a4)
	kernel32_GetConsoleDisplayMode,			// 421 (0x1a5)
	kernel32_GetConsoleFontInfo,			// 422 (0x1a6)
	kernel32_GetConsoleFontSize,			// 423 (0x1a7)
	kernel32_GetConsoleHardwareState,			// 424 (0x1a8)
	kernel32_GetConsoleHistoryInfo,			// 425 (0x1a9)
	kernel32_GetConsoleInputExeNameA,			// 426 (0x1aa)
	kernel32_GetConsoleInputExeNameW,			// 427 (0x1ab)
	kernel32_GetConsoleInputWaitHandle,			// 428 (0x1ac)
	kernel32_GetConsoleKeyboardLayoutNameA,			// 429 (0x1ad)
	kernel32_GetConsoleKeyboardLayoutNameW,			// 430 (0x1ae)
	kernel32_GetConsoleMode,			// 431 (0x1af)
	kernel32_GetConsoleNlsMode,			// 432 (0x1b0)
	kernel32_GetConsoleOriginalTitleA,			// 433 (0x1b1)
	kernel32_GetConsoleOriginalTitleW,			// 434 (0x1b2)
	kernel32_GetConsoleOutputCP,			// 435 (0x1b3)
	kernel32_GetConsoleProcessList,			// 436 (0x1b4)
	kernel32_GetConsoleScreenBufferInfo,			// 437 (0x1b5)
	kernel32_GetConsoleScreenBufferInfoEx,			// 438 (0x1b6)
	kernel32_GetConsoleSelectionInfo,			// 439 (0x1b7)
	kernel32_GetConsoleTitleA,			// 440 (0x1b8)
	kernel32_GetConsoleTitleW,			// 441 (0x1b9)
	kernel32_GetConsoleWindow,			// 442 (0x1ba)
	kernel32_GetCurrencyFormatA,			// 443 (0x1bb)
	kernel32_GetCurrencyFormatEx,			// 444 (0x1bc)
	kernel32_GetCurrencyFormatW,			// 445 (0x1bd)
	kernel32_GetCurrentActCtx,			// 446 (0x1be)
	kernel32_GetCurrentConsoleFont,			// 447 (0x1bf)
	kernel32_GetCurrentConsoleFontEx,			// 448 (0x1c0)
	kernel32_GetCurrentDirectoryA,			// 449 (0x1c1)
	kernel32_GetCurrentDirectoryW,			// 450 (0x1c2)
	kernel32_GetCurrentProcess,			// 451 (0x1c3)
	kernel32_GetCurrentProcessId,			// 452 (0x1c4)
	kernel32_GetCurrentProcessorNumber,			// 453 (0x1c5)
	kernel32_GetCurrentProcessorNumberEx,			// 454 (0x1c6)
	kernel32_GetCurrentThread,			// 455 (0x1c7)
	kernel32_GetCurrentThreadId,			// 456 (0x1c8)
	kernel32_GetDateFormatA,			// 457 (0x1c9)
	kernel32_GetDateFormatEx,			// 458 (0x1ca)
	kernel32_GetDateFormatW,			// 459 (0x1cb)
	kernel32_GetDefaultCommConfigA,			// 460 (0x1cc)
	kernel32_GetDefaultCommConfigW,			// 461 (0x1cd)
	kernel32_GetDevicePowerState,			// 462 (0x1ce)
	kernel32_GetDiskFreeSpaceA,			// 463 (0x1cf)
	kernel32_GetDiskFreeSpaceExA,			// 464 (0x1d0)
	kernel32_GetDiskFreeSpaceExW,			// 465 (0x1d1)
	kernel32_GetDiskFreeSpaceW,			// 466 (0x1d2)
	kernel32_GetDllDirectoryA,			// 467 (0x1d3)
	kernel32_GetDllDirectoryW,			// 468 (0x1d4)
	kernel32_GetDriveTypeA,			// 469 (0x1d5)
	kernel32_GetDriveTypeW,			// 470 (0x1d6)
	kernel32_GetDurationFormat,			// 471 (0x1d7)
	kernel32_GetDurationFormatEx,			// 472 (0x1d8)
	kernel32_GetDynamicTimeZoneInformation,			// 473 (0x1d9)
	kernel32_GetEnabledXStateFeatures,			// 474 (0x1da)
	kernel32_GetEnvironmentStrings,			// 475 (0x1db)
	kernel32_GetEnvironmentStringsA,			// 476 (0x1dc)
	kernel32_GetEnvironmentStringsW,			// 477 (0x1dd)
	kernel32_GetEnvironmentVariableA,			// 478 (0x1de)
	kernel32_GetEnvironmentVariableW,			// 479 (0x1df)
	kernel32_GetEraNameCountedString,			// 480 (0x1e0)
	kernel32_GetErrorMode,			// 481 (0x1e1)
	kernel32_GetExitCodeProcess,			// 482 (0x1e2)
	kernel32_GetExitCodeThread,			// 483 (0x1e3)
	kernel32_GetExpandedNameA,			// 484 (0x1e4)
	kernel32_GetExpandedNameW,			// 485 (0x1e5)
	kernel32_GetFileAttributesA,			// 486 (0x1e6)
	kernel32_GetFileAttributesExA,			// 487 (0x1e7)
	kernel32_GetFileAttributesExW,			// 488 (0x1e8)
	kernel32_GetFileAttributesTransactedA,			// 489 (0x1e9)
	kernel32_GetFileAttributesTransactedW,			// 490 (0x1ea)
	kernel32_GetFileAttributesW,			// 491 (0x1eb)
	kernel32_GetFileBandwidthReservation,			// 492 (0x1ec)
	kernel32_GetFileInformationByHandle,			// 493 (0x1ed)
	kernel32_GetFileInformationByHandleEx,			// 494 (0x1ee)
	kernel32_GetFileMUIInfo,			// 495 (0x1ef)
	kernel32_GetFileMUIPath,			// 496 (0x1f0)
	kernel32_GetFileSize,			// 497 (0x1f1)
	kernel32_GetFileSizeEx,			// 498 (0x1f2)
	kernel32_GetFileTime,			// 499 (0x1f3)
	kernel32_GetFileType,			// 500 (0x1f4)
	kernel32_GetFinalPathNameByHandleA,			// 501 (0x1f5)
	kernel32_GetFinalPathNameByHandleW,			// 502 (0x1f6)
	kernel32_GetFirmwareEnvironmentVariableA,			// 503 (0x1f7)
	kernel32_GetFirmwareEnvironmentVariableW,			// 504 (0x1f8)
	kernel32_GetFullPathNameA,			// 505 (0x1f9)
	kernel32_GetFullPathNameTransactedA,			// 506 (0x1fa)
	kernel32_GetFullPathNameTransactedW,			// 507 (0x1fb)
	kernel32_GetFullPathNameW,			// 508 (0x1fc)
	kernel32_GetGeoInfoA,			// 509 (0x1fd)
	kernel32_GetGeoInfoW,			// 510 (0x1fe)
	kernel32_GetHandleContext,			// 511 (0x1ff)
	kernel32_GetHandleInformation,			// 512 (0x200)
	kernel32_GetLargePageMinimum,			// 513 (0x201)
	kernel32_GetLargestConsoleWindowSize,			// 514 (0x202)
	kernel32_GetLastError,			// 515 (0x203)
	kernel32_GetLocalTime,			// 516 (0x204)
	kernel32_GetLocaleInfoA,			// 517 (0x205)
	kernel32_GetLocaleInfoEx,			// 518 (0x206)
	kernel32_GetLocaleInfoW,			// 519 (0x207)
	kernel32_GetLogicalDriveStringsA,			// 520 (0x208)
	kernel32_GetLogicalDriveStringsW,			// 521 (0x209)
	kernel32_GetLogicalDrives,			// 522 (0x20a)
	kernel32_GetLogicalProcessorInformation,			// 523 (0x20b)
	kernel32_GetLogicalProcessorInformationEx,			// 524 (0x20c)
	kernel32_GetLongPathNameA,			// 525 (0x20d)
	kernel32_GetLongPathNameTransactedA,			// 526 (0x20e)
	kernel32_GetLongPathNameTransactedW,			// 527 (0x20f)
	kernel32_GetLongPathNameW,			// 528 (0x210)
	kernel32_GetMailslotInfo,			// 529 (0x211)
	kernel32_GetMaximumProcessorCount,			// 530 (0x212)
	kernel32_GetMaximumProcessorGroupCount,			// 531 (0x213)
	kernel32_GetModuleFileNameA,			// 532 (0x214)
	kernel32_GetModuleFileNameW,			// 533 (0x215)
	kernel32_GetModuleHandleA,			// 534 (0x216)
	kernel32_GetModuleHandleExA,			// 535 (0x217)
	kernel32_GetModuleHandleExW,			// 536 (0x218)
	kernel32_GetModuleHandleW,			// 537 (0x219)
	kernel32_GetNLSVersion,			// 538 (0x21a)
	kernel32_GetNLSVersionEx,			// 539 (0x21b)
	kernel32_GetNamedPipeAttribute,			// 540 (0x21c)
	kernel32_GetNamedPipeClientComputerNameA,			// 541 (0x21d)
	kernel32_GetNamedPipeClientComputerNameW,			// 542 (0x21e)
	kernel32_GetNamedPipeClientProcessId,			// 543 (0x21f)
	kernel32_GetNamedPipeClientSessionId,			// 544 (0x220)
	kernel32_GetNamedPipeHandleStateA,			// 545 (0x221)
	kernel32_GetNamedPipeHandleStateW,			// 546 (0x222)
	kernel32_GetNamedPipeInfo,			// 547 (0x223)
	kernel32_GetNamedPipeServerProcessId,			// 548 (0x224)
	kernel32_GetNamedPipeServerSessionId,			// 549 (0x225)
	kernel32_GetNativeSystemInfo,			// 550 (0x226)
	kernel32_GetNextVDMCommand,			// 551 (0x227)
	kernel32_GetNumaAvailableMemoryNode,			// 552 (0x228)
	kernel32_GetNumaAvailableMemoryNodeEx,			// 553 (0x229)
	kernel32_GetNumaHighestNodeNumber,			// 554 (0x22a)
	kernel32_GetNumaNodeNumberFromHandle,			// 555 (0x22b)
	kernel32_GetNumaNodeProcessorMask,			// 556 (0x22c)
	kernel32_GetNumaNodeProcessorMaskEx,			// 557 (0x22d)
	kernel32_GetNumaProcessorNode,			// 558 (0x22e)
	kernel32_GetNumaProcessorNodeEx,			// 559 (0x22f)
	kernel32_GetNumaProximityNode,			// 560 (0x230)
	kernel32_GetNumaProximityNodeEx,			// 561 (0x231)
	kernel32_GetNumberFormatA,			// 562 (0x232)
	kernel32_GetNumberFormatEx,			// 563 (0x233)
	kernel32_GetNumberFormatW,			// 564 (0x234)
	kernel32_GetNumberOfConsoleFonts,			// 565 (0x235)
	kernel32_GetNumberOfConsoleInputEvents,			// 566 (0x236)
	kernel32_GetNumberOfConsoleMouseButtons,			// 567 (0x237)
	kernel32_GetOEMCP,			// 568 (0x238)
	kernel32_GetOverlappedResult,			// 569 (0x239)
	kernel32_GetPhysicallyInstalledSystemMemory,			// 570 (0x23a)
	kernel32_GetPriorityClass,			// 571 (0x23b)
	kernel32_GetPrivateProfileIntA,			// 572 (0x23c)
	kernel32_GetPrivateProfileIntW,			// 573 (0x23d)
	kernel32_GetPrivateProfileSectionA,			// 574 (0x23e)
	kernel32_GetPrivateProfileSectionNamesA,			// 575 (0x23f)
	kernel32_GetPrivateProfileSectionNamesW,			// 576 (0x240)
	kernel32_GetPrivateProfileSectionW,			// 577 (0x241)
	kernel32_GetPrivateProfileStringA,			// 578 (0x242)
	kernel32_GetPrivateProfileStringW,			// 579 (0x243)
	kernel32_GetPrivateProfileStructA,			// 580 (0x244)
	kernel32_GetPrivateProfileStructW,			// 581 (0x245)
	kernel32_GetProcAddress,			// 582 (0x246)
	kernel32_GetProcessAffinityMask,			// 583 (0x247)
	kernel32_GetProcessDEPPolicy,			// 584 (0x248)
	kernel32_GetProcessGroupAffinity,			// 585 (0x249)
	kernel32_GetProcessHandleCount,			// 586 (0x24a)
	kernel32_GetProcessHeap,			// 587 (0x24b)
	kernel32_GetProcessHeaps,			// 588 (0x24c)
	kernel32_GetProcessId,			// 589 (0x24d)
	kernel32_GetProcessIdOfThread,			// 590 (0x24e)
	kernel32_GetProcessIoCounters,			// 591 (0x24f)
	kernel32_GetProcessPreferredUILanguages,			// 592 (0x250)
	kernel32_GetProcessPriorityBoost,			// 593 (0x251)
	kernel32_GetProcessShutdownParameters,			// 594 (0x252)
	kernel32_GetProcessTimes,			// 595 (0x253)
	kernel32_GetProcessUserModeExceptionPolicy,			// 596 (0x254)
	kernel32_GetProcessVersion,			// 597 (0x255)
	kernel32_GetProcessWorkingSetSize,			// 598 (0x256)
	kernel32_GetProcessWorkingSetSizeEx,			// 599 (0x257)
	kernel32_GetProcessorSystemCycleTime,			// 600 (0x258)
	kernel32_GetProductInfo,			// 601 (0x259)
	kernel32_GetProfileIntA,			// 602 (0x25a)
	kernel32_GetProfileIntW,			// 603 (0x25b)
	kernel32_GetProfileSectionA,			// 604 (0x25c)
	kernel32_GetProfileSectionW,			// 605 (0x25d)
	kernel32_GetProfileStringA,			// 606 (0x25e)
	kernel32_GetProfileStringW,			// 607 (0x25f)
	kernel32_GetQueuedCompletionStatus,			// 608 (0x260)
	kernel32_GetQueuedCompletionStatusEx,			// 609 (0x261)
	kernel32_GetShortPathNameA,			// 610 (0x262)
	kernel32_GetShortPathNameW,			// 611 (0x263)
	kernel32_GetStartupInfoA,			// 612 (0x264)
	kernel32_GetStartupInfoW,			// 613 (0x265)
	kernel32_GetStdHandle,			// 614 (0x266)
	kernel32_GetStringScripts,			// 615 (0x267)
	kernel32_GetStringTypeA,			// 616 (0x268)
	kernel32_GetStringTypeExA,			// 617 (0x269)
	kernel32_GetStringTypeExW,			// 618 (0x26a)
	kernel32_GetStringTypeW,			// 619 (0x26b)
	kernel32_GetSystemDEPPolicy,			// 620 (0x26c)
	kernel32_GetSystemDefaultLCID,			// 621 (0x26d)
	kernel32_GetSystemDefaultLangID,			// 622 (0x26e)
	kernel32_GetSystemDefaultLocaleName,			// 623 (0x26f)
	kernel32_GetSystemDefaultUILanguage,			// 624 (0x270)
	kernel32_GetSystemDirectoryA,			// 625 (0x271)
	kernel32_GetSystemDirectoryW,			// 626 (0x272)
	kernel32_GetSystemFileCacheSize,			// 627 (0x273)
	kernel32_GetSystemFirmwareTable,			// 628 (0x274)
	kernel32_GetSystemInfo,			// 629 (0x275)
	kernel32_GetSystemPowerStatus,			// 630 (0x276)
	kernel32_GetSystemPreferredUILanguages,			// 631 (0x277)
	kernel32_GetSystemRegistryQuota,			// 632 (0x278)
	kernel32_GetSystemTime,			// 633 (0x279)
	kernel32_GetSystemTimeAdjustment,			// 634 (0x27a)
	kernel32_GetSystemTimeAsFileTime,			// 635 (0x27b)
	kernel32_GetSystemTimes,			// 636 (0x27c)
	kernel32_GetSystemWindowsDirectoryA,			// 637 (0x27d)
	kernel32_GetSystemWindowsDirectoryW,			// 638 (0x27e)
	kernel32_GetSystemWow64DirectoryA,			// 639 (0x27f)
	kernel32_GetSystemWow64DirectoryW,			// 640 (0x280)
	kernel32_GetTapeParameters,			// 641 (0x281)
	kernel32_GetTapePosition,			// 642 (0x282)
	kernel32_GetTapeStatus,			// 643 (0x283)
	kernel32_GetTempFileNameA,			// 644 (0x284)
	kernel32_GetTempFileNameW,			// 645 (0x285)
	kernel32_GetTempPathA,			// 646 (0x286)
	kernel32_GetTempPathW,			// 647 (0x287)
	kernel32_GetThreadContext,			// 648 (0x288)
	kernel32_GetThreadErrorMode,			// 649 (0x289)
	kernel32_GetThreadGroupAffinity,			// 650 (0x28a)
	kernel32_GetThreadIOPendingFlag,			// 651 (0x28b)
	kernel32_GetThreadId,			// 652 (0x28c)
	kernel32_GetThreadIdealProcessorEx,			// 653 (0x28d)
	kernel32_GetThreadLocale,			// 654 (0x28e)
	kernel32_GetThreadPreferredUILanguages,			// 655 (0x28f)
	kernel32_GetThreadPriority,			// 656 (0x290)
	kernel32_GetThreadPriorityBoost,			// 657 (0x291)
	kernel32_GetThreadSelectorEntry,			// 658 (0x292)
	kernel32_GetThreadTimes,			// 659 (0x293)
	kernel32_GetThreadUILanguage,			// 660 (0x294)
	kernel32_GetTickCount64,			// 661 (0x295)
	kernel32_GetTickCount,			// 662 (0x296)
	kernel32_GetTimeFormatA,			// 663 (0x297)
	kernel32_GetTimeFormatEx,			// 664 (0x298)
	kernel32_GetTimeFormatW,			// 665 (0x299)
	kernel32_GetTimeZoneInformation,			// 666 (0x29a)
	kernel32_GetTimeZoneInformationForYear,			// 667 (0x29b)
	kernel32_GetUILanguageInfo,			// 668 (0x29c)
	kernel32_GetUserDefaultLCID,			// 669 (0x29d)
	kernel32_GetUserDefaultLangID,			// 670 (0x29e)
	kernel32_GetUserDefaultLocaleName,			// 671 (0x29f)
	kernel32_GetUserDefaultUILanguage,			// 672 (0x2a0)
	kernel32_GetUserGeoID,			// 673 (0x2a1)
	kernel32_GetUserPreferredUILanguages,			// 674 (0x2a2)
	kernel32_GetVDMCurrentDirectories,			// 675 (0x2a3)
	kernel32_GetVersion,			// 676 (0x2a4)
	kernel32_GetVersionExA,			// 677 (0x2a5)
	kernel32_GetVersionExW,			// 678 (0x2a6)
	kernel32_GetVolumeInformationA,			// 679 (0x2a7)
	kernel32_GetVolumeInformationByHandleW,			// 680 (0x2a8)
	kernel32_GetVolumeInformationW,			// 681 (0x2a9)
	kernel32_GetVolumeNameForVolumeMountPointA,			// 682 (0x2aa)
	kernel32_GetVolumeNameForVolumeMountPointW,			// 683 (0x2ab)
	kernel32_GetVolumePathNameA,			// 684 (0x2ac)
	kernel32_GetVolumePathNameW,			// 685 (0x2ad)
	kernel32_GetVolumePathNamesForVolumeNameA,			// 686 (0x2ae)
	kernel32_GetVolumePathNamesForVolumeNameW,			// 687 (0x2af)
	kernel32_GetWindowsDirectoryA,			// 688 (0x2b0)
	kernel32_GetWindowsDirectoryW,			// 689 (0x2b1)
	kernel32_GetWriteWatch,			// 690 (0x2b2)
	kernel32_GetXStateFeaturesMask,			// 691 (0x2b3)
	kernel32_GlobalAddAtomA,			// 692 (0x2b4)
	kernel32_GlobalAddAtomW,			// 693 (0x2b5)
	kernel32_GlobalAlloc,			// 694 (0x2b6)
	kernel32_GlobalCompact,			// 695 (0x2b7)
	kernel32_GlobalDeleteAtom,			// 696 (0x2b8)
	kernel32_GlobalFindAtomA,			// 697 (0x2b9)
	kernel32_GlobalFindAtomW,			// 698 (0x2ba)
	kernel32_GlobalFix,			// 699 (0x2bb)
	kernel32_GlobalFlags,			// 700 (0x2bc)
	kernel32_GlobalFree,			// 701 (0x2bd)
	kernel32_GlobalGetAtomNameA,			// 702 (0x2be)
	kernel32_GlobalGetAtomNameW,			// 703 (0x2bf)
	kernel32_GlobalHandle,			// 704 (0x2c0)
	kernel32_GlobalLock,			// 705 (0x2c1)
	kernel32_GlobalMemoryStatus,			// 706 (0x2c2)
	kernel32_GlobalMemoryStatusEx,			// 707 (0x2c3)
	kernel32_GlobalReAlloc,			// 708 (0x2c4)
	kernel32_GlobalSize,			// 709 (0x2c5)
	kernel32_GlobalUnWire,			// 710 (0x2c6)
	kernel32_GlobalUnfix,			// 711 (0x2c7)
	kernel32_GlobalUnlock,			// 712 (0x2c8)
	kernel32_GlobalWire,			// 713 (0x2c9)
	kernel32_Heap32First,			// 714 (0x2ca)
	kernel32_Heap32ListFirst,			// 715 (0x2cb)
	kernel32_Heap32ListNext,			// 716 (0x2cc)
	kernel32_Heap32Next,			// 717 (0x2cd)
	kernel32_HeapAlloc,			// 718 (0x2ce)
	kernel32_HeapCompact,			// 719 (0x2cf)
	kernel32_HeapCreate,			// 720 (0x2d0)
	kernel32_HeapDestroy,			// 721 (0x2d1)
	kernel32_HeapFree,			// 722 (0x2d2)
	kernel32_HeapLock,			// 723 (0x2d3)
	kernel32_HeapQueryInformation,			// 724 (0x2d4)
	kernel32_HeapReAlloc,			// 725 (0x2d5)
	kernel32_HeapSetInformation,			// 726 (0x2d6)
	kernel32_HeapSize,			// 727 (0x2d7)
	kernel32_HeapSummary,			// 728 (0x2d8)
	kernel32_HeapUnlock,			// 729 (0x2d9)
	kernel32_HeapValidate,			// 730 (0x2da)
	kernel32_HeapWalk,			// 731 (0x2db)
	kernel32_IdnToAscii,			// 732 (0x2dc)
	kernel32_IdnToNameprepUnicode,			// 733 (0x2dd)
	kernel32_IdnToUnicode,			// 734 (0x2de)
	kernel32_InitAtomTable,			// 735 (0x2df)
	kernel32_InitOnceBeginInitialize,			// 736 (0x2e0)
	kernel32_InitOnceComplete,			// 737 (0x2e1)
	kernel32_InitOnceExecuteOnce,			// 738 (0x2e2)
	kernel32_InitOnceInitialize,			// 739 (0x2e3)
	kernel32_InitializeConditionVariable,			// 740 (0x2e4)
	kernel32_InitializeContext,			// 741 (0x2e5)
	kernel32_InitializeCriticalSection,			// 742 (0x2e6)
	kernel32_InitializeCriticalSectionAndSpinCount,			// 743 (0x2e7)
	kernel32_InitializeCriticalSectionEx,			// 744 (0x2e8)
	kernel32_InitializeProcThreadAttributeList,			// 745 (0x2e9)
	kernel32_InitializeSListHead,			// 746 (0x2ea)
	kernel32_InitializeSRWLock,			// 747 (0x2eb)
	kernel32_InterlockedCompareExchange64,			// 748 (0x2ec)
	kernel32_InterlockedCompareExchange,			// 749 (0x2ed)
	kernel32_InterlockedDecrement,			// 750 (0x2ee)
	kernel32_InterlockedExchange,			// 751 (0x2ef)
	kernel32_InterlockedExchangeAdd,			// 752 (0x2f0)
	kernel32_InterlockedFlushSList,			// 753 (0x2f1)
	kernel32_InterlockedIncrement,			// 754 (0x2f2)
	kernel32_InterlockedPopEntrySList,			// 755 (0x2f3)
	kernel32_InterlockedPushEntrySList,			// 756 (0x2f4)
	kernel32_InvalidateConsoleDIBits,			// 757 (0x2f5)
	kernel32_IsBadCodePtr,			// 758 (0x2f6)
	kernel32_IsBadHugeReadPtr,			// 759 (0x2f7)
	kernel32_IsBadHugeWritePtr,			// 760 (0x2f8)
	kernel32_IsBadReadPtr,			// 761 (0x2f9)
	kernel32_IsBadStringPtrA,			// 762 (0x2fa)
	kernel32_IsBadStringPtrW,			// 763 (0x2fb)
	kernel32_IsBadWritePtr,			// 764 (0x2fc)
	kernel32_IsCalendarLeapDay,			// 765 (0x2fd)
	kernel32_IsCalendarLeapMonth,			// 766 (0x2fe)
	kernel32_IsCalendarLeapYear,			// 767 (0x2ff)
	kernel32_IsDBCSLeadByte,			// 768 (0x300)
	kernel32_IsDBCSLeadByteEx,			// 769 (0x301)
	kernel32_IsDebuggerPresent,			// 770 (0x302)
	kernel32_IsNLSDefinedString,			// 771 (0x303)
	kernel32_IsNormalizedString,			// 772 (0x304)
	kernel32_IsProcessInJob,			// 773 (0x305)
	kernel32_IsProcessorFeaturePresent,			// 774 (0x306)
	kernel32_IsSystemResumeAutomatic,			// 775 (0x307)
	kernel32_IsThreadAFiber,			// 776 (0x308)
	kernel32_IsThreadpoolTimerSet,			// 777 (0x309)
	kernel32_IsTimeZoneRedirectionEnabled,			// 778 (0x30a)
	kernel32_IsValidCalDateTime,			// 779 (0x30b)
	kernel32_IsValidCodePage,			// 780 (0x30c)
	kernel32_IsValidLanguageGroup,			// 781 (0x30d)
	kernel32_IsValidLocale,			// 782 (0x30e)
	kernel32_IsValidLocaleName,			// 783 (0x30f)
	kernel32_IsWow64Process,			// 784 (0x310)
	kernel32_K32EmptyWorkingSet,			// 785 (0x311)
	kernel32_K32EnumDeviceDrivers,			// 786 (0x312)
	kernel32_K32EnumPageFilesA,			// 787 (0x313)
	kernel32_K32EnumPageFilesW,			// 788 (0x314)
	kernel32_K32EnumProcessModules,			// 789 (0x315)
	kernel32_K32EnumProcessModulesEx,			// 790 (0x316)
	kernel32_K32EnumProcesses,			// 791 (0x317)
	kernel32_K32GetDeviceDriverBaseNameA,			// 792 (0x318)
	kernel32_K32GetDeviceDriverBaseNameW,			// 793 (0x319)
	kernel32_K32GetDeviceDriverFileNameA,			// 794 (0x31a)
	kernel32_K32GetDeviceDriverFileNameW,			// 795 (0x31b)
	kernel32_K32GetMappedFileNameA,			// 796 (0x31c)
	kernel32_K32GetMappedFileNameW,			// 797 (0x31d)
	kernel32_K32GetModuleBaseNameA,			// 798 (0x31e)
	kernel32_K32GetModuleBaseNameW,			// 799 (0x31f)
	kernel32_K32GetModuleFileNameExA,			// 800 (0x320)
	kernel32_K32GetModuleFileNameExW,			// 801 (0x321)
	kernel32_K32GetModuleInformation,			// 802 (0x322)
	kernel32_K32GetPerformanceInfo,			// 803 (0x323)
	kernel32_K32GetProcessImageFileNameA,			// 804 (0x324)
	kernel32_K32GetProcessImageFileNameW,			// 805 (0x325)
	kernel32_K32GetProcessMemoryInfo,			// 806 (0x326)
	kernel32_K32GetWsChanges,			// 807 (0x327)
	kernel32_K32GetWsChangesEx,			// 808 (0x328)
	kernel32_K32InitializeProcessForWsWatch,			// 809 (0x329)
	kernel32_K32QueryWorkingSet,			// 810 (0x32a)
	kernel32_K32QueryWorkingSetEx,			// 811 (0x32b)
	kernel32_LCIDToLocaleName,			// 812 (0x32c)
	kernel32_LCMapStringA,			// 813 (0x32d)
	kernel32_LCMapStringEx,			// 814 (0x32e)
	kernel32_LCMapStringW,			// 815 (0x32f)
	kernel32_LZClose,			// 816 (0x330)
	kernel32_LZCloseFile,			// 817 (0x331)
	kernel32_LZCopy,			// 818 (0x332)
	kernel32_LZCreateFileW,			// 819 (0x333)
	kernel32_LZDone,			// 820 (0x334)
	kernel32_LZInit,			// 821 (0x335)
	kernel32_LZOpenFileA,			// 822 (0x336)
	kernel32_LZOpenFileW,			// 823 (0x337)
	kernel32_LZRead,			// 824 (0x338)
	kernel32_LZSeek,			// 825 (0x339)
	kernel32_LZStart,			// 826 (0x33a)
	kernel32_LeaveCriticalSection,			// 827 (0x33b)
	kernel32_LeaveCriticalSectionWhenCallbackReturns,			// 828 (0x33c)
	kernel32_LoadAppInitDlls,			// 829 (0x33d)
	kernel32_LoadLibraryA,			// 830 (0x33e)
	kernel32_LoadLibraryExA,			// 831 (0x33f)
	kernel32_LoadLibraryExW,			// 832 (0x340)
	kernel32_LoadLibraryW,			// 833 (0x341)
	kernel32_LoadModule,			// 834 (0x342)
	kernel32_LoadResource,			// 835 (0x343)
	kernel32_LoadStringBaseExW,			// 836 (0x344)
	kernel32_LoadStringBaseW,			// 837 (0x345)
	kernel32_LocalAlloc,			// 838 (0x346)
	kernel32_LocalCompact,			// 839 (0x347)
	kernel32_LocalFileTimeToFileTime,			// 840 (0x348)
	kernel32_LocalFlags,			// 841 (0x349)
	kernel32_LocalFree,			// 842 (0x34a)
	kernel32_LocalHandle,			// 843 (0x34b)
	kernel32_LocalLock,			// 844 (0x34c)
	kernel32_LocalReAlloc,			// 845 (0x34d)
	kernel32_LocalShrink,			// 846 (0x34e)
	kernel32_LocalSize,			// 847 (0x34f)
	kernel32_LocalUnlock,			// 848 (0x350)
	kernel32_LocaleNameToLCID,			// 849 (0x351)
	kernel32_LocateXStateFeature,			// 850 (0x352)
	kernel32_LockFile,			// 851 (0x353)
	kernel32_LockFileEx,			// 852 (0x354)
	kernel32_LockResource,			// 853 (0x355)
	kernel32_MapUserPhysicalPages,			// 854 (0x356)
	kernel32_MapUserPhysicalPagesScatter,			// 855 (0x357)
	kernel32_MapViewOfFile,			// 856 (0x358)
	kernel32_MapViewOfFileEx,			// 857 (0x359)
	kernel32_MapViewOfFileExNuma,			// 858 (0x35a)
	kernel32_Module32First,			// 859 (0x35b)
	kernel32_Module32FirstW,			// 860 (0x35c)
	kernel32_Module32Next,			// 861 (0x35d)
	kernel32_Module32NextW,			// 862 (0x35e)
	kernel32_MoveFileA,			// 863 (0x35f)
	kernel32_MoveFileExA,			// 864 (0x360)
	kernel32_MoveFileExW,			// 865 (0x361)
	kernel32_MoveFileTransactedA,			// 866 (0x362)
	kernel32_MoveFileTransactedW,			// 867 (0x363)
	kernel32_MoveFileW,			// 868 (0x364)
	kernel32_MoveFileWithProgressA,			// 869 (0x365)
	kernel32_MoveFileWithProgressW,			// 870 (0x366)
	kernel32_MulDiv,			// 871 (0x367)
	kernel32_MultiByteToWideChar,			// 872 (0x368)
	kernel32_NeedCurrentDirectoryForExePathA,			// 873 (0x369)
	kernel32_NeedCurrentDirectoryForExePathW,			// 874 (0x36a)
	kernel32_NlsCheckPolicy,			// 875 (0x36b)
	kernel32_NlsEventDataDescCreate,			// 876 (0x36c)
	kernel32_NlsGetCacheUpdateCount,			// 877 (0x36d)
	kernel32_NlsUpdateLocale,			// 878 (0x36e)
	kernel32_NlsUpdateSystemLocale,			// 879 (0x36f)
	kernel32_NlsWriteEtwEvent,			// 880 (0x370)
	kernel32_NormalizeString,			// 881 (0x371)
	kernel32_NotifyMountMgr,			// 882 (0x372)
	kernel32_NotifyUILanguageChange,			// 883 (0x373)
	kernel32_OpenConsoleW,			// 884 (0x374)
	kernel32_OpenEventA,			// 885 (0x375)
	kernel32_OpenEventW,			// 886 (0x376)
	kernel32_OpenFile,			// 887 (0x377)
	kernel32_OpenFileById,			// 888 (0x378)
	kernel32_OpenFileMappingA,			// 889 (0x379)
	kernel32_OpenFileMappingW,			// 890 (0x37a)
	kernel32_OpenJobObjectA,			// 891 (0x37b)
	kernel32_OpenJobObjectW,			// 892 (0x37c)
	kernel32_OpenMutexA,			// 893 (0x37d)
	kernel32_OpenMutexW,			// 894 (0x37e)
	kernel32_OpenPrivateNamespaceA,			// 895 (0x37f)
	kernel32_OpenPrivateNamespaceW,			// 896 (0x380)
	kernel32_OpenProcess,			// 897 (0x381)
	kernel32_OpenProcessToken,			// 898 (0x382)
	kernel32_OpenProfileUserMapping,			// 899 (0x383)
	kernel32_OpenSemaphoreA,			// 900 (0x384)
	kernel32_OpenSemaphoreW,			// 901 (0x385)
	kernel32_OpenThread,			// 902 (0x386)
	kernel32_OpenThreadToken,			// 903 (0x387)
	kernel32_OpenWaitableTimerA,			// 904 (0x388)
	kernel32_OpenWaitableTimerW,			// 905 (0x389)
	kernel32_OutputDebugStringA,			// 906 (0x38a)
	kernel32_OutputDebugStringW,			// 907 (0x38b)
	kernel32_PeekConsoleInputA,			// 908 (0x38c)
	kernel32_PeekConsoleInputW,			// 909 (0x38d)
	kernel32_PeekNamedPipe,			// 910 (0x38e)
	kernel32_PostQueuedCompletionStatus,			// 911 (0x38f)
	kernel32_PowerClearRequest,			// 912 (0x390)
	kernel32_PowerCreateRequest,			// 913 (0x391)
	kernel32_PowerSetRequest,			// 914 (0x392)
	kernel32_PrepareTape,			// 915 (0x393)
	kernel32_PrivCopyFileExW,			// 916 (0x394)
	kernel32_PrivMoveFileIdentityW,			// 917 (0x395)
	kernel32_Process32First,			// 918 (0x396)
	kernel32_Process32FirstW,			// 919 (0x397)
	kernel32_Process32Next,			// 920 (0x398)
	kernel32_Process32NextW,			// 921 (0x399)
	kernel32_ProcessIdToSessionId,			// 922 (0x39a)
	kernel32_PulseEvent,			// 923 (0x39b)
	kernel32_PurgeComm,			// 924 (0x39c)
	kernel32_QueryActCtxSettingsW,			// 925 (0x39d)
	kernel32_QueryActCtxW,			// 926 (0x39e)
	kernel32_QueryDepthSList,			// 927 (0x39f)
	kernel32_QueryDosDeviceA,			// 928 (0x3a0)
	kernel32_QueryDosDeviceW,			// 929 (0x3a1)
	kernel32_QueryFullProcessImageNameA,			// 930 (0x3a2)
	kernel32_QueryFullProcessImageNameW,			// 931 (0x3a3)
	kernel32_QueryIdleProcessorCycleTime,			// 932 (0x3a4)
	kernel32_QueryIdleProcessorCycleTimeEx,			// 933 (0x3a5)
	kernel32_QueryInformationJobObject,			// 934 (0x3a6)
	kernel32_QueryMemoryResourceNotification,			// 935 (0x3a7)
	kernel32_QueryPerformanceCounter,			// 936 (0x3a8)
	kernel32_QueryPerformanceFrequency,			// 937 (0x3a9)
	kernel32_QueryProcessAffinityUpdateMode,			// 938 (0x3aa)
	kernel32_QueryProcessCycleTime,			// 939 (0x3ab)
	kernel32_QueryThreadCycleTime,			// 940 (0x3ac)
	kernel32_QueryThreadProfiling,			// 941 (0x3ad)
	kernel32_QueryThreadpoolStackInformation,			// 942 (0x3ae)
	kernel32_QueryUnbiasedInterruptTime,			// 943 (0x3af)
	kernel32_QueueUserAPC,			// 944 (0x3b0)
	kernel32_QueueUserWorkItem,			// 945 (0x3b1)
	kernel32_RaiseException,			// 946 (0x3b2)
	kernel32_RaiseFailFastException,			// 947 (0x3b3)
	kernel32_ReOpenFile,			// 948 (0x3b4)
	kernel32_ReadConsoleA,			// 949 (0x3b5)
	kernel32_ReadConsoleInputA,			// 950 (0x3b6)
	kernel32_ReadConsoleInputExA,			// 951 (0x3b7)
	kernel32_ReadConsoleInputExW,			// 952 (0x3b8)
	kernel32_ReadConsoleInputW,			// 953 (0x3b9)
	kernel32_ReadConsoleOutputA,			// 954 (0x3ba)
	kernel32_ReadConsoleOutputAttribute,			// 955 (0x3bb)
	kernel32_ReadConsoleOutputCharacterA,			// 956 (0x3bc)
	kernel32_ReadConsoleOutputCharacterW,			// 957 (0x3bd)
	kernel32_ReadConsoleOutputW,			// 958 (0x3be)
	kernel32_ReadConsoleW,			// 959 (0x3bf)
	kernel32_ReadDirectoryChangesW,			// 960 (0x3c0)
	kernel32_ReadFile,			// 961 (0x3c1)
	kernel32_ReadFileEx,			// 962 (0x3c2)
	kernel32_ReadFileScatter,			// 963 (0x3c3)
	kernel32_ReadProcessMemory,			// 964 (0x3c4)
	kernel32_ReadThreadProfilingData,			// 965 (0x3c5)
	kernel32_RegCloseKey,			// 966 (0x3c6)
	kernel32_RegCreateKeyExA,			// 967 (0x3c7)
	kernel32_RegCreateKeyExW,			// 968 (0x3c8)
	kernel32_RegDeleteKeyExA,			// 969 (0x3c9)
	kernel32_RegDeleteKeyExW,			// 970 (0x3ca)
	kernel32_RegDeleteTreeA,			// 971 (0x3cb)
	kernel32_RegDeleteTreeW,			// 972 (0x3cc)
	kernel32_RegDeleteValueA,			// 973 (0x3cd)
	kernel32_RegDeleteValueW,			// 974 (0x3ce)
	kernel32_RegDisablePredefinedCacheEx,			// 975 (0x3cf)
	kernel32_RegEnumKeyExA,			// 976 (0x3d0)
	kernel32_RegEnumKeyExW,			// 977 (0x3d1)
	kernel32_RegEnumValueA,			// 978 (0x3d2)
	kernel32_RegEnumValueW,			// 979 (0x3d3)
	kernel32_RegFlushKey,			// 980 (0x3d4)
	kernel32_RegGetKeySecurity,			// 981 (0x3d5)
	kernel32_RegGetValueA,			// 982 (0x3d6)
	kernel32_RegGetValueW,			// 983 (0x3d7)
	kernel32_RegKrnGetGlobalState,			// 984 (0x3d8)
	kernel32_RegKrnInitialize,			// 985 (0x3d9)
	kernel32_RegLoadKeyA,			// 986 (0x3da)
	kernel32_RegLoadKeyW,			// 987 (0x3db)
	kernel32_RegLoadMUIStringA,			// 988 (0x3dc)
	kernel32_RegLoadMUIStringW,			// 989 (0x3dd)
	kernel32_RegNotifyChangeKeyValue,			// 990 (0x3de)
	kernel32_RegOpenCurrentUser,			// 991 (0x3df)
	kernel32_RegOpenKeyExA,			// 992 (0x3e0)
	kernel32_RegOpenKeyExW,			// 993 (0x3e1)
	kernel32_RegOpenUserClassesRoot,			// 994 (0x3e2)
	kernel32_RegQueryInfoKeyA,			// 995 (0x3e3)
	kernel32_RegQueryInfoKeyW,			// 996 (0x3e4)
	kernel32_RegQueryValueExA,			// 997 (0x3e5)
	kernel32_RegQueryValueExW,			// 998 (0x3e6)
	kernel32_RegRestoreKeyA,			// 999 (0x3e7)
	kernel32_RegRestoreKeyW,			// 1000 (0x3e8)
	kernel32_RegSaveKeyExA,			// 1001 (0x3e9)
	kernel32_RegSaveKeyExW,			// 1002 (0x3ea)
	kernel32_RegSetKeySecurity,			// 1003 (0x3eb)
	kernel32_RegSetValueExA,			// 1004 (0x3ec)
	kernel32_RegSetValueExW,			// 1005 (0x3ed)
	kernel32_RegUnLoadKeyA,			// 1006 (0x3ee)
	kernel32_RegUnLoadKeyW,			// 1007 (0x3ef)
	kernel32_RegisterApplicationRecoveryCallback,			// 1008 (0x3f0)
	kernel32_RegisterApplicationRestart,			// 1009 (0x3f1)
	kernel32_RegisterConsoleIME,			// 1010 (0x3f2)
	kernel32_RegisterConsoleOS2,			// 1011 (0x3f3)
	kernel32_RegisterConsoleVDM,			// 1012 (0x3f4)
	kernel32_RegisterWaitForInputIdle,			// 1013 (0x3f5)
	kernel32_RegisterWaitForSingleObject,			// 1014 (0x3f6)
	kernel32_RegisterWaitForSingleObjectEx,			// 1015 (0x3f7)
	kernel32_RegisterWowBaseHandlers,			// 1016 (0x3f8)
	kernel32_RegisterWowExec,			// 1017 (0x3f9)
	kernel32_ReleaseActCtx,			// 1018 (0x3fa)
	kernel32_ReleaseMutex,			// 1019 (0x3fb)
	kernel32_ReleaseMutexWhenCallbackReturns,			// 1020 (0x3fc)
	kernel32_ReleaseSRWLockExclusive,			// 1021 (0x3fd)
	kernel32_ReleaseSRWLockShared,			// 1022 (0x3fe)
	kernel32_ReleaseSemaphore,			// 1023 (0x3ff)
	kernel32_ReleaseSemaphoreWhenCallbackReturns,			// 1024 (0x400)
	kernel32_RemoveDirectoryA,			// 1025 (0x401)
	kernel32_RemoveDirectoryTransactedA,			// 1026 (0x402)
	kernel32_RemoveDirectoryTransactedW,			// 1027 (0x403)
	kernel32_RemoveDirectoryW,			// 1028 (0x404)
	kernel32_RemoveDllDirectory,			// 1029 (0x405)
	kernel32_RemoveLocalAlternateComputerNameA,			// 1030 (0x406)
	kernel32_RemoveLocalAlternateComputerNameW,			// 1031 (0x407)
	kernel32_RemoveSecureMemoryCacheCallback,			// 1032 (0x408)
	kernel32_RemoveVectoredContinueHandler,			// 1033 (0x409)
	kernel32_RemoveVectoredExceptionHandler,			// 1034 (0x40a)
	kernel32_ReplaceFile,			// 1035 (0x40b)
	kernel32_ReplaceFileA,			// 1036 (0x40c)
	kernel32_ReplaceFileW,			// 1037 (0x40d)
	kernel32_ReplacePartitionUnit,			// 1038 (0x40e)
	kernel32_RequestDeviceWakeup,			// 1039 (0x40f)
	kernel32_RequestWakeupLatency,			// 1040 (0x410)
	kernel32_ResetEvent,			// 1041 (0x411)
	kernel32_ResetWriteWatch,			// 1042 (0x412)
	kernel32_ResolveLocaleName,			// 1043 (0x413)
	kernel32_RestoreLastError,			// 1044 (0x414)
	kernel32_ResumeThread,			// 1045 (0x415)
	kernel32_RtlCaptureContext,			// 1046 (0x416)
	kernel32_RtlCaptureStackBackTrace,			// 1047 (0x417)
	kernel32_RtlFillMemory,			// 1048 (0x418)
	kernel32_RtlMoveMemory,			// 1049 (0x419)
	kernel32_RtlUnwind,			// 1050 (0x41a)
	kernel32_RtlZeroMemory,			// 1051 (0x41b)
	kernel32_ScrollConsoleScreenBufferA,			// 1052 (0x41c)
	kernel32_ScrollConsoleScreenBufferW,			// 1053 (0x41d)
	kernel32_SearchPathA,			// 1054 (0x41e)
	kernel32_SearchPathW,			// 1055 (0x41f)
	kernel32_SetCalendarInfoA,			// 1056 (0x420)
	kernel32_SetCalendarInfoW,			// 1057 (0x421)
	kernel32_SetClientTimeZoneInformation,			// 1058 (0x422)
	kernel32_SetComPlusPackageInstallStatus,			// 1059 (0x423)
	kernel32_SetCommBreak,			// 1060 (0x424)
	kernel32_SetCommConfig,			// 1061 (0x425)
	kernel32_SetCommMask,			// 1062 (0x426)
	kernel32_SetCommState,			// 1063 (0x427)
	kernel32_SetCommTimeouts,			// 1064 (0x428)
	kernel32_SetComputerNameA,			// 1065 (0x429)
	kernel32_SetComputerNameExA,			// 1066 (0x42a)
	kernel32_SetComputerNameExW,			// 1067 (0x42b)
	kernel32_SetComputerNameW,			// 1068 (0x42c)
	kernel32_SetConsoleActiveScreenBuffer,			// 1069 (0x42d)
	kernel32_SetConsoleCP,			// 1070 (0x42e)
	kernel32_SetConsoleCtrlHandler,			// 1071 (0x42f)
	kernel32_SetConsoleCursor,			// 1072 (0x430)
	kernel32_SetConsoleCursorInfo,			// 1073 (0x431)
	kernel32_SetConsoleCursorMode,			// 1074 (0x432)
	kernel32_SetConsoleCursorPosition,			// 1075 (0x433)
	kernel32_SetConsoleDisplayMode,			// 1076 (0x434)
	kernel32_SetConsoleFont,			// 1077 (0x435)
	kernel32_SetConsoleHardwareState,			// 1078 (0x436)
	kernel32_SetConsoleHistoryInfo,			// 1079 (0x437)
	kernel32_SetConsoleIcon,			// 1080 (0x438)
	kernel32_SetConsoleInputExeNameA,			// 1081 (0x439)
	kernel32_SetConsoleInputExeNameW,			// 1082 (0x43a)
	kernel32_SetConsoleKeyShortcuts,			// 1083 (0x43b)
	kernel32_SetConsoleLocalEUDC,			// 1084 (0x43c)
	kernel32_SetConsoleMaximumWindowSize,			// 1085 (0x43d)
	kernel32_SetConsoleMenuClose,			// 1086 (0x43e)
	kernel32_SetConsoleMode,			// 1087 (0x43f)
	kernel32_SetConsoleNlsMode,			// 1088 (0x440)
	kernel32_SetConsoleNumberOfCommandsA,			// 1089 (0x441)
	kernel32_SetConsoleNumberOfCommandsW,			// 1090 (0x442)
	kernel32_SetConsoleOS2OemFormat,			// 1091 (0x443)
	kernel32_SetConsoleOutputCP,			// 1092 (0x444)
	kernel32_SetConsolePalette,			// 1093 (0x445)
	kernel32_SetConsoleScreenBufferInfoEx,			// 1094 (0x446)
	kernel32_SetConsoleScreenBufferSize,			// 1095 (0x447)
	kernel32_SetConsoleTextAttribute,			// 1096 (0x448)
	kernel32_SetConsoleTitleA,			// 1097 (0x449)
	kernel32_SetConsoleTitleW,			// 1098 (0x44a)
	kernel32_SetConsoleWindowInfo,			// 1099 (0x44b)
	kernel32_SetCriticalSectionSpinCount,			// 1100 (0x44c)
	kernel32_SetCurrentConsoleFontEx,			// 1101 (0x44d)
	kernel32_SetCurrentDirectoryA,			// 1102 (0x44e)
	kernel32_SetCurrentDirectoryW,			// 1103 (0x44f)
	kernel32_SetDefaultCommConfigA,			// 1104 (0x450)
	kernel32_SetDefaultCommConfigW,			// 1105 (0x451)
	kernel32_SetDefaultDllDirectories,			// 1106 (0x452)
	kernel32_SetDllDirectoryA,			// 1107 (0x453)
	kernel32_SetDllDirectoryW,			// 1108 (0x454)
	kernel32_SetDynamicTimeZoneInformation,			// 1109 (0x455)
	kernel32_SetEndOfFile,			// 1110 (0x456)
	kernel32_SetEnvironmentStringsA,			// 1111 (0x457)
	kernel32_SetEnvironmentStringsW,			// 1112 (0x458)
	kernel32_SetEnvironmentVariableA,			// 1113 (0x459)
	kernel32_SetEnvironmentVariableW,			// 1114 (0x45a)
	kernel32_SetErrorMode,			// 1115 (0x45b)
	kernel32_SetEvent,			// 1116 (0x45c)
	kernel32_SetEventWhenCallbackReturns,			// 1117 (0x45d)
	kernel32_SetFileApisToANSI,			// 1118 (0x45e)
	kernel32_SetFileApisToOEM,			// 1119 (0x45f)
	kernel32_SetFileAttributesA,			// 1120 (0x460)
	kernel32_SetFileAttributesTransactedA,			// 1121 (0x461)
	kernel32_SetFileAttributesTransactedW,			// 1122 (0x462)
	kernel32_SetFileAttributesW,			// 1123 (0x463)
	kernel32_SetFileBandwidthReservation,			// 1124 (0x464)
	kernel32_SetFileCompletionNotificationModes,			// 1125 (0x465)
	kernel32_SetFileInformationByHandle,			// 1126 (0x466)
	kernel32_SetFileIoOverlappedRange,			// 1127 (0x467)
	kernel32_SetFilePointer,			// 1128 (0x468)
	kernel32_SetFilePointerEx,			// 1129 (0x469)
	kernel32_SetFileShortNameA,			// 1130 (0x46a)
	kernel32_SetFileShortNameW,			// 1131 (0x46b)
	kernel32_SetFileTime,			// 1132 (0x46c)
	kernel32_SetFileValidData,			// 1133 (0x46d)
	kernel32_SetFirmwareEnvironmentVariableA,			// 1134 (0x46e)
	kernel32_SetFirmwareEnvironmentVariableW,			// 1135 (0x46f)
	kernel32_SetHandleContext,			// 1136 (0x470)
	kernel32_SetHandleCount,			// 1137 (0x471)
	kernel32_SetHandleInformation,			// 1138 (0x472)
	kernel32_SetInformationJobObject,			// 1139 (0x473)
	kernel32_SetLastConsoleEventActive,			// 1140 (0x474)
	kernel32_SetLastError,			// 1141 (0x475)
	kernel32_SetLocalPrimaryComputerNameA,			// 1142 (0x476)
	kernel32_SetLocalPrimaryComputerNameW,			// 1143 (0x477)
	kernel32_SetLocalTime,			// 1144 (0x478)
	kernel32_SetLocaleInfoA,			// 1145 (0x479)
	kernel32_SetLocaleInfoW,			// 1146 (0x47a)
	kernel32_SetMailslotInfo,			// 1147 (0x47b)
	kernel32_SetMessageWaitingIndicator,			// 1148 (0x47c)
	kernel32_SetNamedPipeAttribute,			// 1149 (0x47d)
	kernel32_SetNamedPipeHandleState,			// 1150 (0x47e)
	kernel32_SetPriorityClass,			// 1151 (0x47f)
	kernel32_SetProcessAffinityMask,			// 1152 (0x480)
	kernel32_SetProcessAffinityUpdateMode,			// 1153 (0x481)
	kernel32_SetProcessDEPPolicy,			// 1154 (0x482)
	kernel32_SetProcessPreferredUILanguages,			// 1155 (0x483)
	kernel32_SetProcessPriorityBoost,			// 1156 (0x484)
	kernel32_SetProcessShutdownParameters,			// 1157 (0x485)
	kernel32_SetProcessUserModeExceptionPolicy,			// 1158 (0x486)
	kernel32_SetProcessWorkingSetSize,			// 1159 (0x487)
	kernel32_SetProcessWorkingSetSizeEx,			// 1160 (0x488)
	kernel32_SetSearchPathMode,			// 1161 (0x489)
	kernel32_SetStdHandle,			// 1162 (0x48a)
	kernel32_SetStdHandleEx,			// 1163 (0x48b)
	kernel32_SetSystemFileCacheSize,			// 1164 (0x48c)
	kernel32_SetSystemPowerState,			// 1165 (0x48d)
	kernel32_SetSystemTime,			// 1166 (0x48e)
	kernel32_SetSystemTimeAdjustment,			// 1167 (0x48f)
	kernel32_SetTapeParameters,			// 1168 (0x490)
	kernel32_SetTapePosition,			// 1169 (0x491)
	kernel32_SetTermsrvAppInstallMode,			// 1170 (0x492)
	kernel32_SetThreadAffinityMask,			// 1171 (0x493)
	kernel32_SetThreadContext,			// 1172 (0x494)
	kernel32_SetThreadErrorMode,			// 1173 (0x495)
	kernel32_SetThreadExecutionState,			// 1174 (0x496)
	kernel32_SetThreadGroupAffinity,			// 1175 (0x497)
	kernel32_SetThreadIdealProcessor,			// 1176 (0x498)
	kernel32_SetThreadIdealProcessorEx,			// 1177 (0x499)
	kernel32_SetThreadLocale,			// 1178 (0x49a)
	kernel32_SetThreadPreferredUILanguages,			// 1179 (0x49b)
	kernel32_SetThreadPriority,			// 1180 (0x49c)
	kernel32_SetThreadPriorityBoost,			// 1181 (0x49d)
	kernel32_SetThreadStackGuarantee,			// 1182 (0x49e)
	kernel32_SetThreadToken,			// 1183 (0x49f)
	kernel32_SetThreadUILanguage,			// 1184 (0x4a0)
	kernel32_SetThreadpoolStackInformation,			// 1185 (0x4a1)
	kernel32_SetThreadpoolThreadMaximum,			// 1186 (0x4a2)
	kernel32_SetThreadpoolThreadMinimum,			// 1187 (0x4a3)
	kernel32_SetThreadpoolTimer,			// 1188 (0x4a4)
	kernel32_SetThreadpoolWait,			// 1189 (0x4a5)
	kernel32_SetTimeZoneInformation,			// 1190 (0x4a6)
	kernel32_SetTimerQueueTimer,			// 1191 (0x4a7)
	kernel32_SetUnhandledExceptionFilter,			// 1192 (0x4a8)
	kernel32_SetUserGeoID,			// 1193 (0x4a9)
	kernel32_SetVDMCurrentDirectories,			// 1194 (0x4aa)
	kernel32_SetVolumeLabelA,			// 1195 (0x4ab)
	kernel32_SetVolumeLabelW,			// 1196 (0x4ac)
	kernel32_SetVolumeMountPointA,			// 1197 (0x4ad)
	kernel32_SetVolumeMountPointW,			// 1198 (0x4ae)
	kernel32_SetWaitableTimer,			// 1199 (0x4af)
	kernel32_SetWaitableTimerEx,			// 1200 (0x4b0)
	kernel32_SetXStateFeaturesMask,			// 1201 (0x4b1)
	kernel32_SetupComm,			// 1202 (0x4b2)
	kernel32_ShowConsoleCursor,			// 1203 (0x4b3)
	kernel32_SignalObjectAndWait,			// 1204 (0x4b4)
	kernel32_SizeofResource,			// 1205 (0x4b5)
	kernel32_Sleep,			// 1206 (0x4b6)
	kernel32_SleepConditionVariableCS,			// 1207 (0x4b7)
	kernel32_SleepConditionVariableSRW,			// 1208 (0x4b8)
	kernel32_SleepEx,			// 1209 (0x4b9)
	kernel32_SortCloseHandle,			// 1210 (0x4ba)
	kernel32_SortGetHandle,			// 1211 (0x4bb)
	kernel32_StartThreadpoolIo,			// 1212 (0x4bc)
	kernel32_SubmitThreadpoolWork,			// 1213 (0x4bd)
	kernel32_SuspendThread,			// 1214 (0x4be)
	kernel32_SwitchToFiber,			// 1215 (0x4bf)
	kernel32_SwitchToThread,			// 1216 (0x4c0)
	kernel32_SystemTimeToFileTime,			// 1217 (0x4c1)
	kernel32_SystemTimeToTzSpecificLocalTime,			// 1218 (0x4c2)
	kernel32_SystemTimeToTzSpecificLocalTimeEx,			// 1219 (0x4c3)
	kernel32_TerminateJobObject,			// 1220 (0x4c4)
	kernel32_TerminateProcess,			// 1221 (0x4c5)
	kernel32_TerminateThread,			// 1222 (0x4c6)
	kernel32_TermsrvAppInstallMode,			// 1223 (0x4c7)
	kernel32_Thread32First,			// 1224 (0x4c8)
	kernel32_Thread32Next,			// 1225 (0x4c9)
	kernel32_TlsAlloc,			// 1226 (0x4ca)
	kernel32_TlsFree,			// 1227 (0x4cb)
	kernel32_TlsGetValue,			// 1228 (0x4cc)
	kernel32_TlsSetValue,			// 1229 (0x4cd)
	kernel32_Toolhelp32ReadProcessMemory,			// 1230 (0x4ce)
	kernel32_TransactNamedPipe,			// 1231 (0x4cf)
	kernel32_TransmitCommChar,			// 1232 (0x4d0)
	kernel32_TryAcquireSRWLockExclusive,			// 1233 (0x4d1)
	kernel32_TryAcquireSRWLockShared,			// 1234 (0x4d2)
	kernel32_TryEnterCriticalSection,			// 1235 (0x4d3)
	kernel32_TrySubmitThreadpoolCallback,			// 1236 (0x4d4)
	kernel32_TzSpecificLocalTimeToSystemTime,			// 1237 (0x4d5)
	kernel32_TzSpecificLocalTimeToSystemTimeEx,			// 1238 (0x4d6)
	kernel32_UTRegister,			// 1239 (0x4d7)
	kernel32_UTUnRegister,			// 1240 (0x4d8)
	kernel32_UnhandledExceptionFilter,			// 1241 (0x4d9)
	kernel32_UnlockFile,			// 1242 (0x4da)
	kernel32_UnlockFileEx,			// 1243 (0x4db)
	kernel32_UnmapViewOfFile,			// 1244 (0x4dc)
	kernel32_UnregisterApplicationRecoveryCallback,			// 1245 (0x4dd)
	kernel32_UnregisterApplicationRestart,			// 1246 (0x4de)
	kernel32_UnregisterConsoleIME,			// 1247 (0x4df)
	kernel32_UnregisterWait,			// 1248 (0x4e0)
	kernel32_UnregisterWaitEx,			// 1249 (0x4e1)
	kernel32_UpdateCalendarDayOfWeek,			// 1250 (0x4e2)
	kernel32_UpdateProcThreadAttribute,			// 1251 (0x4e3)
	kernel32_UpdateResourceA,			// 1252 (0x4e4)
	kernel32_UpdateResourceW,			// 1253 (0x4e5)
	kernel32_VDMConsoleOperation,			// 1254 (0x4e6)
	kernel32_VDMOperationStarted,			// 1255 (0x4e7)
	kernel32_VerLanguageNameA,			// 1256 (0x4e8)
	kernel32_VerLanguageNameW,			// 1257 (0x4e9)
	kernel32_VerSetConditionMask,			// 1258 (0x4ea)
	kernel32_VerifyConsoleIoHandle,			// 1259 (0x4eb)
	kernel32_VerifyScripts,			// 1260 (0x4ec)
	kernel32_VerifyVersionInfoA,			// 1261 (0x4ed)
	kernel32_VerifyVersionInfoW,			// 1262 (0x4ee)
	kernel32_VirtualAlloc,			// 1263 (0x4ef)
	kernel32_VirtualAllocEx,			// 1264 (0x4f0)
	kernel32_VirtualAllocExNuma,			// 1265 (0x4f1)
	kernel32_VirtualFree,			// 1266 (0x4f2)
	kernel32_VirtualFreeEx,			// 1267 (0x4f3)
	kernel32_VirtualLock,			// 1268 (0x4f4)
	kernel32_VirtualProtect,			// 1269 (0x4f5)
	kernel32_VirtualProtectEx,			// 1270 (0x4f6)
	kernel32_VirtualQuery,			// 1271 (0x4f7)
	kernel32_VirtualQueryEx,			// 1272 (0x4f8)
	kernel32_VirtualUnlock,			// 1273 (0x4f9)
	kernel32_WTSGetActiveConsoleSessionId,			// 1274 (0x4fa)
	kernel32_WaitCommEvent,			// 1275 (0x4fb)
	kernel32_WaitForDebugEvent,			// 1276 (0x4fc)
	kernel32_WaitForMultipleObjects,			// 1277 (0x4fd)
	kernel32_WaitForMultipleObjectsEx,			// 1278 (0x4fe)
	kernel32_WaitForSingleObject,			// 1279 (0x4ff)
	kernel32_WaitForSingleObjectEx,			// 1280 (0x500)
	kernel32_WaitForThreadpoolIoCallbacks,			// 1281 (0x501)
	kernel32_WaitForThreadpoolTimerCallbacks,			// 1282 (0x502)
	kernel32_WaitForThreadpoolWaitCallbacks,			// 1283 (0x503)
	kernel32_WaitForThreadpoolWorkCallbacks,			// 1284 (0x504)
	kernel32_WaitNamedPipeA,			// 1285 (0x505)
	kernel32_WaitNamedPipeW,			// 1286 (0x506)
	kernel32_WakeAllConditionVariable,			// 1287 (0x507)
	kernel32_WakeConditionVariable,			// 1288 (0x508)
	kernel32_WerGetFlags,			// 1289 (0x509)
	kernel32_WerRegisterFile,			// 1290 (0x50a)
	kernel32_WerRegisterMemoryBlock,			// 1291 (0x50b)
	kernel32_WerRegisterRuntimeExceptionModule,			// 1292 (0x50c)
	kernel32_WerSetFlags,			// 1293 (0x50d)
	kernel32_WerUnregisterFile,			// 1294 (0x50e)
	kernel32_WerUnregisterMemoryBlock,			// 1295 (0x50f)
	kernel32_WerUnregisterRuntimeExceptionModule,			// 1296 (0x510)
	kernel32_WerpCleanupMessageMapping,			// 1297 (0x511)
	kernel32_WerpInitiateRemoteRecovery,			// 1298 (0x512)
	kernel32_WerpNotifyLoadStringResource,			// 1299 (0x513)
	kernel32_WerpNotifyLoadStringResourceEx,			// 1300 (0x514)
	kernel32_WerpNotifyUseStringResource,			// 1301 (0x515)
	kernel32_WerpStringLookup,			// 1302 (0x516)
	kernel32_WideCharToMultiByte,			// 1303 (0x517)
	kernel32_WinExec,			// 1304 (0x518)
	kernel32_Wow64DisableWow64FsRedirection,			// 1305 (0x519)
	kernel32_Wow64EnableWow64FsRedirection,			// 1306 (0x51a)
	kernel32_Wow64GetThreadContext,			// 1307 (0x51b)
	kernel32_Wow64GetThreadSelectorEntry,			// 1308 (0x51c)
	kernel32_Wow64RevertWow64FsRedirection,			// 1309 (0x51d)
	kernel32_Wow64SetThreadContext,			// 1310 (0x51e)
	kernel32_Wow64SuspendThread,			// 1311 (0x51f)
	kernel32_WriteConsoleA,			// 1312 (0x520)
	kernel32_WriteConsoleInputA,			// 1313 (0x521)
	kernel32_WriteConsoleInputVDMA,			// 1314 (0x522)
	kernel32_WriteConsoleInputVDMW,			// 1315 (0x523)
	kernel32_WriteConsoleInputW,			// 1316 (0x524)
	kernel32_WriteConsoleOutputA,			// 1317 (0x525)
	kernel32_WriteConsoleOutputAttribute,			// 1318 (0x526)
	kernel32_WriteConsoleOutputCharacterA,			// 1319 (0x527)
	kernel32_WriteConsoleOutputCharacterW,			// 1320 (0x528)
	kernel32_WriteConsoleOutputW,			// 1321 (0x529)
	kernel32_WriteConsoleW,			// 1322 (0x52a)
	kernel32_WriteFile,			// 1323 (0x52b)
	kernel32_WriteFileEx,			// 1324 (0x52c)
	kernel32_WriteFileGather,			// 1325 (0x52d)
	kernel32_WritePrivateProfileSectionA,			// 1326 (0x52e)
	kernel32_WritePrivateProfileSectionW,			// 1327 (0x52f)
	kernel32_WritePrivateProfileStringA,			// 1328 (0x530)
	kernel32_WritePrivateProfileStringW,			// 1329 (0x531)
	kernel32_WritePrivateProfileStructA,			// 1330 (0x532)
	kernel32_WritePrivateProfileStructW,			// 1331 (0x533)
	kernel32_WriteProcessMemory,			// 1332 (0x534)
	kernel32_WriteProfileSectionA,			// 1333 (0x535)
	kernel32_WriteProfileSectionW,			// 1334 (0x536)
	kernel32_WriteProfileStringA,			// 1335 (0x537)
	kernel32_WriteProfileStringW,			// 1336 (0x538)
	kernel32_WriteTapemark,			// 1337 (0x539)
	kernel32_ZombifyActCtx,			// 1338 (0x53a)
	kernel32__hread,			// 1339 (0x53b)
	kernel32__hwrite,			// 1340 (0x53c)
	kernel32__lclose,			// 1341 (0x53d)
	kernel32__lcreat,			// 1342 (0x53e)
	kernel32__llseek,			// 1343 (0x53f)
	kernel32__lopen,			// 1344 (0x540)
	kernel32__lread,			// 1345 (0x541)
	kernel32__lwrite,			// 1346 (0x542)
	kernel32_lstrcat,			// 1347 (0x543)
	kernel32_lstrcatA,			// 1348 (0x544)
	kernel32_lstrcatW,			// 1349 (0x545)
	kernel32_lstrcmp,			// 1350 (0x546)
	kernel32_lstrcmpA,			// 1351 (0x547)
	kernel32_lstrcmpW,			// 1352 (0x548)
	kernel32_lstrcmpi,			// 1353 (0x549)
	kernel32_lstrcmpiA,			// 1354 (0x54a)
	kernel32_lstrcmpiW,			// 1355 (0x54b)
	kernel32_lstrcpy,			// 1356 (0x54c)
	kernel32_lstrcpyA,			// 1357 (0x54d)
	kernel32_lstrcpyW,			// 1358 (0x54e)
	kernel32_lstrcpyn,			// 1359 (0x54f)
	kernel32_lstrcpynA,			// 1360 (0x550)
	kernel32_lstrcpynW,			// 1361 (0x551)
	kernel32_lstrlen,			// 1362 (0x552)
	kernel32_lstrlenA,			// 1363 (0x553)
	kernel32_lstrlenW			// 1364 (0x554)1
};

struct sUser32Functions {
	DWORD user32_MessageBoxWAddress;
};
sUser32Functions User32Functions;

//Kernel32 Hooks
HRESULT WINAPI hkernel32_CreateFileW(LPCTSTR *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	wprintf(L"lpFilename = %s\n", lpFileName);

	HRESULT tmp;
	tmp = okernel32_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	return tmp;
}

//User32 Hooks
HRESULT WINAPI huser32_MessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	wprintf(L"lpText = %s\n", lpText);

	HRESULT tmp;
	tmp = ouser32_MessageBoxW(hWnd, lpText, lpCaption, uType);
	return tmp;
}

void initKernel32Functions()
{
	kernel32Handle = GetModuleHandle(TEXT("kernel32.dll"));

	printf("Kernel32.dll = %p\n", kernel32Handle);

	DWORD *Kernel32;

	__asm {
		mov eax, kernel32Handle
		add eax, 0xC0098
		mov Kernel32, eax
	}
	DWORD *pVTable = (DWORD*)Kernel32;

	Kernel32Functions.kernel32_CreateFileWAddress = (DWORD)kernel32Handle + pVTable[Kernel32VTable::kernel32_CreateFileW];
}
void initUser32Functions()
{
	user32Handle = GetModuleHandle(TEXT("user32.dll"));

	printf("User32.dll = %p\n", user32Handle);
	DWORD *User32;

	__asm {
		mov eax, user32Handle
		add eax, 0x10570
		mov User32, eax
	}
	DWORD *pVTable = (DWORD*)User32;

	User32Functions.user32_MessageBoxWAddress = (DWORD)user32Handle + pVTable[546];
}




bool InsertHook(void *pTarget, void *pDetour, void *pOriginal)
{
	if (MH_CreateHook(pTarget, pDetour, reinterpret_cast<void**>(pOriginal)))
		return false;
	if (MH_EnableHook(pTarget))
		return false;

	return true;
}


DWORD ModuleCheckingThread()
{
	if (MH_Initialize() != MH_OK)
		return -1;

	//Kernel32 Hooks
	*(PDWORD)&okernel32_CreateFileW = (DWORD)Kernel32Functions.kernel32_CreateFileWAddress;

	DWORD tmpval;
	__asm {
		mov eax, kernel32Handle
		add eax, 0xF0
		mov eax, [eax]
		mov tmpval, eax
	}

	if (tmpval == 0x56258f04) {
		InsertHook((void*)Kernel32Functions.kernel32_CreateFileWAddress, &hkernel32_CreateFileW, &okernel32_CreateFileW);
	}
	else {

		printf("Wrong kernel32.dll.\n");
	}

	//User32Hooks
	__asm {
		mov eax, user32Handle
		add eax, 0xF0
		mov eax, [eax]
		mov tmpval, eax
	}

	if (tmpval == 0x56423973) {
		InsertHook((void*)User32Functions.user32_MessageBoxWAddress, &huser32_MessageBoxW, &ouser32_MessageBoxW);
	}
	else {

		printf("Wrong user32.dll.\n");
	}
	
}

DLLEXPORT void __cdecl Start(void*)
{
	Unloader::Initialize(hDll);

	Console::Create("DllInj");

	if (!SetConsoleCtrlHandler(OnConsoleSignal, TRUE)) {
		printf("\nERROR: Could not set control handler\n");
		return;
	}

	printf("Initializing\n");
	Initialize();
	Run();
	Cleanup();

	SetConsoleCtrlHandler(OnConsoleSignal, FALSE);
	Console::Free();
	Unloader::UnloadSelf(true);		// Unloading on a new thread fixes an unload issue
}


void Initialize()
{
	initKernel32Functions();
	initUser32Functions();
	ModuleCheckingThread();

	_beginthread(&hotkeyThread, 0, 0);
}
void Cleanup()
{
	MH_DisableHook(MH_ALL_HOOKS);
}
void Run()
{
	bRunning = true;
	while (bRunning)
	{
		Sleep(33);
	}
}

BOOL WINAPI OnConsoleSignal(DWORD dwCtrlType) {

	if (dwCtrlType == CTRL_C_EVENT)
	{
		printf("Ctrl-C handled, exiting...\n"); // do cleanup
		bRunning = false;
		return TRUE;
	}

	return FALSE;
}

DLLEXPORT void __cdecl hotkeyThread(void*)
{
	printf("hotkeyThread() called\n");

	bool hk_Enter_Pressed = false;

	bool hk_Num1_Pressed = false;
	bool hk_Num2_Pressed = false;
	bool hk_Num3_Pressed = false;

	bool hk_Numpad2_Pressed = false;
	bool hk_Numpad4_Pressed = false;
	bool hk_Numpad6_Pressed = false;
	bool hk_Numpad8_Pressed = false;

	bool hk_NumpadPlus_Pressed = false;



	short hk_Enter;

	short hk_Num1;
	short hk_Num2;
	short hk_Num3;

	short hk_Numpad2;
	short hk_Numpad4;
	short hk_Numpad6;
	short hk_Numpad8;

	short hk_NumpadPlus;


	while (bRunning)
	{
		hk_Enter = GetKeyState(0x0D);

		hk_Num1 = GetKeyState(0x31);
		hk_Num2 = GetKeyState(0x32);
		hk_Num3 = GetKeyState(0x33);

		hk_Numpad2 = GetKeyState(0x62);
		hk_Numpad4 = GetKeyState(0x64);
		hk_Numpad6 = GetKeyState(0x66);
		hk_Numpad8 = GetKeyState(0x68);

		hk_NumpadPlus = GetKeyState(0x6B);



		if (hk_Enter & 0x8000)
		{
			if (hk_Enter_Pressed == false)
			{
				hk_Enter_Pressed = true;

			}
		}
		else
		{
			hk_Enter_Pressed = false;
		}


		if (hk_Num1 & 0x8000)
		{
			hk_Num1_Pressed = true;
			bRunning = false;
		}



		if (hk_Num2 & 0x8000)
		{
			if (hk_Num2_Pressed == false)
			{
				hk_Num2_Pressed = true;
			}
			else
			{
			
			}

		}
		else
		{
			hk_Num2_Pressed = false;
		}




		if (hk_Num3 & 0x8000)
		{
			if (hk_Num3_Pressed == false)
			{
				hk_Num3_Pressed = true;
			}
		}
		else
		{
			hk_Num3_Pressed = false;
		}



		if (hk_Numpad2 & 0x8000)
		{
			if (hk_Numpad2_Pressed == false)
			{
				hk_Numpad2_Pressed = true;
			}
		}
		else
		{
			hk_Numpad2_Pressed = false;
		}



		if (hk_Numpad4 & 0x8000)
		{
			if (hk_Numpad4_Pressed == false)
			{
				hk_Numpad4_Pressed = true;
			}
		}
		else
		{
			hk_Numpad4_Pressed = false;
		}


		if (hk_Numpad6 & 0x8000)
		{
			if (hk_Numpad6_Pressed == false)
			{
				hk_Numpad6_Pressed = true;
			}
		}
		else
		{
			hk_Numpad6_Pressed = false;
		}


		if (hk_Numpad8 & 0x8000)
		{
			if (hk_Numpad8_Pressed == false)
			{
				hk_Numpad8_Pressed = true;
			}
		}
		else
		{
			hk_Numpad8_Pressed = false;
		}


		if (hk_NumpadPlus & 0x8000)
		{
			if (hk_NumpadPlus_Pressed == false)
			{
				hk_NumpadPlus_Pressed = true;
			}
		}
		else
		{
			hk_NumpadPlus_Pressed = false;
		}


	}
	Sleep(30);
}
