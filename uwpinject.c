#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#define COBJMACROS
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <shobjidl.h>
#include <appmodel.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "advapi32.lib")

#include <stdio.h>

int win32_perror(int err, wchar_t* msg) {
  int res;
  wchar_t* buf = 0;
  int flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER;
  FormatMessageW(flags, 0, err, 0, (LPWSTR)&buf, 0, 0);
  res = fwprintf(stderr, L"%s: error [%08X] %s\n", msg, err, buf);
  if (buf) {
    LocalFree((HLOCAL)buf);
  }
  return res;
}

int win32_addr(char* module_name, char* name, void** dst) {
  HMODULE lib = GetModuleHandleA(module_name);
  void* addr;
  if (!lib) {
    win32_perror((int)GetLastError(), L"GetModuleHandleA failed");
    return 0;
  }
  addr = (void*)GetProcAddress(lib, name);
  if (dst) {
    *dst = addr;
  }
  if (!addr) {
    win32_perror((int)GetLastError(), L"GetProcAddress failed");
    return 0;
  }
  return 1;
}

HANDLE win32_process(int pid) {
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!process) {
    win32_perror((int)GetLastError(), L"OpenProcess failed");
  }
  return process;
}

void* win32_ralloc(int pid, size_t n) {
  void* p;
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  p = VirtualAllocEx(process, 0, n, MEM_RESERVE | MEM_COMMIT,
    PAGE_READWRITE);
  if (!p) {
    win32_perror((int)GetLastError(), L"VirtualAllocEx failed");
  }
  CloseHandle(process);
  return p;
}

int win32_rfree(int pid, void* p) {
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  if (!VirtualFreeEx(process, p, 0, MEM_RELEASE)) {
    win32_perror((int)GetLastError(), L"VirtualFreeEx failed");
    return 0;
  }
  return 1;
}

int win32_rmemcpy(int pid, void* dst, void* src, size_t n) {
  BOOL succ;
  size_t n_written;
  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!process) {
    win32_perror((int)GetLastError(), L"OpenProcess failed");
    return 0;
  }
  succ = WriteProcessMemory(process, dst, src, n, &n_written);
  if (!succ) {
    win32_perror((int)GetLastError(), L"WriteProcessMemory failed");
  }
  if (n_written != n) {
    win32_perror((int)GetLastError(), L"WriteProcessMemory partial write");
  }
  CloseHandle(process);
  return succ == TRUE;
}

void* win32_rwstrdup(int pid, wchar_t* s) {
  size_t n = (wcslen(s) + 1) * sizeof(s[0]);
  void* remote_s = win32_ralloc(pid, n);
  if (!remote_s) {
    return 0;
  }
  if (!win32_rmemcpy(pid, remote_s, s, n)) {
    win32_rfree(pid, remote_s);
    return 0;
  }
  return remote_s;
}

int win32_wait_for_remote_thread(int pid, void* routine, void* param) {
  int res = 1;
  HANDLE remote_thread;
  HANDLE process = win32_process(pid);
  if (!process) {
    return 0;
  }
  remote_thread = CreateRemoteThread(process, 0, 0,
    (LPTHREAD_START_ROUTINE)routine, param, 0, 0);
  if (!remote_thread) {
    win32_perror((int)GetLastError(), L"CreateRemoteThread failed");
    res = 0;
    goto cleanup;
  }
  switch (WaitForSingleObject(remote_thread, 30000)) {
    case WAIT_TIMEOUT:
      win32_perror(ERROR_TIMEOUT, L"WaitForSingleObject failed");
      res = 0;
    case WAIT_FAILED:
      win32_perror(GetLastError(), L"WaitForSingleObject failed");
      res = 0;
  }
cleanup:
  CloseHandle(process);
  return res;
}

/*
 * using the local LoadLibraryA address might seem wrong,
 * but in practice kernel32 is mapped to the same address in all processes
 * so it works
 */

int win32_inject(int pid, wchar_t* path) {
  void* pfnLoadLibraryW;
  void *remote_path;
  int res;
  if (!win32_addr("kernel32.dll", "LoadLibraryW", &pfnLoadLibraryW)) {
    return 0;
  }
  remote_path = win32_rwstrdup(pid, path);
  if (!remote_path) {
    return 0;
  }
  res = win32_wait_for_remote_thread(pid, pfnLoadLibraryW, remote_path);
  win32_rfree(pid, remote_path);
  return res;
}

int win32_resume(int pid) {
  HANDLE process;
  typedef LONG NTAPI fnNtResumeProcess(HANDLE);
  fnNtResumeProcess* resume = 0;
  LONG status;
  if (!win32_addr("ntdll.dll", "NtResumeProcess", (void**)&resume)) {
    return 0;
  }
  process = win32_process(pid);
  if (!process) {
    return 0;
  }
  status = resume(process);
  if (!NT_SUCCESS(status)) {
    win32_perror(status, L"NtResumeProcess failed");
  }
  CloseHandle(process);
  return NT_SUCCESS(status);
}

int win32_coinit() {
  /* it's fine to init multiple times if flags are the same */
  int flags = COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE;
  HRESULT hr = CoInitializeEx(0, flags);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoInitializeEx failed");
    return 0;
  }
  return 1;
}

int win32_couninit() {
  CoUninitialize();
  return 1;
}

/* dlls need certain permissions to be visible to uwp processes */
int uwp_fileperm(wchar_t* file) {
  PACL old_acl = 0;
  PACL new_acl = 0;
  PSECURITY_DESCRIPTOR sd = 0;
  EXPLICIT_ACCESS_W access;
  SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
  DWORD res = ERROR_SUCCESS;
  PSID sid;

  /* get current acl */
  res = GetNamedSecurityInfoW(file, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, 0, 0, &old_acl, 0, &sd);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"GetNamedSecurityInfoW failed");
    goto cleanup;
  }

  /* sid for all application packages */
  ConvertStringSidToSidW(L"S-1-15-2-1", &sid);
  if (!sid) {
    win32_perror(GetLastError(), L"ConvertStringSidToSid failed");
    goto cleanup;
  }

  ZeroMemory(&access, sizeof(access));
  access.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
  access.grfAccessMode = SET_ACCESS;
  access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  access.Trustee.ptstrName = (LPWSTR)sid;

  /* merge new ace into old acl */
  res = SetEntriesInAclW(1, &access, old_acl, &new_acl);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"SetEntriesInAcl failed");
    goto cleanup;
  }

  /* attach new acl */
  res = SetNamedSecurityInfoW(file, SE_FILE_OBJECT, si, 0, 0, new_acl, 0);
  if (res != ERROR_SUCCESS) {
    win32_perror(res, L"SetNamedSecurityInfo failed");
    goto cleanup;
  }

cleanup:
  if (sd) {
    LocalFree((HLOCAL)sd);
  }
  if (new_acl) {
    LocalFree((HLOCAL)new_acl);
  }
  return res == ERROR_SUCCESS;
}

/* class is FamilyName!ClassName */
int uwp_launch_class(wchar_t* class, int* pid) {
  DWORD dwpid = 0;
  IApplicationActivationManager* mgr;
  HRESULT hr;

  if (!win32_coinit()) {
    return 0;
  }

  hr = CoCreateInstance(&CLSID_ApplicationActivationManager, 0,
    CLSCTX_ALL, &IID_IApplicationActivationManager, (void**)&mgr);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoCreateInstance failed");
    goto cleanup;
  }

  /* this seems to fail on win10 /shrug */
  CoAllowSetForegroundWindow((IUnknown*)mgr, 0);

  hr = IApplicationActivationManager_ActivateApplication(mgr, class, 0,
    AO_NONE, &dwpid);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"ActivateApplication failed");
    goto cleanup;
  }

  if (pid) {
    *pid = (int)dwpid;
  }

cleanup:
  if (mgr) {
    IApplicationActivationManager_Release(mgr);
  }
  win32_couninit();
  return SUCCEEDED(hr);
}

int uwp_family(wchar_t* app, wchar_t* buf, size_t buflen) {
  UINT32 len = (UINT32)buflen;
  DWORD err = PackageFamilyNameFromFullName(app, &len, buf);
  if (err != ERROR_SUCCESS) {
    win32_perror((int)err, L"PackageFamilyNameFromFullName failed");
    return 0;
  }
  return 1;
}

int uwp_class(wchar_t* app, wchar_t* buf, size_t buflen) {
  if (!uwp_family(app, buf, buflen)) {
    return 0;
  }
  wcscat_s(buf, buflen - 1, L"!App");
  return 1;
}

int uwp_launch(wchar_t* app, int* pid) {
  WCHAR class[512];
  if (!uwp_class(app, class, sizeof(class))) {
    return 0;
  }
  return uwp_launch_class(class, pid);
}

int uwp_debug(wchar_t* debugger, wchar_t* app) {
  int res = 1;
  HRESULT hr;
  IPackageDebugSettings* settings = 0;
  int pid = 0;

  if (!win32_coinit()) {
    return 0;
  }

  hr = CoCreateInstance(&CLSID_PackageDebugSettings, 0, CLSCTX_ALL,
    &IID_IPackageDebugSettings, (void**)&settings);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"CoCreateInstance failed");
    res = 0;
    goto cleanup;
  }

  hr = IPackageDebugSettings_EnableDebugging(settings, app, debugger, 0);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"EnableDebugging failed");
    res = 0;
    goto cleanup;
  }

  if (!uwp_launch(app, &pid)) {
    res = 0;
    goto cleanup;
  }

  wprintf(L"launched as %d\n", pid);
  hr = IPackageDebugSettings_DisableDebugging(settings, app);
  if (FAILED(hr)) {
    win32_perror((int)hr, L"DisableDebugging failed");
    res = 0;
    goto cleanup;
  }

cleanup:
  if (settings) {
    IPackageDebugSettings_Release(settings);
  }

  win32_couninit();
  return res;
}

// ------------------------------------------------------------------------

void cli_printargs(int argc, wchar_t* argv[]) {
  int i;
  for (i = 0; i < argc; ++i) {
    wprintf(L"%s ", argv[i]);
  }
  wprintf(L"\n");
}

void cli_start(wchar_t* self, wchar_t* app) {
  wprintf(L"starting %s in debug mode\n", app);
  uwp_debug(self, app);
}

/* TODO: make this function more readable */
/* windows will suspend the app's process and call us back with "-p pid" */
void cli_inject(int argc, wchar_t* argv[]) {
  wchar_t fullpath[MAX_PATH];
  wchar_t* p;
  int pid = 0;
  int i;
  HANDLE find;
  WIN32_FIND_DATAW fd;
  DWORD err;
  int success = 1;

  for (i = 1; i < argc - 1; ++i) {
    if (!wcscmp(argv[i], L"-p")) {
      pid = _wtoi(argv[i + 1]);
      break;
    }
  }

  /* get full path to dlls by stripping last element from argv[0] */
  wcscpy_s(fullpath, sizeof(fullpath), argv[0]);
  p = &fullpath[wcslen(fullpath) - 1];
  for (; p > fullpath && *p != '\\'; --p);
  *p = 0;
  wcscat_s(fullpath, sizeof(fullpath), L"\\dlls\\*.dll");

  find = FindFirstFileW(fullpath, &fd);
  if (find == INVALID_HANDLE_VALUE) {
    win32_perror((int)GetLastError(), L"FindFirstFileW failed");
    success = 0;
    goto cleanup;
  }

  p = &fullpath[wcslen(fullpath) - 1];
  for (; p > fullpath && *p != '\\'; --p);
  *p = 0;

  do {
    wprintf(L"%s\n", fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      continue;
    }
    *p = 0;
    wcscat_s(fullpath, sizeof(fullpath), L"\\");
    wcscat_s(fullpath, sizeof(fullpath), fd.cFileName);
    wprintf(L"injecting %s into process %d\n", fullpath, pid);
    uwp_fileperm(fullpath);
    if (!win32_inject(pid, fullpath)) {
      success = 0;
      goto cleanup;
    }
  } while (FindNextFileW(find, &fd));

  err = GetLastError();
  if (err != ERROR_NO_MORE_FILES) {
    win32_perror((int)err, L"FindNextFileW failed");
    success = 0;
    goto cleanup;
  }

cleanup:
  if (!win32_resume(pid) || !success) {
    for (;;) {
      Sleep(1000);
    }
  }
}

int wmain(int argc, wchar_t* argv[]) {
  cli_printargs(argc, argv);
  if (argc == 2) {
    cli_start(argv[0], argv[1]);
  } else if (argc >= 3) {
    cli_inject(argc, argv);
  } else {
    fwprintf(stderr, L"usage: %s full_app_name\n", argv[0]);
    return 1;
  }
  return 0;
}
