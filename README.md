launches uwp apps and injects dll's into them as early as possible by
posing as a debugger and launching the app suspended

if you need a sample dll, here's one that hooks some uwp interfaces for
debugging and reverse engineering https://github.com/Francesco149/uwpspy

might have a GUI to let you pick apps to launch eventually, not a proprity
at the moment

will provide binaries when it's more polished

# compiling
install visual c++ build tools 2017 and the windows 10 sdk

open powershell and navigate to uwpinject

```ps1
.\vcvarsall17.ps1
.\build.ps1
```

# usage (command line)
open powershell, navigate to uwpinject and run

```ps1
.\uwpinject.exe $((Get-AppxPackage uwp-template).PackageFullName)
```

where MyPackage is the name of your target app

this will launch the app and inject all dlls in the ```dlls``` folder
which must be located in the same directory as uwpinject.exe

if it doesn't work, try running powershell as admin. I haven't had issues
injecting as user though

# resources on uwp and winrt internals
* https://reverseengineering.stackexchange.com/questions/17127/how-to-reverse-engineer-a-windows-10-uwp-app
* https://docs.microsoft.com/en-us/windows/desktop/api/appmodel/
* https://docs.microsoft.com/en-us/windows/uwp/xbox-apps/automate-launching-uwp-apps
* https://github.com/GPUOpen-Tools/OCAT/blob/2226171673f3c89369f4b70cf72f12daa94bf5c1/UWPOverlay/UWPOverlay.cpp
* https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-abi
* https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/interop-winrt-cx
