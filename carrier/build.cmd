@echo off
setlocal
pushd "%~dp0"
if not defined VSCMD_ARG_TGT_ARCH call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
if errorlevel 1 exit /b 1
if not "%VSCMD_ARG_TGT_ARCH%"=="x86" exit /b 2
if not exist build mkdir build
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD src\cs_preflight.cpp /Fo:build\cs_preflight.obj /Fe:build\cs_preflight.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD src\cs_contract_test.cpp /Fo:build\cs_contract_test.obj /Fe:build\cs_contract_test.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD src\cs_attach.cpp /Fo:build\cs_attach.obj /Fe:build\cs_attach.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD /LD src\cs_observer.cpp /Fo:build\cs_observer.obj /Fe:build\cs_observer.dll user32.lib
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD /LD src\cs_observer_fixture_provider.cpp /Fo:build\cs_observer_fixture_provider.obj /Fe:build\cs_observer_fixture_provider.dll /link /DEF:src\cs_observer_fixture_provider.def
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /MD src\cs_observer_forwarding_fixture.cpp /Fo:build\cs_observer_forwarding_fixture.obj /Fe:build\cs_observer_forwarding_fixture.exe
if errorlevel 1 exit /b 1
popd
