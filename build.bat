@echo off
setlocal enabledelayedexpansion

echo ====================================================================
echo  Autonomous AI-Powered Malware Sandbox & Code Analyzer - Build Tool
echo ====================================================================

:: Set compiler paths if not in PATH
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\Users\hp\tools\w64devkit\bin\gcc.exe" (
        set "PATH=C:\Users\hp\tools\w64devkit\bin;%PATH%"
        echo [*] Added portable w64devkit GCC/G++ to PATH.
    ) else (
        echo [-] Error: GCC compiler not found! Please ensure gcc is installed.
        exit /b 1
    )
)

echo [+] Compiling Component 1: Low-Level C Agent (c_agent.exe)...
gcc -O2 -Wall -I c_agent/include c_agent/src/pe_parser.c c_agent/src/elf_parser.c c_agent/src/ipc_transport.c c_agent/src/fs_monitor.c c_agent/src/main.c -o c_agent/c_agent.exe
if %errorlevel% neq 0 (
    echo [-] Failed to compile C Agent.
    exit /b 1
)
echo [✓] C Agent compiled successfully -> c_agent/c_agent.exe

echo [+] Compiling Component 2a: C++ Features Processing Shared Library (features_engine.dll)...
g++ -O3 -shared -std=c++17 -I cpp_engine/include cpp_engine/src/entropy_calculator.cpp cpp_engine/src/string_tokenizer.cpp cpp_engine/src/signature_detector.cpp cpp_engine/src/binary_feature_extractor.cpp cpp_engine/src/c_bindings.cpp -o cpp_engine/features_engine.dll
if %errorlevel% neq 0 (
    echo [-] Failed to compile C++ shared library.
    exit /b 1
)
echo [✓] C++ Shared Library compiled successfully -> cpp_engine/features_engine.dll

echo [+] Compiling Component 2b: C++ PyBind11 Python Module (feature_engine.pyd)...
for /f "delims=" %%i in ('python -m pybind11 --includes 2^>nul') do set PYBIND_INC=%%i
for /f "delims=" %%i in ('python -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))" 2^>nul') do set EXT_SUFFIX=%%i
for /f "delims=" %%i in ('python -c "import sys, os; print(os.path.join(sys.prefix, 'libs'))" 2^>nul') do set PY_LIBDIR=%%i

g++ -O3 -shared -std=c++17 -I cpp_engine/include %PYBIND_INC% cpp_engine/src/entropy_calculator.cpp cpp_engine/src/string_tokenizer.cpp cpp_engine/src/signature_detector.cpp cpp_engine/src/binary_feature_extractor.cpp cpp_engine/src/pybind_module.cpp -L"%PY_LIBDIR%" -lpython314 -o cpp_engine/feature_engine.pyd
if %errorlevel% neq 0 (
    echo [!] Note: PyBind11 pyd compilation skipped or failed; system will use features_engine.dll via ctypes.
) else (
    echo [✓] PyBind11 module compiled successfully -> cpp_engine/feature_engine.pyd
)

echo [+] Compiling Test Sample Binaries...
gcc -O2 samples/clean_utility.c -o samples/clean_utility.exe
gcc -O2 samples/simulated_packer.c -o samples/simulated_packer.exe
gcc -O2 samples/simulated_trojan.c -o samples/simulated_trojan.exe
gcc -O2 samples/simulated_ransomware.c -o samples/simulated_ransomware.exe
echo [✓] Test samples compiled.

echo ====================================================================
echo  BUILD COMPLETE! All hybrid components successfully generated.
echo ====================================================================
echo  Quick Start:
echo    python -m python_orchestrator.main demo
echo    python -m python_orchestrator.main scan samples/simulated_trojan.exe
echo    python -m python_orchestrator.main live-agent --watch sandbox_dropzone
echo ====================================================================

