/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XEMUWINAPI_H
#define XEMUWINAPI_H

#include <functional>

#include <QByteArray>
#include <QMap>
#include <QString>
#include <QVector>

#include "xemuarch.h"
#include "xemumemorymanager.h"
#include "xemuregisters.h"

class QFile;

// Emulated Windows-API layer for the user-mode emulator.
//
// Real DLL code cannot be executed by the subset CPU core, so instead of pointing
// import thunks at genuine kernel32 exports we point them at synthetic *trampoline*
// addresses carved out of a small reserved arena. Before every instruction the OS
// personality asks this class whether the current PC is one of those trampolines;
// if it is, dispatch() models the call in C++ (against the emulator's own memory
// manager), sets the return value and simulates the ABI return, and the CPU step is
// skipped. This is exactly what a packer stub needs: it can VirtualAlloc a scratch
// buffer, VirtualProtect it, and walk LoadLibraryA / GetProcAddress to rebuild an
// import table -- all serviced without ever running native library code.
//
// Currently modelled: VirtualAlloc, VirtualProtect, LoadLibraryA, GetProcAddress.
// Every other import resolves to a generic no-op trampoline so a stray call traps
// cleanly here instead of faulting into unmapped memory.
class XEmuWinApi {
public:
    XEmuWinApi(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64);
    ~XEmuWinApi();

    void setProcessContext(const QString &sExecutable, const QString &sArguments, const QString &sWorkingDirectory);

    typedef std::function<void(const QString &)> LOG_CALLBACK;
    void setLogger(LOG_CALLBACK fnLog);

    // Called the first time a module is loaded by name (LoadLibraryA) that is not
    // already mapped. The OS layer synthesises a minimal module image and a PEB Ldr
    // entry for it, returning the module base to use as the handle. Returns 0 to fall
    // back to an opaque synthetic handle.
    typedef std::function<XADDR(const QString &)> MODULE_CREATOR;
    void setModuleCreator(MODULE_CREATOR fnCreate);

    // Base of the main executable, returned by GetModuleHandleA(NULL).
    void setMainModuleBase(XADDR nBaseAddress);

    // Raw bytes of the main module's file on disk. A packer with anti-tamper opens its own
    // file (GetModuleFileNameW -> NtOpenFile) and CRCs it; without the real bytes the check
    // fails and it bails (ExitProcess(0xDEADC0DE)). Served by the modelled Nt file APIs.
    void setMainModuleFile(const QByteArray &baFile);

    // Reserve the trampoline arena and pre-register the modelled APIs. Must be
    // called once before stubFor()/dispatch(). Returns false if the arena could
    // not be allocated.
    bool init();

    // Tell the layer that a real module image is mapped at nBaseAddress. Enables
    // LoadLibraryA to return the genuine base and GetProcAddress to name it.
    void registerModule(const QString &sLibraryLower, XADDR nBaseAddress);

    // Stable trampoline address for lib!func (allocated on first use). Known loader
    // APIs get a modelled handler; everything else gets a generic no-op handler.
    XADDR stubFor(const QString &sLibrary, const QString &sFunction, qint64 nOrdinal = -1);

    // Trampoline address if lib!func is one of the modelled loader APIs, else 0.
    // Used so import patching only diverts the handful of APIs it must model.
    XADDR stubForKnownApi(const QString &sLibrary, const QString &sFunction);

    bool isStub(XADDR nAddress) const;

    // Real-DLL export interception (Option B). When the genuine kernel32/ntdll/kernelbase
    // images are mapped as data so a packer's export walk yields authentic VAs, every
    // reachable export VA must be intercepted BEFORE the subset CPU fetches real DLL code.
    // registerRealExport records a resolved export VA -> modelled API (or generic); addRealRange
    // records the module image range so isStub() also fires for any PC that lands inside it.
    void registerRealExport(XADDR nVa, const QString &sLibrary, const QString &sFunction, qint64 nOrdinal);
    void addRealRange(XADDR nBase, quint64 nSize);

    // Reserve a fresh trampoline slot not bound to any API. The OS layer uses it as a
    // synthetic return address (e.g. the SEH handler-return trap): the arena is filled
    // with 0xC3, so even an unintercepted landing returns cleanly. Returns 0 if the
    // arena is not initialised.
    XADDR allocTrampoline();

    // If the current PC (pRegisters) is a trampoline, service the call and return
    // true; otherwise return false and leave the registers untouched.
    bool dispatch(XEmuRegisters *pRegisters);

    // True once the guest called ExitProcess/TerminateProcess through a trampoline.
    bool processExited() const
    {
        return m_bProcessExited;
    }

    // Bounds of the API-trampoline arena, so a caller (import reconstruction) can cheaply
    // recognise a resolved-import pointer written into the guest IAT.
    XADDR stubBase() const
    {
        return m_nStubBase;
    }
    XADDR stubLimit() const
    {
        return m_nStubBase + m_nStubSize;
    }

    // Reverse-resolve a trampoline address to the import it stands for (original-case name).
    // Returns false if nStub is not a known modelled/named import stub.
    bool resolveImportStub(XADDR nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const;

private:
    enum API_ID {
        API_GENERIC = 0,
        API_VIRTUALALLOC,
        API_VIRTUALPROTECT,
        API_VIRTUALFREE,
        API_VIRTUALFREEEX,
        API_VIRTUALPROTECTEX,
        API_LOADLIBRARYA,
        API_LOADLIBRARYEXA,
        API_GETPROCADDRESS,
        API_GETMODULEHANDLEA,
        API_GLOBALALLOC,
        API_GLOBALFREE,
        API_LOCALALLOC,
        API_LOCALFREE,
        API_HEAPALLOC,
        API_HEAPFREE,
        API_EXITPROCESS,
        API_CREATEFILE
    };

    static int _classify(const QString &sLibrary, const QString &sFunction);
    XADDR _allocStub();
    XADDR _ensureCommandLineA();
    XADDR _ensureCrtIob();

    // Allocate nSize bytes of scratch (R/W/X) and return the base to the guest,
    // cleaning nArgCount stdcall arguments. Shared by the heap-allocation APIs.
    void _allocReturn(XEmuRegisters *pRegisters, quint64 nSize, int nArgCount, const QString &sName);

    // ABI helpers (32-bit stdcall / 64-bit Microsoft x64).
    quint64 _arg(XEmuRegisters *pRegisters, int nIndex) const;
    void _return(XEmuRegisters *pRegisters, quint64 nValue, int nArgCount);

    QString _readAnsi(XADDR nAddress, int nMax = 260) const;
    QString _hostPath(const QString &sGuestPath, bool bWrite) const;
    void _consoleWrite(const QByteArray &baText, bool bStderr);
    void _flushConsole();
    XEmuMemoryManager::MEMORY_FLAGS _flagsFromProtect(quint32 nProtect) const;

    XADDR _moduleHandle(const QString &sLibraryLower, bool bCreate);
    QString _moduleName(XADDR nHandle) const;

    // Modelled APIs.
    void _apiVirtualAlloc(XEmuRegisters *pRegisters);
    void _apiVirtualProtect(XEmuRegisters *pRegisters);
    void _apiVirtualFree(XEmuRegisters *pRegisters);
    void _apiLoadLibraryA(XEmuRegisters *pRegisters);
    void _apiLoadLibraryExA(XEmuRegisters *pRegisters);
    void _apiVirtualFreeEx(XEmuRegisters *pRegisters);
    void _apiVirtualProtectEx(XEmuRegisters *pRegisters);
    void _apiGetProcAddress(XEmuRegisters *pRegisters);
    void _apiGetModuleHandleA(XEmuRegisters *pRegisters);
    void _apiGlobalAlloc(XEmuRegisters *pRegisters);
    void _apiGlobalFree(XEmuRegisters *pRegisters);
    void _apiLocalAlloc(XEmuRegisters *pRegisters);
    void _apiLocalFree(XEmuRegisters *pRegisters);
    void _apiHeapAlloc(XEmuRegisters *pRegisters);
    void _apiHeapFree(XEmuRegisters *pRegisters);
    void _apiExitProcess(XEmuRegisters *pRegisters);
    void _apiCreateFile(XEmuRegisters *pRegisters);

    // By-name model for the bounded set of environment / anti-analysis stdcall APIs a packer
    // calls once real DLLs are mapped (IsWow64Process, VirtualQuery, affinity, TLS, version,
    // ...). Returns true if it modelled the call (correct return value + output buffers +
    // stdcall arg cleanup); false to fall through to the generic no-op. Only used on x86.
    bool _apiByName(XEmuRegisters *pRegisters, const QString &sFunction);

    void _log(const QString &sText) const;

    XEmuMemoryManager *m_pMemoryManager;
    XEmuArch *m_pArch;
    bool m_bIs64;
    LOG_CALLBACK m_fnLog;
    MODULE_CREATOR m_fnCreateModule;
    XADDR m_nMainModuleBase;

    XADDR m_nStubBase;
    quint64 m_nStubSize;
    XADDR m_nStubCursor;

    struct REAL_RANGE {
        XADDR nLo;
        XADDR nHi;
    };
    QVector<REAL_RANGE> m_realRanges;  // mapped real-DLL image ranges to intercept

    QByteArray m_baMainFile;             // main module's on-disk bytes (for anti-tamper file reads)
    QString m_sCommandLine;
    QString m_sWorkingDirectory;
    QString m_sIncludeDirectory;
    XADDR m_nCommandLineA = 0;
    XADDR m_nCommandLineW = 0;
    XADDR m_nCrtIob = 0;
    QMap<XADDR, QFile *> m_mapHostFiles;
    QByteArray m_baStdoutPending;
    QByteArray m_baStderrPending;
    QMap<XADDR, qint64> m_mapFileOffset;  // open file handle -> current byte offset
    QMap<XADDR, bool> m_mapSectionIsFile;  // section handle -> backed by the main-module file
    XADDR m_nNextFileHandle;             // next synthetic file/section handle to hand out
    QMap<XADDR, quint64> m_heapSizes;    // alloc base -> requested size (for HeapSize/RtlSizeHeap)
    QMap<quint32, XADDR> m_tlsValues;
    quint32 m_nNextTlsIndex = 1;

    XADDR m_nFakeHandleCursor;
    bool m_bProcessExited;  // guest called ExitProcess/TerminateProcess

    struct IMPORT_NAME {
        QString sLibrary;   // original-case DLL name, e.g. "KERNEL32.DLL"
        QString sFunction;  // original-case export name (empty for by-ordinal)
        qint64 nOrdinal;    // -1 for by-name
    };

    QMap<XADDR, int> m_mapStubToApi;      // trampoline address -> API_ID
    QMap<XADDR, IMPORT_NAME> m_mapStubToImport;  // trampoline address -> original import name (for IAT rebuild)
    QMap<QString, XADDR> m_mapNameToStub;  // "lib!func" (lower) -> trampoline
    QMap<QString, XADDR> m_mapModuleBase;  // library (lower) -> real mapped base
    QMap<XADDR, QString> m_mapHandleName;  // module handle -> library (lower)
    QMap<QString, XADDR> m_mapNameHandle;  // library (lower) -> synthetic handle
};

#endif  // XEMUWINAPI_H
