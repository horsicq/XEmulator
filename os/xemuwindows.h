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
#ifndef XEMUWINDOWS_H
#define XEMUWINDOWS_H

#include <QList>
#include <QMap>

#include "winapi/xemuwinapi.h"
#include "xemuoperatingsystem.h"
#include "xemuregisters.h"  // SEH_FRAME stores a register snapshot by value

// Windows process personality. Reproduces the state that ntdll's loader leaves for
// a freshly created process: mapped image + dependencies, a PEB and a TEB with the
// three PEB_LDR_DATA module lists, a thread stack, and the initial segment registers
// (FS base == TEB on x86, GS base == TEB on x86-64).
class XEmuWindows : public XEmuOperatingSystem {
    Q_OBJECT

public:
    explicit XEmuWindows(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent = nullptr);
    ~XEmuWindows() override;

    QString getOSName() const override;

    bool setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options) override;
    bool handleApiCall(XEmuRegisters *pRegisters, XADDR nPC) override;
    bool handleException(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress) override;
    bool handleInterrupt(int nVector, XEmuRegisters *pRegisters) override;
    bool processExited() const override;
    quint64 apiStubBase() const override;
    quint64 apiStubLimit() const override;
    bool resolveImportStub(quint64 nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const override;

private:
    friend struct XEmuWindowsLoaderListTestAccess;
    friend struct XEmuWindowsForwarderTestAccess;

    struct LOADED {
        XEmuFileFormat *pFormat;
        XEmuFileFormat::MODULE module;
        bool bOwned;  // this class created and must delete the format loader
    };

    quint64 m_nImageBaseOverride = 0;  // setupProcess OPTIONS: forced base for the main image (0 = preferred)
    XADDR _chooseBase(XEmuFileFormat *pFormat);
    bool _mapModule(XEmuFileFormat *pFormat, bool bOwned, XEmuFileFormat::MODULE *pModuleResult);
    void _loadDependencies(const QString &sSystemRoot, int nMaxModules);
    bool _mapRealSystemDlls();  // Option B: map real ntdll/kernelbase/kernel32 + intercept exports
    void _patchImports();
    XADDR _setupStack(quint64 nStackSize, quint64 *pnStackBase, quint64 *pnStackLimit);
    void _buildLoaderData();
    void _buildPebTeb(quint64 nStackBase, quint64 nStackLimit);
    void _setupRegisters(XEmuRegisters *pRegisters, quint64 nStackTop, bool bIsDll);
    void _releaseOwnedFormats();

    int _ptrSize() const;
    bool _writePtr(XADDR nAddress, quint64 nValue);
    quint64 _readPtr(XADDR nAddress) const;
    XADDR _poolAlloc(quint64 nSize);
    XADDR _writeUnicode(const QString &sText, quint16 *pnByteLength);
    void _linkList(XADDR nHeadAddress, int nLinkOffset, const QList<XADDR> &listEntryBases);

    // One entry a synthetic module exports: a function the loaded images import from that
    // DLL, resolved to the winapi trampoline the rebuilt IAT should hold.
    struct SYN_EXPORT {
        QString sName;    // export name (empty for an ordinal-only import)
        qint64 nOrdinal;  // requested ordinal (-1 for a by-name import)
        XADDR nStub;      // winapi trampoline this export resolves to
    };

    struct FORWARDED_EXPORT {
        QString sName;    // target symbol name, empty for an ordinal target
        qint64 nOrdinal;  // target ordinal, -1 for a named target
    };

    // Runtime loader modelling: create a minimal module image + a PEB Ldr entry for a
    // library loaded by name at runtime (LoadLibraryA). Returns the module base (used as
    // the HMODULE), or 0 on failure. Registered as the winapi module-creator callback.
    XADDR _createSyntheticModule(const QString &sNameLower);
    // Gather every function the loaded images import from sLibraryLower (dedup'd) and
    // allocate/return the winapi trampoline for each. These become the synthetic module's
    // exports so a packer that rebuilds its IAT by walking the export table (PeX) resolves
    // to the same trampoline _patchImports would have written.
    QList<SYN_EXPORT> _collectImportsFor(const QString &sLibraryLower);
    // Remember validated PE forwarder targets found in mapped real DLLs.  API-set
    // contract DLLs are commonly absent as files; when the guest loads one, its
    // synthetic export table is populated from these observed contracts.
    void _collectForwardedExports(
        const QList<XEmuFileFormat::EXPORT_ENTRY> &exports);
    // Write a minimal but valid PE image (DOS + NT headers + an export directory that names
    // the module AND exports `exports`) so code that parses the handle as a module finds a
    // real header, and code that walks the export table finds resolvable function addresses.
    void _writeSyntheticImage(XADDR nBase, quint64 nSize, const QString &sNameLower, const QList<SYN_EXPORT> &exports);
    // Append an LDR_DATA_TABLE_ENTRY for a newly loaded module to the three PEB module
    // lists (InLoadOrder / InMemoryOrder / InInitializationOrder).
    void _ldrAddModule(const QString &sNameLower, XADDR nBase, quint64 nSize, XADDR nEntryPoint);
    // Insert one LIST_ENTRY link at the tail of a circular list (before its head).
    void _ldrAppend(XADDR nHeadAddress, XADDR nLinkAddress);
    XADDR _findLdrEntryByBase(XADDR nHeadAddress, int nLinkOffset, int nDllBaseOffset, XADDR nDllBase) const;
    void _ldrMoveToFront(XADDR nHeadAddress, int nLinkOffset, XADDR nEntryAddress);

    bool _isAsdPackCandidate() const;

    // Forwards Windows-API-layer log text to this OS object's infoMessage() signal.
    void _forwardWinApiLog(const QString &sText);

    // --- Win32 SEH exception dispatch (32-bit fs:[0] EXCEPTION_REGISTRATION_RECORD chain) ---
    // One in-flight dispatch. SEH nests (a handler can itself fault), so these are kept
    // on a LIFO stack rather than in single-valued members; a handler returning to the
    // trap always belongs to the top frame.
    struct SEH_FRAME {
        XADDR nRecord;             // EXCEPTION_REGISTRATION_RECORD currently being tried
        XADDR nContextPtr;         // CONTEXT built on the guest stack
        XADDR nExcRecordPtr;       // EXCEPTION_RECORD built on the guest stack
        XADDR nFaultingPC;         // faulting instruction
        XADDR nSavedSehHead;       // fs:[0] chain head saved before the nested dispatch record was installed
        XADDR nStagedTop;          // highest staged stack address (the CONTEXT); used to reclaim unwound-past frames
        bool bTrap;                // true = trap (int3/ud2: PC already advanced, cannot re-fault); false = fault (AV)
        XEmuRegisters faultRegs;   // register snapshot at the fault (for unhandled delivery)
    };

    // Dispatch a hardware exception to the guest SEH chain. Returns true if a handler
    // was invoked (execution redirected), false to let the emulator report the fault.
    bool _sehDispatch(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress, quint32 nExceptionCode, bool bTrap);
    // Called when a dispatched handler returns to the synthetic trap address; reads the
    // disposition in EAX and either resumes (ContinueExecution), tries the next record
    // (ContinueSearch), or restores the faulting state so the emulator delivers the fault.
    bool _sehHandlerReturned(XEmuRegisters *pRegisters);
    // Build EXCEPTION_RECORD + CONTEXT on the guest stack for the current fault into
    // pFrame (validating the reserved span is committed). Returns false on failure.
    bool _sehBuildFrame(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress, quint32 nExceptionCode, SEH_FRAME *pFrame);
    // Push the _except_handler(record, frame, context, dispatcher) call frame (for the
    // top dispatch) with the trap as the return address and jump to the record's handler.
    void _sehCallHandler(XEmuRegisters *pRegisters);
    void _sehWriteContext(XADDR nContext, XEmuRegisters *pRegisters, XADDR nEip);
    void _sehLoadContext(XADDR nContext, XEmuRegisters *pRegisters);

    XADDR m_nSehReturnTrap;         // synthetic return address a dispatched handler returns to
    QList<SEH_FRAME> m_listSehStack;  // LIFO of in-flight dispatches (nesting)
    bool m_bSehDeliver;             // an unhandled fault is being re-raised for delivery
    XADDR m_nSehDeliverPC;          // the PC of that fault (guards against re-dispatch loop)
    bool m_bSehTerminate;           // an unhandled trap (int3/ud2) exhausted its chain -> halt the run

    bool m_bIs64;
    XEmuArchType m_archType;
    bool m_bAsdPackMode;
    bool m_bImploderMode;

    QList<LOADED> m_listLoaded;
    QMap<QString, int> m_mapNameToIndex;  // lower-case base name -> index in m_listLoaded
    QMap<QString, QList<FORWARDED_EXPORT> > m_mapForwardedExports;
    int m_nForwardedExportCount = 0;

    XADDR m_nPebAddress;
    XADDR m_nTebAddress;
    XADDR m_nLdrDataAddress;
    XADDR m_nPoolAddress;
    XADDR m_nPoolCursor;
    quint64 m_nPoolSize;

    XEmuWinApi *m_pWinApi;  // emulated Windows-API layer (loader/memory stubs)
};

#endif  // XEMUWINDOWS_H
