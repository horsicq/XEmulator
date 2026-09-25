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
#include "xemuwindows.h"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <functional>

#include <QDir>
#include <QFileInfo>
#include <QSet>
#include <QVector>

#include "xemupe.h"

#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {
const quint64 N_FAKE_PID = 0x1000;
const quint64 N_FAKE_TID = 0x1004;

bool isUsable32BitSystemDllDirectory(const QString &sDirectory, QString *pReason)
{
    const QString sCleanDirectory = QDir::cleanPath(sDirectory);
    if (sCleanDirectory.isEmpty() || !QDir::isAbsolutePath(sCleanDirectory)) {
        if (pReason) {
            *pReason = QStringLiteral("path is not absolute");
        }
        return false;
    }

    QDir directory(sCleanDirectory);
    if (!directory.exists()) {
        if (pReason) {
            *pReason = QStringLiteral("directory does not exist");
        }
        return false;
    }

    const QList<QPair<QString, QString>> listRequired = {
        qMakePair(QStringLiteral("ntdll.dll"), QStringLiteral("LdrGetProcedureAddress")),
        qMakePair(QStringLiteral("kernelbase.dll"), QStringLiteral("VirtualAlloc")),
        qMakePair(QStringLiteral("kernel32.dll"), QStringLiteral("GetProcAddress"))
    };
    for (const QPair<QString, QString> &required : listRequired) {
        const QString &sDll = required.first;
        const QString sPath = directory.absoluteFilePath(sDll);
        XEmuPE pe;
        if (!pe.setFileName(sPath) || !pe.isValid() || pe.is64Bit() || (pe.getArchType() != XARCH_X86_32) || !pe.isDll() || (pe.getImageSize() == 0)) {
            if (pReason) {
                *pReason = QStringLiteral("%1 is missing or is not a usable 32-bit x86 PE DLL").arg(sPath);
            }
            return false;
        }
        if (pe.getExportRVA(required.second, -1) < 0) {
            if (pReason) {
                *pReason = QStringLiteral("%1 does not export required symbol %2")
                               .arg(sPath, required.second);
            }
            return false;
        }
    }

    return true;
}

#ifdef Q_OS_WIN
QString queryWindowsDirectory(bool bWow64)
{
    QVector<wchar_t> buffer(MAX_PATH);
    for (int nAttempt = 0; nAttempt < 2; nAttempt++) {
        UINT nLength = bWow64 ? GetSystemWow64DirectoryW(buffer.data(), (UINT)buffer.size())
                              : GetWindowsDirectoryW(buffer.data(), (UINT)buffer.size());
        if (nLength == 0) {
            return QString();
        }
        if (nLength < (UINT)buffer.size()) {
            return QDir::cleanPath(QString::fromWCharArray(buffer.constData(), (int)nLength));
        }
        if (nLength >= (UINT)(INT_MAX - 1)) {
            return QString();
        }
        buffer.resize((int)nLength + 1);
    }

    return QString();
}
#endif

QString resolve32BitSystemDllDirectory(QString *pError)
{
#ifndef Q_OS_WIN
    if (pError) {
        *pError = QStringLiteral("real Windows system DLLs are unavailable on this host");
    }
    return QString();
#else
    const QString sOverride = qEnvironmentVariable("XEMU_REALDLL_ROOT").trimmed();
    if (!sOverride.isEmpty()) {
        QString sReason;
        if (isUsable32BitSystemDllDirectory(sOverride, &sReason)) {
            return QDir::cleanPath(sOverride);
        }
        if (pError) {
            *pError = QStringLiteral("XEMU_REALDLL_ROOT is invalid: %1 (%2)").arg(sOverride, sReason);
        }
        return QString();
    }

    QStringList listCandidates;
    const QString sWow64Directory = queryWindowsDirectory(true);
    if (!sWow64Directory.isEmpty()) {
        listCandidates.append(sWow64Directory);
    }

    auto appendWindowsRootCandidates = [&listCandidates](const QString &sRoot) {
        if (sRoot.trimmed().isEmpty()) {
            return;
        }
        const QString sCleanRoot = QDir::cleanPath(sRoot);
        if (!QDir::isAbsolutePath(sCleanRoot)) {
            return;
        }
        QDir root(sCleanRoot);
        listCandidates.append(root.absoluteFilePath(QStringLiteral("SysWOW64")));
        listCandidates.append(root.absoluteFilePath(QStringLiteral("System32")));
    };

    appendWindowsRootCandidates(qEnvironmentVariable("SystemRoot"));
    appendWindowsRootCandidates(queryWindowsDirectory(false));

    QSet<QString> setSeen;
    QStringList listRejected;
    for (const QString &sCandidate : listCandidates) {
        const QString sCleanCandidate = QDir::cleanPath(sCandidate);
        const QString sKey = sCleanCandidate.toLower();
        if (setSeen.contains(sKey)) {
            continue;
        }
        setSeen.insert(sKey);

        QString sReason;
        if (isUsable32BitSystemDllDirectory(sCleanCandidate, &sReason)) {
            return sCleanCandidate;
        }
        listRejected.append(QStringLiteral("%1 (%2)").arg(sCleanCandidate, sReason));
    }

    if (pError) {
        if (listRejected.isEmpty()) {
            *pError = QStringLiteral("Windows did not report a system DLL directory");
        } else {
            *pError = QStringLiteral("no candidate contained usable 32-bit x86 system DLLs; checked %1").arg(listRejected.join(QStringLiteral("; ")));
        }
    }
    return QString();
#endif
}
}  // namespace

XEmuWindows::XEmuWindows(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent)
    : XEmuOperatingSystem(pMemoryManager, pArch, pParent), m_bIs64(true), m_archType(XARCH_X86_64), m_bAsdPackMode(false), m_bImploderMode(false), m_nPebAddress(0),
      m_nTebAddress(0), m_nLdrDataAddress(0),
      m_nPoolAddress(0), m_nPoolCursor(0), m_nPoolSize(0), m_pWinApi(nullptr), m_nSehReturnTrap(0), m_bSehDeliver(false), m_nSehDeliverPC(0), m_bSehTerminate(false)
{
}

XEmuWindows::~XEmuWindows()
{
    _releaseOwnedFormats();
    delete m_pWinApi;
}

QString XEmuWindows::getOSName() const
{
    return QStringLiteral("Windows");
}

void XEmuWindows::_forwardWinApiLog(const QString &sText)
{
    emit infoMessage(sText);
}

int XEmuWindows::_ptrSize() const
{
    return m_bIs64 ? 8 : 4;
}

bool XEmuWindows::_writePtr(XADDR nAddress, quint64 nValue)
{
    if (m_bIs64) {
        return m_pMemoryManager->writeQword(nAddress, nValue);
    }

    return m_pMemoryManager->writeDword(nAddress, (quint32)nValue);
}

quint64 XEmuWindows::_readPtr(XADDR nAddress) const
{
    if (m_bIs64) {
        return m_pMemoryManager->readQword(nAddress);
    }

    return m_pMemoryManager->readDword(nAddress);
}

XADDR XEmuWindows::_chooseBase(XEmuFileFormat *pFormat)
{
    quint64 nImageSize = pFormat->getImageSize();

    // Relocation reconstruction forces the MAIN image (the first module mapped, so the module
    // list is still empty) to a second base; XEmuPE::map() relocates it there via the file's
    // reloc table. Only honour it when that range is free.
    if ((m_nImageBaseOverride != 0) && m_listLoaded.isEmpty() && m_pMemoryManager->isRangeFree(m_nImageBaseOverride, nImageSize)) {
        return (XADDR)m_nImageBaseOverride;
    }

    XADDR nPreferred = pFormat->getPreferredImageBase();

    if ((nPreferred != 0) && m_pMemoryManager->isRangeFree(nPreferred, nImageSize)) {
        return nPreferred;
    }

    return m_pMemoryManager->findFree(nImageSize, m_pMemoryManager->getMinAddress(), XEmuMemoryManager::N_ALLOCATION_GRANULARITY);
}

bool XEmuWindows::_mapModule(XEmuFileFormat *pFormat, bool bOwned, XEmuFileFormat::MODULE *pModuleResult)
{
    XADDR nBase = _chooseBase(pFormat);

    if (nBase == 0) {
        emit errorMessage(tr("No free address space to map a module"));
        return false;
    }

    if (!pFormat->map(m_pMemoryManager, nBase, pModuleResult)) {
        return false;
    }

    LOADED loaded;
    loaded.pFormat = pFormat;
    loaded.module = *pModuleResult;
    loaded.bOwned = bOwned;

    m_mapNameToIndex.insert(pModuleResult->sName, m_listLoaded.size());
    m_listLoaded.append(loaded);

    return true;
}

void XEmuWindows::_loadDependencies(const QString &sSystemRoot, int nMaxModules)
{
    if (sSystemRoot.trimmed().isEmpty()) {
        emit infoMessage(tr("No system root configured; dependency DLLs will not be loaded"));
        return;
    }

    QDir systemDir(sSystemRoot);

    if (!systemDir.exists()) {
        emit errorMessage(tr("System root does not exist: %1").arg(sSystemRoot));
        return;
    }

    QSet<QString> setMissing;

    // Breadth-first walk: new modules are appended to m_listLoaded and picked up by
    // the same loop, so transitive dependencies are resolved too.
    for (int i = 0; (i < m_listLoaded.size()) && (m_listLoaded.size() < nMaxModules); i++) {
        QStringList listLibraries = m_listLoaded.at(i).pFormat->getImportLibraries();

        for (int j = 0; j < listLibraries.count(); j++) {
            QString sLibrary = listLibraries.at(j).toLower();

            if (m_mapNameToIndex.contains(sLibrary) || setMissing.contains(sLibrary)) {
                continue;
            }

            QString sPath = systemDir.absoluteFilePath(sLibrary);

            if (!QFileInfo::exists(sPath)) {
                setMissing.insert(sLibrary);
                emit infoMessage(tr("Dependency not found: %1").arg(sLibrary));
                continue;
            }

            XEmuPE *pDependency = new XEmuPE(this);
            connect(pDependency, &XEmuFileFormat::infoMessage, this, &XEmuOperatingSystem::infoMessage);
            connect(pDependency, &XEmuFileFormat::errorMessage, this, &XEmuOperatingSystem::errorMessage);

            XEmuFileFormat::MODULE module;

            if (!pDependency->setFileName(sPath) || !_mapModule(pDependency, true, &module)) {
                delete pDependency;
                setMissing.insert(sLibrary);
                continue;
            }
        }
    }
}

void XEmuWindows::_patchImports()
{
    for (int i = 0; i < m_listLoaded.size(); i++) {
        const LOADED &loaded = m_listLoaded.at(i);
        QList<XEmuFileFormat::IMPORT> listImports = loaded.pFormat->getImports();

        for (int j = 0; j < listImports.count(); j++) {
            const XEmuFileFormat::IMPORT &import = listImports.at(j);
            XADDR nSlot = loaded.module.nBaseAddress + import.nSlotRVA;

            // Loader/memory APIs the subset core cannot run natively are always
            // diverted to a modelled trampoline, even when kernel32 is mapped.
            if (m_pWinApi) {
                XADDR nKnownStub = m_pWinApi->stubForKnownApi(import.sLibrary, import.sFunction);

                if (nKnownStub != 0) {
                    _writePtr(nSlot, nKnownStub);
                    continue;
                }
            }

            if (m_mapNameToIndex.contains(import.sLibrary)) {
                const LOADED &target = m_listLoaded.at(m_mapNameToIndex.value(import.sLibrary));
                qint64 nExportRVA = target.pFormat->getExportRVA(import.sFunction, import.nOrdinal);

                if (nExportRVA >= 0) {
                    _writePtr(nSlot, target.module.nBaseAddress + nExportRVA);
                    continue;
                }
            }

            // Exporting module absent (or export not found): point the thunk at a
            // generic trampoline so a call traps in the API layer instead of
            // faulting into unmapped memory.
            if (m_pWinApi) {
                XADDR nStub = m_pWinApi->stubFor(import.sLibrary, import.sFunction, import.nOrdinal);
                _writePtr(nSlot, nStub);
                if (!qEnvironmentVariableIsEmpty("XEMU_APILOG")) {
                    fprintf(stderr, "[IMPORT-stub] %s!%s (ord %lld) -> stub 0x%llx  (getExportRVA failed: forwarded?)\n",
                            import.sLibrary.toLatin1().constData(),
                            import.sFunction.isEmpty() ? "<none>" : import.sFunction.toLatin1().constData(),
                            (long long)import.nOrdinal, (unsigned long long)nStub);
                    fflush(stderr);
                }
            }
        }
    }
}

bool XEmuWindows::_mapRealSystemDlls()
{
    // ntdll first (no forwarders), then kernelbase (kernel32 forwards to it), then kernel32.
    QString sRootError;
    const QString sRoot = resolve32BitSystemDllDirectory(&sRootError);
    if (sRoot.isEmpty()) {
        emit errorMessage(tr("Real system DLL mode requires a usable 32-bit Windows DLL directory: %1").arg(sRootError));
        return false;
    }
    const QDir systemDirectory(sRoot);
    emit infoMessage(tr("Real system DLL root: %1").arg(systemDirectory.absolutePath()));

    // ntdll/kernelbase/kernel32 first, then EVERY DLL the main image imports. VMProtect's
    // import protection resolves the program's real imports at runtime by walking each library's
    // FULL export table; a synthetic image (which exports only the handful of functions in the
    // static import directory) misses e.g. oleaut32!SysReAllocStringLen and the loader errors
    // ("procedure entry point ... could not be located") then bails. Mapped as DATA; exports
    // intercepted so the subset CPU never runs them and their unresolved IATs never execute.
    QStringList listDlls = {QStringLiteral("ntdll.dll"), QStringLiteral("kernelbase.dll"), QStringLiteral("kernel32.dll"),
                            QStringLiteral("gdi32.dll"), QStringLiteral("user32.dll"), QStringLiteral("advapi32.dll")};
    const QSet<QString> setRequired = {QStringLiteral("ntdll.dll"), QStringLiteral("kernelbase.dll"), QStringLiteral("kernel32.dll")};
    if (!m_listLoaded.isEmpty()) {
        const QStringList listImports = m_listLoaded.at(0).pFormat->getImportLibraries();
        for (const QString &sImp : listImports) {
            const QString sLower = sImp.toLower();
            if (!listDlls.contains(sLower)) {
                listDlls.append(sLower);
            }
        }
    }

    for (const QString &sDll : listDlls) {
        if (m_mapNameToIndex.contains(sDll)) {
            continue;
        }
        const QString sPath = systemDirectory.absoluteFilePath(sDll);
        if (!QFileInfo::exists(sPath)) {
            if (setRequired.contains(sDll)) {
                emit errorMessage(tr("Required 32-bit system DLL not found: %1").arg(sPath));
                return false;
            }
            emit infoMessage(tr("Optional real system DLL not found: %1").arg(sPath));
            continue;
        }

        XEmuPE *pDll = new XEmuPE(this);
        connect(pDll, &XEmuFileFormat::infoMessage, this, &XEmuOperatingSystem::infoMessage);
        connect(pDll, &XEmuFileFormat::errorMessage, this, &XEmuOperatingSystem::errorMessage);

        XEmuFileFormat::MODULE module;
        if (!pDll->setFileName(sPath) || pDll->is64Bit() || (pDll->getArchType() != XARCH_X86_32) || !_mapModule(pDll, true, &module)) {
            delete pDll;
            emit errorMessage(tr("Failed to map real DLL: %1").arg(sPath));
            if (setRequired.contains(sDll)) {
                return false;
            }
            continue;
        }

        m_pWinApi->registerModule(sDll, module.nBaseAddress);
        m_pWinApi->addRealRange(module.nBaseAddress, module.nImageSize);
        _ldrAddModule(sDll, module.nBaseAddress, module.nImageSize, module.nEntryPointAddress);

        // Register every export VA so a call to any of them is intercepted before the subset
        // CPU fetches real DLL code; the ~15 loader/memory APIs get modelled, the rest a no-op.
        const QList<XEmuFileFormat::EXPORT_ENTRY> exports = pDll->getExportEntries();
        _collectForwardedExports(exports);
        int nReg = 0;
        for (const XEmuFileFormat::EXPORT_ENTRY &e : exports) {
            if (e.nRVA <= 0) {
                continue;
            }
            m_pWinApi->registerRealExport(module.nBaseAddress + (XADDR)e.nRVA, sDll, e.sName, e.nOrdinal);
            nReg++;
        }
        emit infoMessage(tr("Loader: mapped REAL %1 @ 0x%2 (%3 exports intercepted)").arg(sDll).arg(module.nBaseAddress, 0, 16).arg(nReg));
    }

    // In a real process EVERY statically-imported DLL is loaded before the entry point. A
    // packer that probes GetModuleHandleA("user32"/"advapi32"/...) and finds one ABSENT treats
    // it as an anomalous environment and bails (ExitProcess(0xDEADC0DE)). Pre-create synthetic
    // images for the imported DLLs we did not map real, so the query returns a valid base.
    if (!m_listLoaded.isEmpty()) {
        QSet<QString> seen;
        const QStringList listLibs = m_listLoaded.at(0).pFormat->getImportLibraries();
        for (const QString &sLib : listLibs) {
            const QString sLower = sLib.toLower();
            if (seen.contains(sLower) || m_mapNameToIndex.contains(sLower)) {
                continue;  // duplicate or already mapped real
            }
            seen.insert(sLower);
            XADDR nBase = _createSyntheticModule(sLower);
            if (nBase != 0) {
                m_pWinApi->registerModule(sLower, nBase);
            }
        }
    }

    for (const QString &sRequired : setRequired) {
        if (!m_mapNameToIndex.contains(sRequired)) {
            emit errorMessage(tr("Required 32-bit system DLL was not mapped: %1").arg(sRequired));
            return false;
        }
    }

    return true;
}

bool XEmuWindows::handleApiCall(XEmuRegisters *pRegisters, XADDR nPC)
{
    // A dispatched SEH handler has returned to the synthetic trap address. The return
    // belongs to the innermost (top) in-flight dispatch.
    if (!m_listSehStack.isEmpty() && (m_nSehReturnTrap != 0) && (nPC == m_nSehReturnTrap)) {
        return _sehHandlerReturned(pRegisters);
    }

    if (m_pWinApi == nullptr) {
        return false;
    }

    return m_pWinApi->dispatch(pRegisters);
}

bool XEmuWindows::handleException(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress)
{
    return _sehDispatch(pRegisters, nFaultingPC, nFaultAddress, 0xC0000005u, false);  // STATUS_ACCESS_VIOLATION (fault: PC at instruction)
}

bool XEmuWindows::handleInterrupt(int nVector, XEmuRegisters *pRegisters)
{
    // int3 raises STATUS_BREAKPOINT (a trap): Windows reports Eip = the instruction AFTER
    // int3, which is where the CPU already left the PC, so getPC() is correct.
    if (nVector == 3) {
        return _sehDispatch(pRegisters, m_pArch->getPC(pRegisters), 0, 0x80000003u, true);
    }

    // ud2 raises STATUS_ILLEGAL_INSTRUCTION (vector 6, #UD -- a FAULT): Windows reports Eip =
    // the ud2 itself, not the following instruction. The CPU advanced PC by the 2-byte
    // opcode, so report getPC()-2. bTrap stays true: the PC has still advanced, so the
    // exhausted-chain re-fault delivery (which relies on re-executing the instruction) can
    // never fire and must instead terminate.
    if (nVector == 6) {
        return _sehDispatch(pRegisters, m_pArch->getPC(pRegisters) - 2, 0, 0xC000001Du, true);
    }

    // Any other software-interrupt vector (int 0x68, int 0x2D, ...) is not a valid user-mode gate:
    // real Windows raises an exception and delivers it through the SEH chain. ExeStealth executes
    // `int 0x68` on purpose and catches it with its own handler as an obfuscated control transfer
    // (the handler rewrites CONTEXT.Eip to the next unpack stage). Deliver it through fs:[0] like
    // int3; bTrap=true so an exhausted chain terminates (identical to the prior unhandled-vector ->
    // STEP_HALT behaviour) instead of re-executing. The handler ignores the exception code, so
    // STATUS_ACCESS_VIOLATION is sufficient and matches real user-mode int-N GP-fault delivery.
    return _sehDispatch(pRegisters, m_pArch->getPC(pRegisters), 0, 0xC0000005u, true);
}

bool XEmuWindows::processExited() const
{
    // Either the guest called ExitProcess/TerminateProcess, or an unhandled trap (int3/ud2
    // whose SEH chain was exhausted) requested termination.
    return m_bSehTerminate || ((m_pWinApi != nullptr) && m_pWinApi->processExited());
}

quint64 XEmuWindows::apiStubBase() const
{
    return (m_pWinApi != nullptr) ? m_pWinApi->stubBase() : 0;
}

quint64 XEmuWindows::apiStubLimit() const
{
    return (m_pWinApi != nullptr) ? m_pWinApi->stubLimit() : 0;
}

bool XEmuWindows::resolveImportStub(quint64 nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const
{
    return (m_pWinApi != nullptr) && m_pWinApi->resolveImportStub((XADDR)nStub, pLibrary, pFunction, pOrdinal);
}

bool XEmuWindows::_sehDispatch(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress, quint32 nExceptionCode, bool bTrap)
{
    // Win32 SEH via the fs:[0] chain is x86-32 only (x86-64 uses table-based EH).
    if (m_bIs64 || (m_archType != XARCH_X86_32) || (m_nSehReturnTrap == 0)) {
        return false;
    }

    // A prior dispatch walked the whole chain for this exact fault without a handler
    // continuing execution and restored the faulting state to re-raise it: deliver now.
    if (m_bSehDeliver && (nFaultingPC == m_nSehDeliverPC)) {
        m_bSehDeliver = false;
        m_nSehDeliverPC = 0;
        return false;
    }

    // Reclaim frames orphaned by low-level UNWINDING handlers. Such a handler (PeX:
    // "mov esp,[fs:0]; pop fs:[0]; ...; ret") restores esp to at/above its establisher
    // frame and jumps to a packer continuation, never returning to the trap, so its
    // SEH_FRAME is never popped by _sehHandlerReturned. Its staged region sits BELOW the
    // original faulting esp (nStagedTop = the CONTEXT address), so once the guest stack has
    // unwound to at/above nStagedTop the dispatch is provably dead -- drop it. Genuine
    // in-flight nesting runs the handler on a DEEPER esp (below nStagedTop) and is kept.
    // Without this the leak saturates the depth cap and halts SEH-heavy stubs before OEP.
    const XADDR nEsp = (XADDR)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
    while (!m_listSehStack.isEmpty() && (nEsp >= m_listSehStack.last().nStagedTop)) {
        m_listSehStack.removeLast();
    }

    // Bound nesting depth (a handler that itself keeps faulting).
    if (m_listSehStack.size() >= 16) {
        return false;
    }

    // Head of the SEH chain = [fs:0] (NtTib.ExceptionList).
    bool bOk = false;
    XADDR nHead = m_pMemoryManager->readDword(pRegisters->nFSBase, &bOk);
    if (!bOk) {
        return false;
    }

    // A handler is in-flight when fs:[0] points at one of our nested dispatch records (its
    // Handler field is the return trap). A fault here is a NESTED exception: the
    // establisher's handler is already running, so the search must continue from the record
    // BELOW the establisher. Never treat the nested record as a real handler -- resolving
    // its handler to the trap and "invoking" it makes _sehHandlerReturned re-read a stale
    // EAX as the disposition and, on ContinueExecution, reload the faulting CONTEXT with
    // fs:[0] unchanged -> an infinite fault loop the depth cap never bounds.
    int nSkip = 0;
    while (bOk && m_pMemoryManager->isCommitted(nHead, 8) &&
           (m_pMemoryManager->readDword(nHead + 0x04) == m_nSehReturnTrap) && (nSkip++ < 32)) {
        const XADDR nEstablisher = m_pMemoryManager->readDword(nHead + 0x00, &bOk);  // nested.Next = establisher
        if (!bOk || !m_pMemoryManager->isCommitted(nEstablisher, 8)) {
            return false;
        }
        nHead = m_pMemoryManager->readDword(nEstablisher + 0x00, &bOk);  // establisher.Next (skip the in-flight handler)
    }

    if (!bOk || (nHead == 0) || (nHead == 0xFFFFFFFFu) || !m_pMemoryManager->isCommitted(nHead, 8)) {
        return false;  // no registered handler -> genuine fault
    }

    SEH_FRAME frame;
    frame.nRecord = nHead;
    frame.nFaultingPC = nFaultingPC;
    frame.bTrap = bTrap;
    frame.nStagedTop = 0;  // set by _sehBuildFrame
    frame.faultRegs = *pRegisters;  // snapshot for unhandled delivery (exact re-fault)
    if (!_sehBuildFrame(pRegisters, nFaultingPC, nFaultAddress, nExceptionCode, &frame)) {
        return false;  // could not stage the frame (e.g. stack not committed) -> genuine fault
    }

    m_listSehStack.append(frame);
    _sehCallHandler(pRegisters);
    return true;
}

bool XEmuWindows::_sehBuildFrame(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress, quint32 nExceptionCode, SEH_FRAME *pFrame)
{
    // Reserve the CONTEXT, the EXCEPTION_RECORD and the call frame just below the
    // faulting esp. Validate the whole span is committed first: if the fault happened
    // near the stack limit these writes would silently drop and the handler would run
    // on garbage.
    const XADDR nEsp = (XADDR)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
    const XADDR nContext = (nEsp - 0x2CC) & ~(XADDR)0xF;  // sizeof(CONTEXT) for i386
    const XADDR nExc = (nContext - 0x50) & ~(XADDR)0xF;   // sizeof(EXCEPTION_RECORD)
    const XADDR nLow = nExc - 0x40;                       // room for the 5-dword call frame + slack

    if ((nLow >= nEsp) || !m_pMemoryManager->isCommitted(nLow, nEsp - nLow)) {
        return false;
    }

    // esp is only republished at the end, so _sehWriteContext still sees the original esp.
    _sehWriteContext(nContext, pRegisters, nFaultingPC);

    const bool bAccessViolation = (nExceptionCode == 0xC0000005u);
    m_pMemoryManager->writeDword(nExc + 0x00, nExceptionCode);         // ExceptionCode
    m_pMemoryManager->writeDword(nExc + 0x04, 0);                      // ExceptionFlags = continuable
    m_pMemoryManager->writeDword(nExc + 0x08, 0);                      // ExceptionRecord (nested) = none
    m_pMemoryManager->writeDword(nExc + 0x0C, (quint32)nFaultingPC);   // ExceptionAddress
    m_pMemoryManager->writeDword(nExc + 0x10, bAccessViolation ? 2 : 0);  // NumberParameters
    m_pMemoryManager->writeDword(nExc + 0x14, 0);                      // [0] access type (0=read; direction not tracked)
    m_pMemoryManager->writeDword(nExc + 0x18, (quint32)nFaultAddress);  // [1] faulting VA

    // Real Windows dispatches through RtlpExecuteHandlerForException, which installs its
    // own nested EXCEPTION_REGISTRATION_RECORD (Next -> the establisher chain head) and
    // repoints fs:[0] at it *before* calling the handler. Low-level handlers that unwind
    // by reading [fs:0] (e.g. PeX's `mov eax,fs:[0]; mov esp,[eax]; pop fs:[0]; ...`)
    // depend on this: [fs:0] must be the nested record whose Next is the establisher
    // frame, not the establisher frame itself (whose first dword is its own -1 sentinel).
    // Stage a minimal nested record just below the EXCEPTION_RECORD and point fs:[0] at it.
    const XADDR nNested = nExc - 8;  // 8-byte {Next, Handler}
    bool bHeadOk = false;
    const XADDR nOldHead = m_pMemoryManager->readDword(pRegisters->nFSBase, &bHeadOk);
    m_pMemoryManager->writeDword(nNested + 0x00, (quint32)nOldHead);          // Next = establisher chain head
    m_pMemoryManager->writeDword(nNested + 0x04, (quint32)m_nSehReturnTrap);  // Handler = trap placeholder
    m_pMemoryManager->writeDword(pRegisters->nFSBase, (quint32)nNested);      // fs:[0] = &nested
    pFrame->nSavedSehHead = bHeadOk ? nOldHead : 0;

    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, nNested);

    pFrame->nContextPtr = nContext;
    pFrame->nExcRecordPtr = nExc;
    pFrame->nStagedTop = nContext;  // highest staged address; _sehDispatch reclaims frames unwound past this
    return true;
}

void XEmuWindows::_sehWriteContext(XADDR nContext, XEmuRegisters *pRegisters, XADDR nEip)
{
    m_pMemoryManager->write(nContext, QByteArray(0x2CC, (char)0));

    m_pMemoryManager->writeDword(nContext + 0x00, 0x00010007u);  // ContextFlags = CONTEXT_FULL (i386|CONTROL|INTEGER|SEGMENTS)
    m_pMemoryManager->writeDword(nContext + 0x8C, (quint32)pRegisters->nGS);
    m_pMemoryManager->writeDword(nContext + 0x90, (quint32)pRegisters->nFS);
    m_pMemoryManager->writeDword(nContext + 0x94, (quint32)pRegisters->nES);
    m_pMemoryManager->writeDword(nContext + 0x98, (quint32)pRegisters->nDS);
    m_pMemoryManager->writeDword(nContext + 0x9C, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RDI, 4));
    m_pMemoryManager->writeDword(nContext + 0xA0, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 4));
    m_pMemoryManager->writeDword(nContext + 0xA4, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 4));
    m_pMemoryManager->writeDword(nContext + 0xA8, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 4));
    m_pMemoryManager->writeDword(nContext + 0xAC, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RCX, 4));
    m_pMemoryManager->writeDword(nContext + 0xB0, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 4));
    m_pMemoryManager->writeDword(nContext + 0xB4, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RBP, 4));
    m_pMemoryManager->writeDword(nContext + 0xB8, (quint32)nEip);                              // Eip
    m_pMemoryManager->writeDword(nContext + 0xBC, (quint32)pRegisters->nCS);
    m_pMemoryManager->writeDword(nContext + 0xC0, (quint32)pRegisters->nRFLAGS);               // EFlags
    m_pMemoryManager->writeDword(nContext + 0xC4, (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4));  // Esp (at fault)
    m_pMemoryManager->writeDword(nContext + 0xC8, (quint32)pRegisters->nSS);
}

void XEmuWindows::_sehLoadContext(XADDR nContext, XEmuRegisters *pRegisters)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RDI, 4, m_pMemoryManager->readDword(nContext + 0x9C));
    pRegisters->setGPR(XEmuRegisters::GPR_RSI, 4, m_pMemoryManager->readDword(nContext + 0xA0));
    pRegisters->setGPR(XEmuRegisters::GPR_RBX, 4, m_pMemoryManager->readDword(nContext + 0xA4));
    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 4, m_pMemoryManager->readDword(nContext + 0xA8));
    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 4, m_pMemoryManager->readDword(nContext + 0xAC));
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 4, m_pMemoryManager->readDword(nContext + 0xB0));
    pRegisters->setGPR(XEmuRegisters::GPR_RBP, 4, m_pMemoryManager->readDword(nContext + 0xB4));
    pRegisters->nRFLAGS = m_pMemoryManager->readDword(nContext + 0xC0);
    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, m_pMemoryManager->readDword(nContext + 0xC4));
    m_pArch->setPC(pRegisters, m_pMemoryManager->readDword(nContext + 0xB8));  // Eip (handler may have changed it)
}

void XEmuWindows::_sehCallHandler(XEmuRegisters *pRegisters)
{
    const SEH_FRAME &frame = m_listSehStack.last();
    const XADDR nHandler = m_pMemoryManager->readDword(frame.nRecord + 0x04);  // EXCEPTION_REGISTRATION_RECORD.Handler

    // _except_handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext),
    // cdecl: push right-to-left, then the trap return address.
    XADDR nEsp = (XADDR)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
    const quint32 args[5] = {
        0,                                 // DispatcherContext
        (quint32)frame.nContextPtr,        // ContextRecord
        (quint32)frame.nRecord,            // EstablisherFrame
        (quint32)frame.nExcRecordPtr,      // ExceptionRecord
        (quint32)m_nSehReturnTrap,         // return address
    };
    for (int i = 0; i < 5; i++) {
        nEsp -= 4;
        m_pMemoryManager->writeDword(nEsp, args[i]);
    }
    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, nEsp);
    m_pArch->setPC(pRegisters, nHandler);

    emit infoMessage(QStringLiteral("SEH: fault 0x%1 -> handler 0x%2 (frame 0x%3, depth %4)")
                         .arg(frame.nFaultingPC, 0, 16)
                         .arg(nHandler, 0, 16)
                         .arg(frame.nRecord, 0, 16)
                         .arg(m_listSehStack.size()));
}

bool XEmuWindows::_sehHandlerReturned(XEmuRegisters *pRegisters)
{
    const quint32 nDisposition = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 4);
    SEH_FRAME frame = m_listSehStack.last();  // copy: we pop before resuming

    if (nDisposition == 0) {  // ExceptionContinueExecution
        // Unwind the nested dispatch record: restore fs:[0] to the establisher chain head.
        if (frame.nSavedSehHead != 0) {
            m_pMemoryManager->writeDword(pRegisters->nFSBase, (quint32)frame.nSavedSehHead);
        }
        _sehLoadContext(frame.nContextPtr, pRegisters);  // handler may have modified the CONTEXT
        m_listSehStack.removeLast();
        emit infoMessage(QStringLiteral("SEH: continue execution at 0x%1").arg((quint32)pRegisters->nRIP, 0, 16));
        return true;
    }

    // ExceptionContinueSearch (1) / others: try the previous record in the chain.
    bool bOk = false;
    const XADDR nNext = m_pMemoryManager->readDword(frame.nRecord + 0x00, &bOk);  // Next
    if (bOk && (nNext != 0) && (nNext != 0xFFFFFFFFu) && m_pMemoryManager->isCommitted(nNext, 8)) {
        m_listSehStack.last().nRecord = nNext;
        _sehCallHandler(pRegisters);
        return true;
    }

    // Chain exhausted: no handler accepted the exception.
    if (frame.nSavedSehHead != 0) {
        m_pMemoryManager->writeDword(pRegisters->nFSBase, (quint32)frame.nSavedSehHead);
    }
    *pRegisters = frame.faultRegs;
    m_listSehStack.removeLast();

    if (frame.bTrap) {
        // int3/ud2: the CPU already advanced past the instruction, so re-executing the
        // restored state would NOT re-fault -- the re-fault delivery mechanism (which relies
        // on re-hitting the faulting instruction) can never fire. An unhandled trap
        // terminates the process on real Windows; request a clean halt instead of arming a
        // deliver-PC that would never be consumed and could later collide with a genuine
        // fault at the post-trap address.
        m_bSehTerminate = true;
        emit infoMessage(QStringLiteral("SEH: chain exhausted for unhandled trap at 0x%1; terminating").arg(frame.nFaultingPC, 0, 16));
        return true;
    }

    // Fault (access violation): restore the exact faulting register state and let it
    // re-fault so the emulator delivers a genuine fault. m_bSehDeliver short-circuits the
    // re-dispatch of that one re-fault.
    m_bSehDeliver = true;
    m_nSehDeliverPC = frame.nFaultingPC;
    emit infoMessage(QStringLiteral("SEH: chain exhausted for fault 0x%1; delivering").arg(frame.nFaultingPC, 0, 16));
    return true;
}

XADDR XEmuWindows::_setupStack(quint64 nStackSize, quint64 *pnStackBase, quint64 *pnStackLimit)
{
    // Diagnostic override: XEMU_STACKTOP=<hex top> places the stack so its top matches a
    // chosen VA (e.g. the real Windows stack base), to test whether an emulation divergence
    // is driven by the stack-base offset relative to the real process.
    XADDR nStack = 0;
    QByteArray envTop = qgetenv("XEMU_STACKTOP");
    if (!envTop.isEmpty()) {
        quint64 nTop = QString::fromLocal8Bit(envTop).trimmed().toULongLong(nullptr, 16);
        if (nTop > nStackSize) {
            XADDR nWant = (XADDR)XEmuMemoryManager::alignDown(nTop - nStackSize, 0x10000);
            nStack = m_pMemoryManager->allocate(nWant, nStackSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("stack"));
        }
    }
    if (nStack == 0) {
        nStack = m_pMemoryManager->allocate(0, nStackSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("stack"));
    }

    if (nStack == 0) {
        return 0;
    }

    *pnStackLimit = nStack;
    *pnStackBase = nStack + nStackSize;

    return nStack + nStackSize;
}

XADDR XEmuWindows::_poolAlloc(quint64 nSize)
{
    nSize = XEmuMemoryManager::alignUp(nSize, 8);

    if ((m_nPoolCursor + nSize) > (m_nPoolAddress + m_nPoolSize)) {
        return 0;
    }

    XADDR nResult = m_nPoolCursor;
    m_nPoolCursor += nSize;

    return nResult;
}

XADDR XEmuWindows::_writeUnicode(const QString &sText, quint16 *pnByteLength)
{
    quint16 nByteLength = (quint16)(sText.size() * 2);
    XADDR nAddress = _poolAlloc(nByteLength + 2);

    if (nAddress != 0) {
        for (int i = 0; i < sText.size(); i++) {
            m_pMemoryManager->writeWord(nAddress + i * 2, sText.at(i).unicode());
        }

        m_pMemoryManager->writeWord(nAddress + nByteLength, 0);
    }

    if (pnByteLength) {
        *pnByteLength = nByteLength;
    }

    return nAddress;
}

void XEmuWindows::_linkList(XADDR nHeadAddress, int nLinkOffset, const QList<XADDR> &listEntryBases)
{
    int nPtr = _ptrSize();

    if (listEntryBases.isEmpty()) {
        _writePtr(nHeadAddress, nHeadAddress);
        _writePtr(nHeadAddress + nPtr, nHeadAddress);
        return;
    }

    XADDR nPrev = nHeadAddress;

    for (int i = 0; i < listEntryBases.size(); i++) {
        XADDR nLink = listEntryBases.at(i) + nLinkOffset;
        _writePtr(nPrev, nLink);              // prev.Flink = &cur
        _writePtr(nLink + nPtr, nPrev);       // cur.Blink = prev
        nPrev = nLink;
    }

    _writePtr(nPrev, nHeadAddress);           // last.Flink = &head
    _writePtr(nHeadAddress + nPtr, nPrev);    // head.Blink = &last
}

bool XEmuWindows::_isAsdPackCandidate() const
{
    if (m_listLoaded.isEmpty() || !m_listLoaded.at(0).pFormat) {
        return false;
    }

    const QList<XEmuFileFormat::IMPORT> listImports = m_listLoaded.at(0).pFormat->getImports();
    if (listImports.isEmpty()) {
        return false;
    }

    QSet<QString> setLibraries;
    bool bHasUser32 = false;
    bool bHasUser32Marker = false;

    for (int i = 0; i < listImports.size(); i++) {
        const XEmuFileFormat::IMPORT &imp = listImports.at(i);
        const QString sLib = imp.sLibrary.toLower();
        const QString sFunc = imp.sFunction.toLower();

        setLibraries.insert(sLib);
        if (sLib == QStringLiteral("user32.dll")) {
            bHasUser32 = true;
            if ((sFunc == QStringLiteral("messageboxa")) || (sFunc == QStringLiteral("messageboxw")) || (sFunc == QStringLiteral("messagebeep"))) {
                bHasUser32Marker = true;
            }
        }
    }

    if (!bHasUser32) {
        return false;
    }

    // ASDPack host EXEs are known to use user32 at startup; accept known near-matches and
    // tolerate kernel32/ntdll imports so ASDPack-like binaries are not filtered out too early.
    if ((setLibraries.size() > 1) && !bHasUser32Marker) {
        return false;
    }

    return true;
}

QList<XEmuWindows::SYN_EXPORT> XEmuWindows::_collectImportsFor(const QString &sLibraryLower)
{
    QList<SYN_EXPORT> result;
    if (m_pWinApi == nullptr) {
        return result;
    }

    QSet<QString> seenNames;
    QSet<qint64> seenOrdinals;
    for (int i = 0; i < m_listLoaded.size(); i++) {
        XEmuFileFormat *pFormat = m_listLoaded.at(i).pFormat;
        if (pFormat == nullptr) {
            continue;
        }
        const QList<XEmuFileFormat::IMPORT> imports = pFormat->getImports();
        for (int j = 0; j < imports.size(); j++) {
            const XEmuFileFormat::IMPORT &imp = imports.at(j);
            if (imp.sLibrary.toLower() != sLibraryLower) {
                continue;
            }
            SYN_EXPORT e;
            // Route by-ordinal first: the PE loader parser stringifies a by-ordinal import's
            // ordinal into sFunction (a decimal like "123"), so a non-empty sFunction does
            // NOT mean by-name. Distinguish on nOrdinal (>=0 only for by-ordinal imports).
            if (imp.nOrdinal >= 1) {
                if (seenOrdinals.contains(imp.nOrdinal)) {
                    continue;
                }
                seenOrdinals.insert(imp.nOrdinal);
                e.sName = QString();          // export at the ordinal slot, not the decimal name
                e.nOrdinal = imp.nOrdinal;
            } else if (!imp.sFunction.isEmpty()) {
                if (seenNames.contains(imp.sFunction)) {
                    continue;
                }
                seenNames.insert(imp.sFunction);
                e.sName = imp.sFunction;
                e.nOrdinal = -1;
            } else {
                continue;  // ordinal 0 / nameless: degenerate, unresolvable -> skip
            }
            // Same cached trampoline _patchImports resolves this import to (stubFor keys on
            // the lower-cased "lib!func"), so both resolution paths agree.
            e.nStub = m_pWinApi->stubFor(sLibraryLower, imp.sFunction, imp.nOrdinal);
            result.append(e);
        }
    }

    // ASDPack/Imploder modes intentionally pre-seed extra, hashed API names in synthetic export
    // directories. The arena is generally immutable across the golden families; these paths are
    // narrow and gate-specific to avoid destabilizing unrelated packs.
    auto seedNamedExport = [this, &seenNames, &result](const QString &sLib, const QString &sName) {
        if (seenNames.contains(sName)) {
            return;
        }
        seenNames.insert(sName);
        SYN_EXPORT e;
        e.sName = sName;
        e.nOrdinal = -1;
        e.nStub = m_pWinApi->stubFor(sLib, sName, -1);
        result.append(e);
    };

    // Merge symbols promised by forwarders in mapped real DLLs.  Allocate
    // trampolines only when the target contract is actually loaded, preserving
    // the stable API-arena layout for unrelated runs.
    const QList<FORWARDED_EXPORT> forwarded =
        m_mapForwardedExports.value(sLibraryLower);
    for (int i = 0; i < forwarded.size(); ++i) {
        const FORWARDED_EXPORT &forward = forwarded.at(i);
        SYN_EXPORT e;
        if (!forward.sName.isEmpty()) {
            if (seenNames.contains(forward.sName)) {
                continue;
            }
            seenNames.insert(forward.sName);
            e.sName = forward.sName;
            e.nOrdinal = -1;
            e.nStub = m_pWinApi->stubFor(
                sLibraryLower, forward.sName, -1);
        } else if (forward.nOrdinal >= 1) {
            if (seenOrdinals.contains(forward.nOrdinal)) {
                continue;
            }
            seenOrdinals.insert(forward.nOrdinal);
            e.sName = QString();
            e.nOrdinal = forward.nOrdinal;
            e.nStub = m_pWinApi->stubFor(
                sLibraryLower, QString(), forward.nOrdinal);
        } else {
            continue;
        }
        result.append(e);
    }

    if (m_bAsdPackMode && (sLibraryLower == QStringLiteral("kernel32.dll"))) {
        static const char *const kAsdPack[] = {
            "CloseHandle", "GetModuleHandleA", "GetProcAddress", "LoadLibraryExA",
            "VirtualAlloc", "VirtualFreeEx", "VirtualProtectEx", nullptr};
        for (int i = 0; kAsdPack[i] != nullptr; i++) {
            seedNamedExport(QStringLiteral("kernel32.dll"), QString::fromLatin1(kAsdPack[i]));
        }
    }

    if (m_bImploderMode &&
        ((sLibraryLower == QStringLiteral("kernel32.dll")) || (sLibraryLower == QStringLiteral("ntdll.dll")) ||
         (sLibraryLower == QStringLiteral("advapi32.dll")) || (sLibraryLower == QStringLiteral("user32.dll")))) {
        static const char *const kImploderKernel32[] = {
            "LoadLibraryA", "LoadLibraryExA", "GetModuleHandleA", "GetProcAddress", "FreeLibrary", "ExitProcess",
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "VirtualAlloc", "VirtualFree", "VirtualProtect",
            "VirtualFreeEx", "VirtualProtectEx", "GetSystemDirectoryA", "GetSystemDirectoryW", "GetCurrentDirectoryA", "GetCurrentDirectoryW",
            "GetWindowsDirectoryA", "GetWindowsDirectoryW", "CreateDirectoryA", "CreateDirectoryW", "OpenProcess", "GetModuleFileNameA",
            "GetModuleFileNameW", "GetCurrentProcess", "GetCurrentThread", "GetCurrentProcessId", "GetCurrentThreadId", "GetSystemTimeAsFileTime",
            "GetTickCount", "GetSystemInfo", "GetVersion", "GetVersionExA", "GetVersionExW", "MessageBoxA", "Sleep", "SleepEx",
            "WaitForSingleObject", "LoadResource", "FindResourceA", "FindResourceW", "SizeofResource", "LoadStringA", "GetLocaleInfoA",
            "GetLocaleInfoW", "HeapAlloc", "HeapFree", "CreateProcessA", "CreateProcessW", nullptr};
        static const char *const kImploderNtdll[] = {
            "NtOpenFile", "NtCreateFile", "NtReadFile", "NtMapViewOfSection", "NtUnmapViewOfSection", "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory", "NtFreeVirtualMemory", "NtQueryInformationFile", "NtSetInformationFile", "NtClose",
            "LdrGetProcedureAddress", "LdrLoadDll", "LdrGetDllHandle", "RtlGetVersion", nullptr};
        static const char *const kImploderAdvapi32[] = {"RegOpenKeyExA", "RegQueryValueExA", "RegCloseKey", nullptr};
        static const char *const kImploderUser32[] = {"MessageBoxA", "MessageBoxW", "FindWindowA", "FindWindowW", "GetWindowThreadProcessId", nullptr};

        const char *const *ppList = nullptr;
        if (sLibraryLower == QStringLiteral("kernel32.dll")) ppList = kImploderKernel32;
        else if (sLibraryLower == QStringLiteral("ntdll.dll")) ppList = kImploderNtdll;
        else if (sLibraryLower == QStringLiteral("advapi32.dll")) ppList = kImploderAdvapi32;
        else if (sLibraryLower == QStringLiteral("user32.dll")) ppList = kImploderUser32;

        if (ppList) {
            for (int i = 0; ppList[i] != nullptr; i++) {
                seedNamedExport(sLibraryLower, QString::fromLatin1(ppList[i]));
            }
        }

        // Cover any additional hash-only imports in the wild: seed real kernel32 exports
        // once for this run so one unidentified hash constant does not abort the walk.
        if (sLibraryLower == QStringLiteral("kernel32.dll")) {
            QString sRootError;
            const QString sSystemDllRoot = resolve32BitSystemDllDirectory(&sRootError);
            const QString sSysKernel32 = sSystemDllRoot.isEmpty() ? QString() : QDir(sSystemDllRoot).absoluteFilePath(QStringLiteral("kernel32.dll"));
            if (!sSysKernel32.isEmpty()) {
                XEmuPE *pSys = new XEmuPE(this);
                connect(pSys, &XEmuFileFormat::infoMessage, this, &XEmuOperatingSystem::infoMessage);
                connect(pSys, &XEmuFileFormat::errorMessage, this, &XEmuOperatingSystem::errorMessage);
                if (pSys->setFileName(sSysKernel32)) {
                    const QList<XEmuFileFormat::EXPORT_ENTRY> listKernelExports = pSys->getExportEntries();
                    for (const XEmuFileFormat::EXPORT_ENTRY &e : listKernelExports) {
                        if (!e.sName.isEmpty()) {
                            seedNamedExport(QStringLiteral("kernel32.dll"), e.sName);
                        }
                    }
                }
                delete pSys;
            }
        }
    }

    return result;
}

void XEmuWindows::_collectForwardedExports(
    const QList<XEmuFileFormat::EXPORT_ENTRY> &exports)
{
    // Keep this derived catalog bounded even for hostile export directories.
    const int N_MAX_TARGET_MODULES = 512;
    const int N_MAX_EXPORTS_PER_TARGET = 2048;
    const int N_MAX_TOTAL_EXPORTS = 32768;

    for (int i = 0;
         (i < exports.size())
         && (m_nForwardedExportCount < N_MAX_TOTAL_EXPORTS);
         ++i) {
        const QString forwarder = exports.at(i).sForwarder;
        const int nDot = forwarder.indexOf(QLatin1Char('.'));
        if ((nDot <= 0) || (nDot + 1 >= forwarder.size())) {
            continue;
        }

        QString sTargetModule = forwarder.left(nDot).toLower();
        if (!sTargetModule.contains(QLatin1Char('.'))) {
            sTargetModule += QStringLiteral(".dll");
        }
        if (!m_mapForwardedExports.contains(sTargetModule)
            && (m_mapForwardedExports.size() >= N_MAX_TARGET_MODULES)) {
            continue;
        }

        FORWARDED_EXPORT target;
        target.nOrdinal = -1;
        const QString sTargetSymbol = forwarder.mid(nDot + 1);
        if (sTargetSymbol.startsWith(QLatin1Char('#'))) {
            bool bOk = false;
            const int nOrdinal = sTargetSymbol.mid(1).toInt(&bOk);
            if (!bOk || (nOrdinal < 1) || (nOrdinal > 0xFFFF)) {
                continue;
            }
            target.nOrdinal = nOrdinal;
        } else {
            target.sName = sTargetSymbol;
        }

        QList<FORWARDED_EXPORT> &listTarget =
            m_mapForwardedExports[sTargetModule];
        if (listTarget.size() >= N_MAX_EXPORTS_PER_TARGET) {
            continue;
        }

        bool bDuplicate = false;
        for (int j = 0; j < listTarget.size(); ++j) {
            const FORWARDED_EXPORT &existing = listTarget.at(j);
            if ((!target.sName.isEmpty()
                 && (existing.sName == target.sName))
                || (target.sName.isEmpty()
                    && existing.sName.isEmpty()
                    && (existing.nOrdinal == target.nOrdinal))) {
                bDuplicate = true;
                break;
            }
        }
        if (!bDuplicate) {
            listTarget.append(target);
            ++m_nForwardedExportCount;
        }
    }
}

XADDR XEmuWindows::_createSyntheticModule(const QString &sNameLower)
{
    QList<SYN_EXPORT> exports = _collectImportsFor(sNameLower);

    // Hash-based import resolvers (yzpack 1.x resolves kernel32 APIs by ror13 hash over the export
    // table) need the common loader APIs NAMED in the synth kernel32 export directory -- a packer
    // that imports kernel32 only by ordinal leaves the table nameless and the hash walk derails.
    // CRITICAL: name ONLY the 15 APIs already pre-seeded in XEmuWinApi::init (stubFor there reserved
    // their arena slots up front), so stubFor() here DEDUPS to the existing address and never calls
    // _allocStub -- the arena cursor does not move, every other family's on-demand GetProcAddress
    // stub addresses stay byte-identical, and dumped IATs are unchanged. Do NOT do this for ntdll
    // (no pre-seeded stubs -> would allocate -> shift the whole arena -> regress every family).
    if (sNameLower == QStringLiteral("kernel32.dll")) {
        static const char *const kPreseeded[] = {
            "VirtualAlloc", "VirtualProtect", "VirtualFree", "LoadLibraryA", "GetProcAddress",
            "GetModuleHandleA", "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
            "HeapAlloc", "HeapFree", "ExitProcess", "CreateFileA", "CreateFileW", nullptr };
        QSet<QString> have;
        for (const SYN_EXPORT &e : exports) {
            if (!e.sName.isEmpty()) have.insert(e.sName);
        }
        for (int i = 0; kPreseeded[i] != nullptr; i++) {
            const QString sApi = QString::fromLatin1(kPreseeded[i]);
            if (have.contains(sApi)) continue;
            SYN_EXPORT e;
            e.sName = sApi;
            e.nOrdinal = -1;
            e.nStub = m_pWinApi->stubFor(QStringLiteral("kernel32.dll"), sApi, -1);  // dedups: no _allocStub
            exports.append(e);
        }
        if (m_bAsdPackMode) {
            const char *const kAsdExtra[] = {"CloseHandle", "LoadLibraryExA", "VirtualFreeEx", "VirtualProtectEx", nullptr};
            for (int i = 0; kAsdExtra[i] != nullptr; i++) {
                const QString sApi = QString::fromLatin1(kAsdExtra[i]);
                if (have.contains(sApi)) continue;
                have.insert(sApi);
                SYN_EXPORT e;
                e.sName = sApi;
                e.nOrdinal = -1;
                e.nStub = m_pWinApi->stubFor(QStringLiteral("kernel32.dll"), sApi, -1);  // ASDPack mode: gated allocator-safe fill
                exports.append(e);
            }
        }
    }

    // Size the image to hold the headers + a real export directory (dir + the three arrays
    // + name strings). Named exports occupy function slots 0..n-1; ordinal-only imports
    // occupy slot (ordinal - 1), so the function table must span whichever is larger.
    int nNamed = 0;
    qint64 nMaxOrdinal = 0;
    quint64 nStrBytes = 0;
    for (int i = 0; i < exports.size(); i++) {
        if (!exports.at(i).sName.isEmpty()) {
            nNamed++;
            nStrBytes += (quint64)exports.at(i).sName.toLatin1().size() + 1;
        } else {
            nMaxOrdinal = qMax(nMaxOrdinal, exports.at(i).nOrdinal);
        }
    }
    // Named exports occupy the function slots ABOVE the by-ordinal region [0, nMaxOrdinal)
    // so the two never collide, so the table spans nMaxOrdinal + nNamed slots. (Must match
    // the nFuncCount computed in _writeSyntheticImage.)
    const int nFuncCount = (int)(nMaxOrdinal + (qint64)nNamed);
    quint64 nNeeded = 0x200 + 0x28;                        // headers + export directory
    nNeeded += (quint64)nFuncCount * 4;                    // AddressOfFunctions
    nNeeded += (quint64)nNamed * 4;                        // AddressOfNames
    nNeeded += (quint64)nNamed * 2;                        // AddressOfNameOrdinals
    nNeeded += nStrBytes + (quint64)sNameLower.toLatin1().size() + 1 + 16;  // strings + slack
    quint64 nSize = (nNeeded + 0xFFF) & ~(quint64)0xFFF;
    if (nSize < 0x1000) {
        nSize = 0x1000;
    }

    XADDR nBase = m_pMemoryManager->allocate(0, nSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("module:%1").arg(sNameLower));
    if (nBase == 0) {
        return 0;
    }

    _writeSyntheticImage(nBase, nSize, sNameLower, exports);
    _ldrAddModule(sNameLower, nBase, nSize, 0);

    emit infoMessage(QStringLiteral("Loader: synthesised module \"%1\" @ 0x%2 (%3 exports)").arg(sNameLower).arg(nBase, 0, 16).arg(exports.size()));
    return nBase;
}

void XEmuWindows::_writeSyntheticImage(XADDR nBase, quint64 nSize, const QString &sNameLower, const QList<SYN_EXPORT> &exports)
{
    m_pMemoryManager->write(nBase, QByteArray((int)nSize, (char)0));

    const int nNtOffset = 0x40;

    // DOS header.
    m_pMemoryManager->writeWord(nBase + 0x00, 0x5A4D);          // 'MZ'
    m_pMemoryManager->writeDword(nBase + 0x3C, nNtOffset);       // e_lfanew

    // NT headers.
    const XADDR nNt = nBase + nNtOffset;
    m_pMemoryManager->writeDword(nNt + 0x00, 0x00004550);        // 'PE\0\0'

    // IMAGE_FILE_HEADER.
    const XADDR nFh = nNt + 0x04;
    m_pMemoryManager->writeWord(nFh + 0x00, m_bIs64 ? 0x8664 : 0x014C);  // Machine
    m_pMemoryManager->writeWord(nFh + 0x02, 0);                          // NumberOfSections
    m_pMemoryManager->writeWord(nFh + 0x10, m_bIs64 ? 0x00F0 : 0x00E0);  // SizeOfOptionalHeader
    m_pMemoryManager->writeWord(nFh + 0x12, 0x2102);                     // Characteristics (DLL | EXECUTABLE_IMAGE)

    // IMAGE_OPTIONAL_HEADER (PE32 / PE32+).
    const XADDR nOh = nFh + 0x14;
    m_pMemoryManager->writeWord(nOh + 0x00, m_bIs64 ? 0x020B : 0x010B);  // Magic

    // --- Lay out the export directory ---
    // By-ordinal imports occupy their fixed function slot (ordinal - Base) in the region
    // [0, nMaxOrdinal). Named exports are placed ABOVE that region (slot nMaxOrdinal + i) so
    // the two never collide. Names are sorted case-sensitively so a binary-search export
    // walk (GetProcAddress-style) finds them; a linear walk works too.
    const quint32 nBaseOrdinal = 1;
    QList<SYN_EXPORT> named;
    qint64 nMaxOrdinal = 0;
    for (int i = 0; i < exports.size(); i++) {
        if (!exports.at(i).sName.isEmpty()) {
            named.append(exports.at(i));
        } else {
            nMaxOrdinal = qMax(nMaxOrdinal, exports.at(i).nOrdinal);
        }
    }
    std::sort(named.begin(), named.end(), [](const SYN_EXPORT &a, const SYN_EXPORT &b) { return a.sName < b.sName; });
    const int nNamed = named.size();
    const int nNamedSlotBase = (int)nMaxOrdinal;         // named exports start after the ordinal region
    const int nFuncCount = nNamedSlotBase + nNamed;      // must match _createSyntheticModule

    const quint32 nExportRva = 0x200;
    quint32 nCur = nExportRva + 0x28;                                   // after the export directory
    const quint32 nFuncsRva = nCur; nCur += (quint32)nFuncCount * 4;    // AddressOfFunctions
    const quint32 nNamesRva = nCur; nCur += (quint32)nNamed * 4;        // AddressOfNames
    const quint32 nOrdsRva  = nCur; nCur += (quint32)nNamed * 2;        // AddressOfNameOrdinals
    nCur = (nCur + 3u) & ~3u;

    QVector<quint32> nameStrRva(nNamed);
    for (int i = 0; i < nNamed; i++) {
        const QByteArray b = named.at(i).sName.toLatin1();
        nameStrRva[i] = nCur;
        m_pMemoryManager->write(nBase + nCur, b);
        m_pMemoryManager->writeByte(nBase + nCur + b.size(), 0);
        nCur += (quint32)b.size() + 1;
    }
    const quint32 nModNameRva = nCur;
    {
        const QByteArray b = sNameLower.toLatin1();
        m_pMemoryManager->write(nBase + nCur, b);
        m_pMemoryManager->writeByte(nBase + nCur + b.size(), 0);
        nCur += (quint32)b.size() + 1;
    }
    const quint32 nExportDirSize = nCur - nExportRva;  // covers the whole export region

    // Optional-header sizes + DataDirectory[0] (Export).
    if (m_bIs64) {
        m_pMemoryManager->writeQword(nOh + 0x18, nBase);
        m_pMemoryManager->writeDword(nOh + 0x38, (quint32)nSize);
        m_pMemoryManager->writeDword(nOh + 0x3C, 0x200);
        m_pMemoryManager->writeDword(nOh + 0x6C, 16);
        m_pMemoryManager->writeDword(nOh + 0x70, nExportRva);
        m_pMemoryManager->writeDword(nOh + 0x74, nExportDirSize);
    } else {
        m_pMemoryManager->writeDword(nOh + 0x1C, (quint32)nBase);
        m_pMemoryManager->writeDword(nOh + 0x38, (quint32)nSize);
        m_pMemoryManager->writeDword(nOh + 0x3C, 0x200);
        m_pMemoryManager->writeDword(nOh + 0x5C, 16);
        m_pMemoryManager->writeDword(nOh + 0x60, nExportRva);
        m_pMemoryManager->writeDword(nOh + 0x64, nExportDirSize);
    }

    // IMAGE_EXPORT_DIRECTORY.
    const XADDR nExp = nBase + nExportRva;
    m_pMemoryManager->writeDword(nExp + 0x0C, nModNameRva);   // Name (RVA)
    m_pMemoryManager->writeDword(nExp + 0x10, nBaseOrdinal);  // Base (ordinal base)
    m_pMemoryManager->writeDword(nExp + 0x14, (quint32)nFuncCount);  // NumberOfFunctions
    m_pMemoryManager->writeDword(nExp + 0x18, (quint32)nNamed);      // NumberOfNames
    m_pMemoryManager->writeDword(nExp + 0x1C, nFuncsRva);    // AddressOfFunctions
    m_pMemoryManager->writeDword(nExp + 0x20, nNamesRva);    // AddressOfNames
    m_pMemoryManager->writeDword(nExp + 0x24, nOrdsRva);     // AddressOfNameOrdinals

    // AddressOfFunctions: RVA relative to the image base. The trampolines live in the winapi
    // stub arena (below the module base), so the RVA is stored modulo 2^32 -- base + RVA
    // wraps back to the stub, exactly the address the modelled GetProcAddress hands back.
    // Named exports occupy slots [nNamedSlotBase, nNamedSlotBase+nNamed); by-ordinal imports
    // occupy their fixed slot (ordinal - Base) in [0, nMaxOrdinal) -- disjoint, no clobber.
    for (int i = 0; i < nNamed; i++) {
        m_pMemoryManager->writeDword(nBase + nFuncsRva + (quint32)(nNamedSlotBase + i) * 4, (quint32)(named.at(i).nStub - nBase));
    }
    for (int i = 0; i < exports.size(); i++) {
        const SYN_EXPORT &e = exports.at(i);
        if (e.sName.isEmpty() && (e.nOrdinal >= (qint64)nBaseOrdinal)) {
            const quint32 nIndex = (quint32)(e.nOrdinal - nBaseOrdinal);
            m_pMemoryManager->writeDword(nBase + nFuncsRva + nIndex * 4, (quint32)(e.nStub - nBase));
        }
    }

    // AddressOfNames (sorted) + AddressOfNameOrdinals (name i -> its function slot).
    for (int i = 0; i < nNamed; i++) {
        m_pMemoryManager->writeDword(nBase + nNamesRva + (quint32)i * 4, nameStrRva[i]);
        m_pMemoryManager->writeWord(nBase + nOrdsRva + (quint32)i * 2, (quint16)(nNamedSlotBase + i));
    }
}

void XEmuWindows::_ldrAppend(XADDR nHeadAddress, XADDR nLinkAddress)
{
    const int nPtr = _ptrSize();

    // Insert at the tail: between the current last node and the head.
    const XADDR nOldLast = (XADDR)_readPtr(nHeadAddress + nPtr);  // head.Blink
    _writePtr(nLinkAddress, nHeadAddress);          // new.Flink = &head
    _writePtr(nLinkAddress + nPtr, nOldLast);       // new.Blink = oldLast
    _writePtr(nOldLast, nLinkAddress);              // oldLast.Flink = &new
    _writePtr(nHeadAddress + nPtr, nLinkAddress);   // head.Blink = &new
}

void XEmuWindows::_ldrAddModule(const QString &sNameLower, XADDR nBase, quint64 nSize, XADDR nEntryPoint)
{
    // LDR_DATA_TABLE_ENTRY / PEB_LDR_DATA field offsets (must match _buildLoaderData).
    const int nOffInLoad = m_bIs64 ? 0x10 : 0x0C;
    const int nOffInMem = m_bIs64 ? 0x20 : 0x14;
    const int nOffInInit = m_bIs64 ? 0x30 : 0x1C;

    const int nEntInLoad = 0x00;
    const int nEntInMem = m_bIs64 ? 0x10 : 0x08;
    const int nEntInInit = m_bIs64 ? 0x20 : 0x10;
    const int nEntDllBase = m_bIs64 ? 0x30 : 0x18;
    const int nEntEntryPoint = m_bIs64 ? 0x38 : 0x1C;
    const int nEntSizeOfImage = m_bIs64 ? 0x40 : 0x20;
    const int nEntFullName = m_bIs64 ? 0x48 : 0x24;
    const int nEntBaseName = m_bIs64 ? 0x58 : 0x2C;
    const int nUnicodeBuffer = m_bIs64 ? 0x08 : 0x04;
    const int nEntrySize = 0x80;

    const XADDR nEntry = _poolAlloc(nEntrySize);
    if (nEntry == 0) {
        return;  // pool exhausted; the module image still exists, just not listed
    }

    _writePtr(nEntry + nEntDllBase, nBase);
    _writePtr(nEntry + nEntEntryPoint, nEntryPoint);
    m_pMemoryManager->writeDword(nEntry + nEntSizeOfImage, (quint32)nSize);

    quint16 nFullLength = 0;
    quint16 nBaseLength = 0;
    XADDR nFullBuffer = _writeUnicode(QStringLiteral("C:\\Windows\\System32\\%1").arg(sNameLower), &nFullLength);
    XADDR nBaseBuffer = _writeUnicode(sNameLower, &nBaseLength);

    m_pMemoryManager->writeWord(nEntry + nEntFullName + 0x00, nFullLength);
    m_pMemoryManager->writeWord(nEntry + nEntFullName + 0x02, nFullLength + 2);
    _writePtr(nEntry + nEntFullName + nUnicodeBuffer, nFullBuffer);

    m_pMemoryManager->writeWord(nEntry + nEntBaseName + 0x00, nBaseLength);
    m_pMemoryManager->writeWord(nEntry + nEntBaseName + 0x02, nBaseLength + 2);
    _writePtr(nEntry + nEntBaseName + nUnicodeBuffer, nBaseBuffer);

    _ldrAppend(m_nLdrDataAddress + nOffInLoad, nEntry + nEntInLoad);
    _ldrAppend(m_nLdrDataAddress + nOffInMem, nEntry + nEntInMem);
    _ldrAppend(m_nLdrDataAddress + nOffInInit, nEntry + nEntInInit);
}

XADDR XEmuWindows::_findLdrEntryByBase(XADDR nHeadAddress, int nLinkOffset, int nDllBaseOffset, XADDR nDllBase) const
{
    if (nHeadAddress == 0) {
        return 0;
    }

    XADDR nNode = (XADDR)_readPtr(nHeadAddress);
    if (nNode == 0) {
        return 0;
    }

    const XADDR nSentinel = nHeadAddress;
    int nSafety = 0;
    while ((nNode != nSentinel) && (nNode != 0) && (nSafety < 128)) {
        XADDR nEntryBase = nNode - nLinkOffset;
        if (_readPtr(nEntryBase + nDllBaseOffset) == nDllBase) {
            return nEntryBase;
        }

        // nNode is already the address of this entry's LIST_ENTRY.  Flink is
        // the first member of LIST_ENTRY, independent of where that link sits
        // inside LDR_DATA_TABLE_ENTRY.
        XADDR nNext = (XADDR)_readPtr(nNode);
        if (nNext == nNode) {
            break;
        }
        nNode = nNext;
        nSafety++;
    }

    return 0;
}

void XEmuWindows::_ldrMoveToFront(XADDR nHeadAddress, int nLinkOffset, XADDR nEntryAddress)
{
    if ((nHeadAddress == 0) || (nEntryAddress == 0)) {
        return;
    }

    const int nPtr = _ptrSize();
    const XADDR nLinkAddress = nEntryAddress + nLinkOffset;
    const XADDR nFirst = (XADDR)_readPtr(nHeadAddress);
    if ((nFirst == 0) || (nFirst == nLinkAddress)) {
        return;
    }

    const XADDR nEntryFlink = (XADDR)_readPtr(nLinkAddress);
    const XADDR nEntryBlink = (XADDR)_readPtr(nLinkAddress + nPtr);
    if ((nEntryFlink == 0) || (nEntryBlink == 0)) {
        return;
    }

    _writePtr(nEntryBlink, nEntryFlink);        // remove from current position
    _writePtr(nEntryFlink + nPtr, nEntryBlink);

    _writePtr(nLinkAddress, nFirst);   // prepend to list head
    _writePtr(nLinkAddress + nPtr, nHeadAddress);
    _writePtr(nHeadAddress, nLinkAddress);
    _writePtr(nFirst + nPtr, nLinkAddress);
}

void XEmuWindows::_buildLoaderData()
{
    // PEB_LDR_DATA field offsets.
    const int nOffInLoad = m_bIs64 ? 0x10 : 0x0C;
    const int nOffInMem = m_bIs64 ? 0x20 : 0x14;
    const int nOffInInit = m_bIs64 ? 0x30 : 0x1C;

    // LDR_DATA_TABLE_ENTRY field offsets.
    const int nEntInLoad = 0x00;
    const int nEntInMem = m_bIs64 ? 0x10 : 0x08;
    const int nEntInInit = m_bIs64 ? 0x20 : 0x10;
    const int nEntDllBase = m_bIs64 ? 0x30 : 0x18;
    const int nEntEntryPoint = m_bIs64 ? 0x38 : 0x1C;
    const int nEntSizeOfImage = m_bIs64 ? 0x40 : 0x20;
    const int nEntFullName = m_bIs64 ? 0x48 : 0x24;
    const int nEntBaseName = m_bIs64 ? 0x58 : 0x2C;
    const int nUnicodeBuffer = m_bIs64 ? 0x08 : 0x04;
    const int nEntrySize = 0x80;

    m_pMemoryManager->writeDword(m_nLdrDataAddress + 0x00, m_bIs64 ? 0x58 : 0x30);  // Length
    m_pMemoryManager->writeByte(m_nLdrDataAddress + 0x04, 1);                       // Initialized

    QList<XADDR> listEntryBases;
    QList<XADDR> listInitBases;  // InInitializationOrder: real Windows never lists the main .exe here

    for (int i = 0; i < m_listLoaded.size(); i++) {
        const XEmuFileFormat::MODULE &module = m_listLoaded.at(i).module;

        XADDR nEntry = _poolAlloc(nEntrySize);

        if (nEntry == 0) {
            emit errorMessage(tr("Loader-data pool exhausted"));
            break;
        }

        _writePtr(nEntry + nEntDllBase, module.nBaseAddress);
        _writePtr(nEntry + nEntEntryPoint, module.nEntryPointAddress);
        m_pMemoryManager->writeDword(nEntry + nEntSizeOfImage, (quint32)module.nImageSize);

        quint16 nFullLength = 0;
        quint16 nBaseLength = 0;
        XADDR nFullBuffer = _writeUnicode(module.sFileName, &nFullLength);
        XADDR nBaseBuffer = _writeUnicode(module.sName, &nBaseLength);

        m_pMemoryManager->writeWord(nEntry + nEntFullName + 0x00, nFullLength);
        m_pMemoryManager->writeWord(nEntry + nEntFullName + 0x02, nFullLength + 2);
        _writePtr(nEntry + nEntFullName + nUnicodeBuffer, nFullBuffer);

        m_pMemoryManager->writeWord(nEntry + nEntBaseName + 0x00, nBaseLength);
        m_pMemoryManager->writeWord(nEntry + nEntBaseName + 0x02, nBaseLength + 2);
        _writePtr(nEntry + nEntBaseName + nUnicodeBuffer, nBaseBuffer);

        listEntryBases.append(nEntry);
        // InInitializationOrder holds only DLLs (the main EXE has no DllMain and is never listed
        // here on real Windows). With bLoadDependencies=false, m_listLoaded is just the main EXE at
        // this point, so listInitBases starts EMPTY -- the synth ntdll then kernel32, appended after
        // setup via _ldrAddModule, become InInit[0]/[1]. This makes the classic "2nd InInit module =
        // kernel32" locator (yzpack 1.x) land on kernel32. InLoad/InMem keep the EXE at [0].
        if (m_listLoaded.at(i).pFormat && m_listLoaded.at(i).pFormat->isDll()) {
            listInitBases.append(nEntry);
        }
    }

    _linkList(m_nLdrDataAddress + nOffInLoad, nEntInLoad, listEntryBases);
    _linkList(m_nLdrDataAddress + nOffInMem, nEntInMem, listEntryBases);
    _linkList(m_nLdrDataAddress + nOffInInit, nEntInInit, listInitBases);
}

void XEmuWindows::_buildPebTeb(quint64 nStackBase, quint64 nStackLimit)
{
    XADDR nImageBase = m_listLoaded.isEmpty() ? 0 : m_listLoaded.at(0).module.nBaseAddress;

    // PEB.
    const int nPebImageBase = m_bIs64 ? 0x10 : 0x08;
    const int nPebLdr = m_bIs64 ? 0x18 : 0x0C;
    const int nPebProcessParameters = m_bIs64 ? 0x20 : 0x10;
    const int nPebNumberOfProcessors = m_bIs64 ? 0xB8 : 0x64;
    const int nPebOSMajor = m_bIs64 ? 0x118 : 0xA4;
    const int nPebOSMinor = m_bIs64 ? 0x11C : 0xA8;
    const int nPebOSBuild = m_bIs64 ? 0x120 : 0xAC;
    const int nPebOSPlatformId = m_bIs64 ? 0x124 : 0xB0;

    m_pMemoryManager->writeByte(m_nPebAddress + 0x02, 0);  // BeingDebugged
    _writePtr(m_nPebAddress + nPebImageBase, nImageBase);
    _writePtr(m_nPebAddress + nPebLdr, m_nLdrDataAddress);
    _writePtr(m_nPebAddress + nPebProcessParameters, 0);
    m_pMemoryManager->writeDword(m_nPebAddress + nPebNumberOfProcessors, 1);
    m_pMemoryManager->writeDword(m_nPebAddress + nPebOSMajor, 10);
    m_pMemoryManager->writeDword(m_nPebAddress + nPebOSMinor, 0);
    m_pMemoryManager->writeWord(m_nPebAddress + nPebOSBuild, 19041);
    m_pMemoryManager->writeDword(m_nPebAddress + nPebOSPlatformId, 2);

    // TEB.
    const int nTebStackBase = m_bIs64 ? 0x08 : 0x04;
    const int nTebStackLimit = m_bIs64 ? 0x10 : 0x08;
    const int nTebSelf = m_bIs64 ? 0x30 : 0x18;
    const int nTebClientId = m_bIs64 ? 0x40 : 0x20;
    const int nTebPeb = m_bIs64 ? 0x60 : 0x30;

    _writePtr(m_nTebAddress + 0x00, ~Q_UINT64_C(0));  // NtTib.ExceptionList = -1
    _writePtr(m_nTebAddress + nTebStackBase, nStackBase);
    _writePtr(m_nTebAddress + nTebStackLimit, nStackLimit);
    _writePtr(m_nTebAddress + nTebSelf, m_nTebAddress);
    _writePtr(m_nTebAddress + nTebClientId, N_FAKE_PID);
    _writePtr(m_nTebAddress + nTebClientId + _ptrSize(), N_FAKE_TID);
    _writePtr(m_nTebAddress + nTebPeb, m_nPebAddress);
}

void XEmuWindows::_setupRegisters(XEmuRegisters *pRegisters, quint64 nStackTop, bool bIsDll)
{
    pRegisters->reset();

    quint64 nSp = XEmuMemoryManager::alignDown(nStackTop - 0x100, 16);
    XADDR nEntry = m_listLoaded.isEmpty() ? 0 : m_listLoaded.at(0).module.nEntryPointAddress;
    XADDR nMainBase = m_listLoaded.isEmpty() ? 0 : (XADDR)m_listLoaded.at(0).module.nBaseAddress;

    m_pArch->setStackPointer(pRegisters, nSp);
    m_pArch->setPC(pRegisters, nEntry);

    if ((m_archType == XARCH_X86_64) || (m_archType == XARCH_X86_32)) {
        pRegisters->nRFLAGS = 0x202;
        // Windows hands the initial thread EBX = PEB pointer at the image entry point.
        // Packers (VMProtect, etc.) read PEB fields via EBX during their entry stub, so
        // without this they dereference a null/garbage pointer and diverge. Because the PEB
        // is page-aligned, PEB-relative address arithmetic keeps the same low bits as on a
        // real (ASLR'd) process, so control flow that is ASLR-independent stays in lockstep.
        pRegisters->setGPR(3, m_bIs64 ? 8 : 4, m_nPebAddress);  // EBX/RBX
        // Windows also enters the image with a valid EBP (the loader's BaseThreadInitThunk
        // frame), never 0. Frameless entry stubs (e.g. Very Simple PE Crypter) use [ebp-0xC]
        // scratch with no push ebp/mov ebp,esp prologue; with EBP=0 the first write faults at
        // ~0xfffffff4. Seed EBP just below the initial ESP so that scratch lands in the stack.
        pRegisters->setGPR(5, m_bIs64 ? 8 : 4, nSp);  // EBP/RBP
        if (m_bIs64) {
            pRegisters->nCS = 0x33;
            pRegisters->nSS = 0x2B;
            pRegisters->nDS = 0x2B;
            pRegisters->nES = 0x2B;
            pRegisters->nFS = 0x53;
            pRegisters->nGS = 0x2B;
            pRegisters->nFSBase = 0;
            pRegisters->nGSBase = m_nTebAddress;  // GS points at the TEB on x86-64
        } else {
            pRegisters->nCS = 0x23;
            pRegisters->nSS = 0x2B;
            pRegisters->nDS = 0x2B;
            pRegisters->nES = 0x2B;
            pRegisters->nFS = 0x3B;
            pRegisters->nGS = 0x00;
            pRegisters->nFSBase = m_nTebAddress;  // FS points at the TEB on x86
            pRegisters->nGSBase = 0;

            // Install an initial SEH frame like the Windows loader: fs:[0] points at an
            // EXCEPTION_REGISTRATION_RECORD near the stack top ({Next=-1, Handler}), not the
            // empty chain (-1). Packers read fs:[0] and chain their own handler onto it; an
            // empty chain makes them store/checksum -1 instead of a stack pointer and diverge.
            XADDR nRec = (XADDR)XEmuMemoryManager::alignDown(nStackTop - 0x34, 4);
            m_pMemoryManager->writeDword(nRec + 0x00, 0xFFFFFFFFu);            // Next = end
            m_pMemoryManager->writeDword(nRec + 0x04, (quint32)nEntry);       // Handler (synthetic)
            m_pMemoryManager->writeDword(m_nTebAddress + 0x00, (quint32)nRec);  // TEB.ExceptionList
        }
    } else if (m_archType == XARCH_ARM64) {
        pRegisters->nGPR[18] = m_nTebAddress;  // Windows on ARM64 keeps the TEB in x18
        pRegisters->nTPIDR = m_nTebAddress;
    } else if (m_archType == XARCH_ARM) {
        pRegisters->nTPIDR = m_nTebAddress;
    }

    // A DLL's entry point is DllMain(hinstDLL, fdwReason, lpvReserved). The real loader calls
    // it with fdwReason == DLL_PROCESS_ATTACH (1); a packer's DLL stub (UPX, ...) branches on
    // that argument and only decompresses + resolves imports on ATTACH -- with no proper call
    // frame it reads a garbage/zero reason, skips unpacking entirely, and "runs" through a
    // still-compressed (zero-filled) image. Synthesise the loader's DLL_PROCESS_ATTACH call so
    // the stub actually unpacks. (lpvReserved != 0 == static/implicit load.)
    if (bIsDll && (nEntry != 0)) {
        if (m_archType == XARCH_X86_32) {
            nSp -= 0x10;
            m_pMemoryManager->writeDword(nSp + 0x0, 0);                 // return address (ATTACH path tail-jumps to the OEP; never returns)
            m_pMemoryManager->writeDword(nSp + 0x4, (quint32)nMainBase);  // hinstDLL
            m_pMemoryManager->writeDword(nSp + 0x8, 1);                 // fdwReason = DLL_PROCESS_ATTACH
            m_pMemoryManager->writeDword(nSp + 0xC, 1);                 // lpvReserved (non-null == static load)
            m_pArch->setStackPointer(pRegisters, nSp);
        } else if (m_archType == XARCH_X86_64) {
            // x64 __fastcall: RCX=hinstDLL, RDX=fdwReason, R8=lpvReserved + 0x20 shadow space.
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 8, nMainBase);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 8, 1);
            pRegisters->setGPR(XEmuRegisters::GPR_R8, 8, 1);
            nSp -= 0x28;
            m_pMemoryManager->writeDword(nSp + 0x0, 0);  // return address (low)
            m_pMemoryManager->writeDword(nSp + 0x4, 0);  // return address (high)
            m_pArch->setStackPointer(pRegisters, nSp);
        }
    }
}

void XEmuWindows::_releaseOwnedFormats()
{
    for (int i = 0; i < m_listLoaded.size(); i++) {
        if (m_listLoaded.at(i).bOwned && m_listLoaded.at(i).pFormat) {
            delete m_listLoaded[i].pFormat;
            m_listLoaded[i].pFormat = nullptr;
        }
    }
}

bool XEmuWindows::setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options)
{
    m_listLoaded.clear();
    m_mapNameToIndex.clear();
    m_mapForwardedExports.clear();
    m_nForwardedExportCount = 0;
    m_listModules.clear();
    m_bAsdPackMode = false;
    m_bImploderMode = false;

    if (!pMainFormat || !pMainFormat->isValid()) {
        emit errorMessage(tr("Invalid main module"));
        return false;
    }

    m_nImageBaseOverride = options.nImageBaseOverride;
    m_bIs64 = pMainFormat->is64Bit();
    m_archType = pMainFormat->getArchType();
    m_pMemoryManager->clear();
    m_pMemoryManager->setBits(m_bIs64 ? 64 : 32);
    m_pArch->setBits(m_bIs64 ? 64 : 32);

    XEmuFileFormat::MODULE mainModule;

    if (!_mapModule(pMainFormat, false, &mainModule)) {
        emit errorMessage(tr("Cannot map the main image"));
        return false;
    }

    m_bAsdPackMode = _isAsdPackCandidate();
    auto isOrdinalKernelImport = [](const XEmuFileFormat::IMPORT &imp) {
        if (imp.sLibrary.toLower() != QStringLiteral("kernel32.dll")) {
            return false;
        }
        if (imp.nOrdinal >= 1) {
            return true;
        }
        bool bHasNumber = false;
        const int nDecimal = imp.sFunction.toInt(&bHasNumber);
        return bHasNumber && (nDecimal >= 1);
    };

    if (!m_bIs64 && !m_listLoaded.isEmpty() && m_listLoaded.at(0).pFormat) {
        const QList<XEmuFileFormat::IMPORT> listImports = m_listLoaded.at(0).pFormat->getImports();
        for (int i = 0; i < listImports.size(); i++) {
            if (isOrdinalKernelImport(listImports.at(i))) {
                m_bImploderMode = true;
                break;
            }
        }
    }

    // Emulated Windows-API layer. Real DLL code cannot run on the subset CPU core,
    // so loader/memory APIs are modelled in C++ and imports are diverted to
    // trampolines this layer intercepts -- independent of whether real dependency
    // images were mapped.
    delete m_pWinApi;
    m_pWinApi = new XEmuWinApi(m_pMemoryManager, m_pArch, m_bIs64);
    m_pWinApi->setLogger(std::bind(&XEmuWindows::_forwardWinApiLog, this, std::placeholders::_1));
    m_pWinApi->setProcessContext(mainModule.sFileName, options.sCommandLine, options.sWorkingDirectory);

    if (!m_pWinApi->init()) {
        emit errorMessage(tr("Cannot allocate the emulated-API region"));
    }

    // Reserve the SEH handler-return trap and reset any dispatch state from a prior run.
    m_nSehReturnTrap = m_pWinApi->allocTrampoline();
    m_listSehStack.clear();
    m_bSehDeliver = false;
    m_nSehDeliverPC = 0;
    m_bSehTerminate = false;

    if (options.bLoadDependencies) {
        _loadDependencies(options.sSystemRoot, 96);
    }

    // Let the API layer name every mapped module so LoadLibraryA / GetProcAddress
    // can hand back genuine bases where available.
    for (QMap<QString, int>::const_iterator it = m_mapNameToIndex.constBegin(); it != m_mapNameToIndex.constEnd(); ++it) {
        m_pWinApi->registerModule(it.key(), m_listLoaded.at(it.value()).module.nBaseAddress);
    }

    _patchImports();

    // Control structures.
    // Diagnostic override: XEMU_PEBBASE=<hex> forces the PEB base VA (e.g. to match a real
    // process), to test whether an emulation divergence is driven by PEB-base ASLR when a
    // packer rotates/derives values from the PEB pointer.
    m_nPebAddress = 0;
    { QByteArray e = qgetenv("XEMU_PEBBASE");
      if (!e.isEmpty()) {
          XADDR nWant = (XADDR)(QString::fromLocal8Bit(e).trimmed().toULongLong(nullptr, 16) & ~0xFFFULL);
          m_nPebAddress = m_pMemoryManager->allocate(nWant, 0x1000, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("PEB"));
      } }
    if (m_nPebAddress == 0)
        m_nPebAddress = m_pMemoryManager->allocate(0, 0x1000, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("PEB"));
    m_nTebAddress = m_pMemoryManager->allocate(0, 0x1000, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("TEB"));
    m_nLdrDataAddress = m_pMemoryManager->allocate(0, 0x1000, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("PEB_LDR_DATA"));

    m_nPoolSize = qMax<quint64>(0x10000, (quint64)m_listLoaded.size() * 0x800);
    m_nPoolAddress = m_pMemoryManager->allocate(0, m_nPoolSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("loader_pool"));
    m_nPoolCursor = m_nPoolAddress;

    if ((m_nPebAddress == 0) || (m_nTebAddress == 0) || (m_nLdrDataAddress == 0) || (m_nPoolAddress == 0)) {
        emit errorMessage(tr("Cannot allocate process control structures"));
        return false;
    }

    quint64 nStackBase = 0;
    quint64 nStackLimit = 0;
    XADDR nStackTop = _setupStack(options.nStackSize, &nStackBase, &nStackLimit);

    if (nStackTop == 0) {
        emit errorMessage(tr("Cannot allocate the thread stack"));
        return false;
    }

    _buildLoaderData();
    _buildPebTeb(nStackBase, nStackLimit);
    _setupRegisters(pRegisters, nStackTop, pMainFormat->isDll());

    // Let LoadLibraryA/GetModuleHandleA synthesise a module image + PEB Ldr entry for
    // any dependency that is not really mapped, and answer GetModuleHandleA(NULL).
    m_pWinApi->setMainModuleBase(m_listLoaded.isEmpty() ? 0 : m_listLoaded.at(0).module.nBaseAddress);
    m_pWinApi->setModuleCreator(std::bind(&XEmuWindows::_createSyntheticModule, this, std::placeholders::_1));

    // Serve the main module's real on-disk bytes so a packer's anti-tamper self-CRC (open its
    // own file via GetModuleFileNameW->NtOpenFile->NtReadFile) succeeds instead of bailing.
    if (!m_listLoaded.isEmpty()) {
        QFile fMain(m_listLoaded.at(0).module.sFileName);
        if (fMain.open(QIODevice::ReadOnly)) {
            m_pWinApi->setMainModuleFile(fMain.readAll());
            fMain.close();
        }
    }

    // ntdll.dll and kernel32.dll are mapped into EVERY Win32 process. Packers with runtime
    // import protection (VMProtect, etc.) call GetModuleHandleA("kernel32"/"ntdll") and then
    // walk the returned module's PE header + export table to resolve APIs by hash. Without
    // these present, GetModuleHandleA returns 0 and the packer dereferences a null base
    // (observed: null-deref at .vmp0 0x4726c0). Pre-create + register them so the query
    // succeeds and the header/export walk lands on a valid synthetic image.
    // Option B (env-gated XEMU_REALDLLS): map the REAL 32-bit ntdll/kernelbase/kernel32 as
    // data so a packer with runtime import protection (VMProtect) that walks the export tables
    // and folds the resolved VAs into its VM state gets AUTHENTIC in-module addresses instead
    // of synthetic arena stubs (which it rejects, spinning forever). Otherwise fall back to the
    // cheap synthetic kernel32/ntdll (enough for the common loader-API case, no regression).
    XADDR nNtdllBase = 0;
    XADDR nKernel32Base = 0;

    if (!m_bIs64 && !qEnvironmentVariableIsEmpty("XEMU_REALDLLS")) {
        if (!_mapRealSystemDlls()) {
            return false;
        }
        if (m_mapNameToIndex.contains(QStringLiteral("ntdll.dll"))) {
            const int nIdx = m_mapNameToIndex.value(QStringLiteral("ntdll.dll"));
            if ((nIdx >= 0) && (nIdx < m_listLoaded.size())) {
                nNtdllBase = m_listLoaded.at(nIdx).module.nBaseAddress;
            }
        }
        if (m_mapNameToIndex.contains(QStringLiteral("kernel32.dll"))) {
            const int nIdx = m_mapNameToIndex.value(QStringLiteral("kernel32.dll"));
            if ((nIdx >= 0) && (nIdx < m_listLoaded.size())) {
                nKernel32Base = m_listLoaded.at(nIdx).module.nBaseAddress;
            }
        }
    } else {
        for (const QString &sSysDll : {QStringLiteral("ntdll.dll"), QStringLiteral("kernel32.dll")}) {
            if (m_pWinApi->stubBase() == 0) break;  // arena not initialised
            XADDR nBase = _createSyntheticModule(sSysDll);
            if (nBase != 0) {
                m_pWinApi->registerModule(sSysDll, nBase);
                if (sSysDll == QStringLiteral("ntdll.dll")) {
                    nNtdllBase = nBase;
                } else if (sSysDll == QStringLiteral("kernel32.dll")) {
                    nKernel32Base = nBase;
                }
            }
        }
    }

    // Imploder resolves some APIs through a by-ordinal kernel32 IAT slot before walking
    // the import table. Seed that slot to a plausible kernel32 image base so the resolver's
    // MZ scan starts on a real module and does not underflow.
    if (m_bImploderMode && (nKernel32Base != 0) && !m_listLoaded.isEmpty() && m_listLoaded.at(0).pFormat) {
        const QList<XEmuFileFormat::IMPORT> listImports = m_listLoaded.at(0).pFormat->getImports();
        XADDR nMainBase = m_listLoaded.at(0).module.nBaseAddress;
        for (int i = 0; i < listImports.size(); i++) {
            const XEmuFileFormat::IMPORT &imp = listImports.at(i);
            if ((imp.sLibrary.toLower() == QStringLiteral("kernel32.dll")) && isOrdinalKernelImport(imp)) {
                _writePtr(nMainBase + imp.nSlotRVA, nKernel32Base + 0x100);
            }
        }
    }

    // ASDPack expects ntdll then kernel32 in the initialization list (InInitOrderModuleList).
    // Real-DLL mode can include extra libraries (kernelbase, etc.), so move only those two entries
    // when their bases are known.
    if (m_bAsdPackMode && (m_nLdrDataAddress != 0)) {
        if ((nNtdllBase != 0) && (nKernel32Base != 0)) {
            const int nOffInInit = m_bIs64 ? 0x30 : 0x1C;
            const int nEntInInit = m_bIs64 ? 0x20 : 0x10;
            const int nEntDllBase = m_bIs64 ? 0x30 : 0x18;
            XADDR nInitHead = m_nLdrDataAddress + nOffInInit;
            XADDR nKernel32Entry = _findLdrEntryByBase(nInitHead, nEntInInit, nEntDllBase, nKernel32Base);
            XADDR nNtdllEntry = _findLdrEntryByBase(nInitHead, nEntInInit, nEntDllBase, nNtdllBase);
            if ((nKernel32Entry != 0) && (nNtdllEntry != 0)) {
                _ldrMoveToFront(nInitHead, nEntInInit, nKernel32Entry);
                _ldrMoveToFront(nInitHead, nEntInInit, nNtdllEntry);
            }
        }
    }

    for (int i = 0; i < m_listLoaded.size(); i++) {
        m_listModules.append(m_listLoaded.at(i).module);
    }

    emit infoMessage(tr("Process ready: %1 module(s), entry point %2").arg(m_listModules.size()).arg(pRegisters->nRIP, 0, 16));

    _releaseOwnedFormats();

    return true;
}
