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
#include "xemuwinapi.h"

#include <cstdio>

// Win32 memory-protection constants (winnt.h values).
static const quint32 PAGE_NOACCESS_V = 0x01;
static const quint32 PAGE_EXECUTE_MASK = 0xF0;   // EXECUTE | *_READ | *_READWRITE | *_WRITECOPY
static const quint32 PAGE_WRITE_MASK = 0xCC;     // READWRITE | WRITECOPY | EXECUTE_READWRITE | EXECUTE_WRITECOPY

// A trampoline entry is one byte (0xC3 RET as a safety net); we space them out so
// each API has a distinct, easily recognised address inside the arena.
static const quint64 N_STUB_STRIDE = 0x10;

XEmuWinApi::XEmuWinApi(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64)
    : m_pMemoryManager(pMemoryManager), m_pArch(pArch), m_bIs64(bIs64), m_nMainModuleBase(0), m_nStubBase(0), m_nStubSize(0), m_nStubCursor(0),
      m_nFakeHandleCursor(0xE0000000), m_bProcessExited(false), m_nNextFileHandle(0x00000F00)
{
}

void XEmuWinApi::setMainModuleFile(const QByteArray &baFile)
{
    m_baMainFile = baFile;
}

void XEmuWinApi::setLogger(LOG_CALLBACK fnLog)
{
    m_fnLog = fnLog;
}

void XEmuWinApi::setModuleCreator(MODULE_CREATOR fnCreate)
{
    m_fnCreateModule = fnCreate;
}

void XEmuWinApi::setMainModuleBase(XADDR nBaseAddress)
{
    m_nMainModuleBase = nBaseAddress;
}

void XEmuWinApi::_log(const QString &sText) const
{
    if (m_fnLog) {
        m_fnLog(sText);
    }
}

bool XEmuWinApi::init()
{
    m_nStubSize = 0x10000;

    // Place the trampoline arena at a high, DLL-like base (like a real system DLL) rather
    // than low memory. Trampoline pointers get written into the guest IAT; a low base such
    // as 0x10000 collides with extremely common data constants (0x10000 == 64 KB), which
    // makes it impossible to tell a real IAT entry from coincidental data during import
    // reconstruction. A high base makes every IAT-range value unambiguously a resolved import.
    // Import reconstruction relies on this base being HIGH (see guBuildImportBlob /
    // XEmulUnpacker's IAT scan): a low base such as 0x10000 collides with common data
    // constants (0x10000 == 64 KB) so ordinary data dwords would be misread as resolved
    // imports. Try a series of high, DLL-like bases; only fall back to first-fit (which may
    // land low) if every high candidate is somehow occupied.
    static const XADDR s_highBases[] = {0x71000000, 0x68000000, 0x60000000, 0x58000000, 0x50000000};
    for (size_t i = 0; (m_nStubBase == 0) && (i < sizeof(s_highBases) / sizeof(s_highBases[0])); i++) {
        m_nStubBase = m_pMemoryManager->allocate(s_highBases[i], m_nStubSize, XEmuMemoryManager::MEMORY_FLAGS(true, false, true), QStringLiteral("winapi_stubs"));
    }

    if (m_nStubBase == 0) {
        // Last resort: first-fit. (Astronomically unlikely given a 64 KB arena and five high
        // candidates; import reconstruction's no-collision invariant is weaker here.)
        m_nStubBase = m_pMemoryManager->allocate(0, m_nStubSize, XEmuMemoryManager::MEMORY_FLAGS(true, false, true), QStringLiteral("winapi_stubs"));
    }

    if (m_nStubBase == 0) {
        return false;
    }

    // Safety net: if a call ever reaches a trampoline without being caught by
    // dispatch(), a plain 0xC3 makes the CPU return cleanly instead of decoding
    // whatever happens to lie there.
    QByteArray baRet(static_cast<int>(m_nStubSize), (char)0xC3);
    m_pMemoryManager->write(m_nStubBase, baRet);

    m_nStubCursor = m_nStubBase;

    // Reserve stable addresses for the modelled loader APIs up front.
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("VirtualAlloc"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("VirtualProtect"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("VirtualFree"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("LoadLibraryA"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("LoadLibraryExA"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("GetProcAddress"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("GetModuleHandleA"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("VirtualFreeEx"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("VirtualProtectEx"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("GlobalAlloc"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("GlobalFree"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("LocalAlloc"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("LocalFree"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("HeapAlloc"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("HeapFree"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("ExitProcess"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("CreateFileA"));
    stubFor(QStringLiteral("kernel32.dll"), QStringLiteral("CreateFileW"));

    return true;
}

void XEmuWinApi::registerModule(const QString &sLibraryLower, XADDR nBaseAddress)
{
    if (sLibraryLower.isEmpty() || (nBaseAddress == 0)) {
        return;
    }

    m_mapModuleBase.insert(sLibraryLower, nBaseAddress);
    m_mapHandleName.insert(nBaseAddress, sLibraryLower);
}

int XEmuWinApi::_classify(const QString &sLibrary, const QString &sFunction)
{
    Q_UNUSED(sLibrary)

    // The modelled APIs (VirtualAlloc/VirtualProtect/VirtualFree/LoadLibraryA/
    // GetProcAddress) live in kernel32 and their names are unique to it, so match on
    // the function name alone -- do NOT gate on the module string. A packer that
    // resolves these through its own PEB/Ldr walk (ASPack, PECompact, ...) hands
    // GetProcAddress a kernel32 base we never registered, which _moduleName reports as
    // "unknown.dll". Gating on "kernel32" here would then misclassify the call as
    // API_GENERIC -- a no-op that returns 0 -- so the stub would VirtualAlloc a null
    // scratch buffer and fault (e.g. ASPack 2.x in a 'rep stosd' through 0x00001020).
    if (sFunction == QStringLiteral("VirtualAlloc")) {
        return API_VIRTUALALLOC;
    } else if (sFunction == QStringLiteral("VirtualProtect")) {
        return API_VIRTUALPROTECT;
    } else if (sFunction == QStringLiteral("VirtualFree")) {
        return API_VIRTUALFREE;
    } else if (sFunction == QStringLiteral("LoadLibraryA")) {
        return API_LOADLIBRARYA;
    } else if (sFunction == QStringLiteral("LoadLibraryExA")) {
        return API_LOADLIBRARYEXA;
    } else if (sFunction == QStringLiteral("GetProcAddress")) {
        return API_GETPROCADDRESS;
    } else if (sFunction == QStringLiteral("GetModuleHandleA")) {
        return API_GETMODULEHANDLEA;
    } else if (sFunction == QStringLiteral("GlobalAlloc")) {
        return API_GLOBALALLOC;
    } else if (sFunction == QStringLiteral("GlobalFree")) {
        return API_GLOBALFREE;
    } else if (sFunction == QStringLiteral("LocalAlloc")) {
        return API_LOCALALLOC;
    } else if (sFunction == QStringLiteral("LocalFree")) {
        return API_LOCALFREE;
    } else if (sFunction == QStringLiteral("HeapAlloc")) {
        return API_HEAPALLOC;
    } else if (sFunction == QStringLiteral("HeapFree")) {
        return API_HEAPFREE;
    } else if (sFunction == QStringLiteral("VirtualFreeEx")) {
        return API_VIRTUALFREEEX;
    } else if (sFunction == QStringLiteral("VirtualProtectEx")) {
        return API_VIRTUALPROTECTEX;
    } else if ((sFunction == QStringLiteral("ExitProcess")) || (sFunction == QStringLiteral("TerminateProcess"))) {
        return API_EXITPROCESS;
    } else if ((sFunction == QStringLiteral("CreateFileA")) || (sFunction == QStringLiteral("CreateFileW"))) {
        return API_CREATEFILE;
    }

    return API_GENERIC;
}

XADDR XEmuWinApi::_allocStub()
{
    XADDR nStub = m_nStubCursor;
    m_nStubCursor += N_STUB_STRIDE;

    // If the arena is exhausted just keep handing out the last slot; the modelled
    // APIs are pre-registered, so any overflow can only be a generic no-op anyway.
    if (m_nStubCursor > (m_nStubBase + m_nStubSize)) {
        m_nStubCursor = m_nStubBase + m_nStubSize - N_STUB_STRIDE;
        nStub = m_nStubCursor;
    }

    return nStub;
}

bool XEmuWinApi::resolveImportStub(XADDR nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const
{
    QMap<XADDR, IMPORT_NAME>::const_iterator it = m_mapStubToImport.constFind(nStub);
    if (it == m_mapStubToImport.constEnd()) {
        return false;
    }
    if (pLibrary) {
        *pLibrary = it->sLibrary;
    }
    if (pFunction) {
        *pFunction = it->sFunction;
    }
    if (pOrdinal) {
        *pOrdinal = it->nOrdinal;
    }
    return true;
}

XADDR XEmuWinApi::stubFor(const QString &sLibrary, const QString &sFunction, qint64 nOrdinal)
{
    QString sFunc = sFunction;

    if (sFunc.isEmpty() && (nOrdinal >= 0)) {
        sFunc = QStringLiteral("#%1").arg(nOrdinal);
    }

    QString sKey = sLibrary.toLower() + QStringLiteral("!") + sFunc.toLower();

    if (m_mapNameToStub.contains(sKey)) {
        return m_mapNameToStub.value(sKey);
    }

    XADDR nStub = _allocStub();
    m_mapStubToApi.insert(nStub, _classify(sLibrary, sFunc));
    m_mapNameToStub.insert(sKey, nStub);

    // Remember the original-case name so import reconstruction can rebuild a real import
    // directory from the trampolines the packer wrote into the IAT.
    IMPORT_NAME imp;
    imp.sLibrary = sLibrary;
    imp.sFunction = sFunction;  // original case; empty for a by-ordinal import
    imp.nOrdinal = nOrdinal;
    m_mapStubToImport.insert(nStub, imp);

    return nStub;
}

XADDR XEmuWinApi::stubForKnownApi(const QString &sLibrary, const QString &sFunction)
{
    if (_classify(sLibrary, sFunction) == API_GENERIC) {
        return 0;
    }

    return stubFor(sLibrary, sFunction);
}

bool XEmuWinApi::isStub(XADDR nAddress) const
{
    if ((m_nStubBase != 0) && (nAddress >= m_nStubBase) && (nAddress < (m_nStubBase + m_nStubSize))) {
        return true;
    }
    // Any PC inside a mapped real system DLL is intercepted (the subset CPU cannot run real
    // DLL code): dispatch() models the export at this VA, or a generic no-op if unknown.
    for (int i = 0; i < m_realRanges.size(); i++) {
        if ((nAddress >= m_realRanges.at(i).nLo) && (nAddress < m_realRanges.at(i).nHi)) {
            return true;
        }
    }
    return false;
}

void XEmuWinApi::registerRealExport(XADDR nVa, const QString &sLibrary, const QString &sFunction, qint64 nOrdinal)
{
    // Map the resolved export VA to a modelled API id (or API_GENERIC). dispatch() keys on
    // m_mapStubToApi, so this makes a real export VA dispatch exactly like an arena stub.
    m_mapStubToApi.insert(nVa, _classify(sLibrary, sFunction));

    IMPORT_NAME name;
    name.sLibrary = sLibrary;
    name.sFunction = sFunction;
    name.nOrdinal = nOrdinal;
    m_mapStubToImport.insert(nVa, name);
}

void XEmuWinApi::addRealRange(XADDR nBase, quint64 nSize)
{
    REAL_RANGE r;
    r.nLo = nBase;
    r.nHi = nBase + nSize;
    m_realRanges.append(r);
}

XADDR XEmuWinApi::allocTrampoline()
{
    if (m_nStubBase == 0) {
        return 0;
    }

    // A slot with no API mapping: dispatch() would treat it as API_GENERIC, so the OS
    // layer must intercept it before delegating here.
    return _allocStub();
}

bool XEmuWinApi::dispatch(XEmuRegisters *pRegisters)
{
    XADDR nPC = m_pArch->getPC(pRegisters);

    if (!isStub(nPC)) {
        return false;
    }

    const int nApiId = m_mapStubToApi.value(nPC, API_GENERIC);

    // Env-gated API-call trace (XEMU_APILOG=1): logs every dispatched call -- the resolved
    // import name, first 4 stdcall args, and the return value -- to stderr, so the API
    // boundary can be diffed against the real process. GENERIC = unmodelled no-op (returns 0,
    // cleans 0 args): the prime suspect for anti-debug/anti-VM/timing divergence.
    static const bool bApiLog = !qEnvironmentVariableIsEmpty("XEMU_APILOG");
    QString sImp;
    quint64 aArg[4] = {0, 0, 0, 0};
    if (bApiLog) {
        QString sLib, sFunc;
        qint64 nOrd = -1;
        if (resolveImportStub(nPC, &sLib, &sFunc, &nOrd)) {
            sImp = !sFunc.isEmpty() ? QString("%1!%2").arg(sLib, sFunc)
                                    : (nOrd >= 0 ? QString("%1!#%2").arg(sLib).arg(nOrd) : QString("%1!?").arg(sLib));
        } else {
            sImp = QStringLiteral("<unnamed>");
        }
        for (int k = 0; k < 4; k++) aArg[k] = _arg(pRegisters, k);
    }

    switch (nApiId) {
        case API_VIRTUALALLOC: _apiVirtualAlloc(pRegisters); break;
        case API_VIRTUALPROTECT: _apiVirtualProtect(pRegisters); break;
        case API_VIRTUALFREE: _apiVirtualFree(pRegisters); break;
        case API_LOADLIBRARYA: _apiLoadLibraryA(pRegisters); break;
        case API_LOADLIBRARYEXA: _apiLoadLibraryExA(pRegisters); break;
        case API_GETPROCADDRESS: _apiGetProcAddress(pRegisters); break;
        case API_GETMODULEHANDLEA: _apiGetModuleHandleA(pRegisters); break;
        case API_GLOBALALLOC: _apiGlobalAlloc(pRegisters); break;
        case API_GLOBALFREE: _apiGlobalFree(pRegisters); break;
        case API_LOCALALLOC: _apiLocalAlloc(pRegisters); break;
        case API_LOCALFREE: _apiLocalFree(pRegisters); break;
        case API_HEAPALLOC: _apiHeapAlloc(pRegisters); break;
        case API_HEAPFREE: _apiHeapFree(pRegisters); break;
        case API_EXITPROCESS: _apiExitProcess(pRegisters); break;
        case API_CREATEFILE: _apiCreateFile(pRegisters); break;
        case API_VIRTUALFREEEX: _apiVirtualFreeEx(pRegisters); break;
        case API_VIRTUALPROTECTEX: _apiVirtualProtectEx(pRegisters); break;
        default:
            // With real DLLs mapped, a packer also calls environment/anti-analysis APIs.
            // Model the bounded known set (correct return + output buffers + stdcall cleanup);
            // otherwise fall back to the plain no-op (argument-less unwind, return 0).
            if (!_apiByName(pRegisters, m_mapStubToImport.value(nPC).sFunction)) {
                _return(pRegisters, 0, 0);
            }
            break;
    }

    if (bApiLog) {
        quint64 nRet = pRegisters->getGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4);
        fprintf(stderr, "[API] va=%08llx %-32s id=%2d  args=%08llx %08llx %08llx %08llx  -> %08llx%s\n",
                (unsigned long long)nPC, sImp.toLatin1().constData(), nApiId,
                (unsigned long long)aArg[0], (unsigned long long)aArg[1],
                (unsigned long long)aArg[2], (unsigned long long)aArg[3],
                (unsigned long long)nRet, (nApiId == API_GENERIC) ? "   <== GENERIC no-op" : "");
        fflush(stderr);
    }

    return true;
}

quint64 XEmuWinApi::_arg(XEmuRegisters *pRegisters, int nIndex) const
{
    if (m_bIs64) {
        switch (nIndex) {
            case 0: return pRegisters->getGPR(XEmuRegisters::GPR_RCX, 8);
            case 1: return pRegisters->getGPR(XEmuRegisters::GPR_RDX, 8);
            case 2: return pRegisters->getGPR(XEmuRegisters::GPR_R8, 8);
            case 3: return pRegisters->getGPR(XEmuRegisters::GPR_R9, 8);
            default: {
                XADDR nRsp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, 8);
                // [rsp+0x00]=return, [rsp+0x08..0x20]=shadow space, [rsp+0x28]=arg5.
                return m_pMemoryManager->readQword(nRsp + 0x28 + (quint64)(nIndex - 4) * 8);
            }
        }
    }

    XADDR nEsp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
    return m_pMemoryManager->readDword(nEsp + 4 + (quint64)nIndex * 4);
}

void XEmuWinApi::_return(XEmuRegisters *pRegisters, quint64 nValue, int nArgCount)
{
    if (m_bIs64) {
        XADDR nRsp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, 8);
        XADDR nRet = m_pMemoryManager->readQword(nRsp);
        pRegisters->setGPR(XEmuRegisters::GPR_RSP, 8, nRsp + 8);  // caller cleans the arguments
        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 8, nValue);
        m_pArch->setPC(pRegisters, nRet);
    } else {
        XADDR nEsp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
        XADDR nRet = m_pMemoryManager->readDword(nEsp);
        pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, nEsp + 4 + (quint64)nArgCount * 4);  // stdcall: callee cleans
        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 4, nValue & 0xFFFFFFFF);
        m_pArch->setPC(pRegisters, nRet);
    }
}

QString XEmuWinApi::_readAnsi(XADDR nAddress, int nMax) const
{
    if (nAddress == 0) {
        return QString();
    }

    QByteArray baText;

    for (int i = 0; i < nMax; i++) {
        bool bOk = false;
        quint8 nChar = m_pMemoryManager->readByte(nAddress + i, &bOk);

        if (!bOk || (nChar == 0)) {
            break;
        }

        baText.append((char)nChar);
    }

    return QString::fromLatin1(baText);
}

XEmuMemoryManager::MEMORY_FLAGS XEmuWinApi::_flagsFromProtect(quint32 nProtect) const
{
    bool bExec = (nProtect & PAGE_EXECUTE_MASK) != 0;
    bool bWrite = (nProtect & PAGE_WRITE_MASK) != 0;
    bool bRead = (nProtect & PAGE_NOACCESS_V) == 0;  // everything except PAGE_NOACCESS is readable

    return XEmuMemoryManager::MEMORY_FLAGS(bRead || bWrite || bExec, bWrite, bExec);
}

XADDR XEmuWinApi::_moduleHandle(const QString &sLibraryLower, bool bCreate)
{
    if (m_mapModuleBase.contains(sLibraryLower)) {
        XADDR nBase = m_mapModuleBase.value(sLibraryLower);
        m_mapHandleName.insert(nBase, sLibraryLower);
        return nBase;
    }

    if (m_mapNameHandle.contains(sLibraryLower)) {
        return m_mapNameHandle.value(sLibraryLower);
    }

    if (!bCreate) {
        return 0;  // GetModuleHandleA semantics: not loaded
    }

    // Prefer a real synthetic module image + PEB Ldr entry from the OS layer; fall back
    // to an opaque cookie handle if unavailable.
    XADDR nHandle = 0;
    if (m_fnCreateModule) {
        nHandle = m_fnCreateModule(sLibraryLower);
    }
    if (nHandle == 0) {
        nHandle = m_nFakeHandleCursor;
        m_nFakeHandleCursor += 0x10000;
    }

    m_mapNameHandle.insert(sLibraryLower, nHandle);
    m_mapHandleName.insert(nHandle, sLibraryLower);

    return nHandle;
}

QString XEmuWinApi::_moduleName(XADDR nHandle) const
{
    if (m_mapHandleName.contains(nHandle)) {
        return m_mapHandleName.value(nHandle);
    }

    for (QMap<QString, XADDR>::const_iterator it = m_mapModuleBase.constBegin(); it != m_mapModuleBase.constEnd(); ++it) {
        if (it.value() == nHandle) {
            return it.key();
        }
    }

    return QStringLiteral("unknown.dll");
}

void XEmuWinApi::_apiVirtualAlloc(XEmuRegisters *pRegisters)
{
    XADDR nAddress = (XADDR)_arg(pRegisters, 0);
    quint64 nRegionSize = _arg(pRegisters, 1);
    quint32 nAllocationType = (quint32)_arg(pRegisters, 2);
    quint32 nProtect = (quint32)_arg(pRegisters, 3);

    Q_UNUSED(nAllocationType)

    if (nRegionSize == 0) {
        _return(pRegisters, 0, 4);
        return;
    }

    XEmuMemoryManager::MEMORY_FLAGS flags = _flagsFromProtect(nProtect);
    XADDR nBase = 0;

    if (nAddress != 0) {
        XADDR nAligned = XEmuMemoryManager::alignDown(nAddress, XEmuMemoryManager::N_PAGE_SIZE);
        quint64 nSize = XEmuMemoryManager::alignUp(nRegionSize + (nAddress - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

        if (m_pMemoryManager->isCommitted(nAligned, 1)) {
            // Already backed (e.g. a MEM_COMMIT over previously reserved space):
            // adjust protection and treat as success.
            m_pMemoryManager->protect(nAligned, nSize, flags);
            nBase = nAligned;
        } else {
            nBase = m_pMemoryManager->allocate(nAligned, nSize, flags, QStringLiteral("VirtualAlloc"));

            if (nBase == 0) {
                if (m_pMemoryManager->commit(nAligned, nSize, flags)) {
                    nBase = nAligned;
                }
            }

            if (nBase == 0) {
                // The exact address was unavailable; Windows would fail, but for
                // unpacking it is more useful to satisfy the request elsewhere.
                nBase = m_pMemoryManager->allocate(0, nSize, flags, QStringLiteral("VirtualAlloc"));
            }
        }
    } else {
        quint64 nSize = XEmuMemoryManager::alignUp(nRegionSize, XEmuMemoryManager::N_PAGE_SIZE);
        nBase = m_pMemoryManager->allocate(0, nSize, flags, QStringLiteral("VirtualAlloc"));
    }

    _log(QStringLiteral("VirtualAlloc(0x%1, 0x%2) = 0x%3").arg(nAddress, 0, 16).arg(nRegionSize, 0, 16).arg(nBase, 0, 16));
    _return(pRegisters, nBase, 4);
}

void XEmuWinApi::_apiVirtualProtect(XEmuRegisters *pRegisters)
{
    XADDR nAddress = (XADDR)_arg(pRegisters, 0);
    quint64 nRegionSize = _arg(pRegisters, 1);
    quint32 nNewProtect = (quint32)_arg(pRegisters, 2);
    XADDR nOldProtectPtr = (XADDR)_arg(pRegisters, 3);

    XADDR nAligned = XEmuMemoryManager::alignDown(nAddress, XEmuMemoryManager::N_PAGE_SIZE);
    quint64 nSize = XEmuMemoryManager::alignUp(nRegionSize + (nAddress - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

    bool bOk = m_pMemoryManager->protect(nAligned, nSize, _flagsFromProtect(nNewProtect));

    if (nOldProtectPtr != 0) {
        // Report a plausible previous protection (PAGE_EXECUTE_READWRITE). Packers
        // only require the pointer to be written, not an exact prior value.
        m_pMemoryManager->writeDword(nOldProtectPtr, 0x40);
    }

    _log(QStringLiteral("VirtualProtect(0x%1, 0x%2, 0x%3) = %4").arg(nAddress, 0, 16).arg(nRegionSize, 0, 16).arg(nNewProtect, 0, 16).arg(bOk ? 1 : 0));
    _return(pRegisters, bOk ? 1 : 0, 4);
}

void XEmuWinApi::_apiVirtualFree(XEmuRegisters *pRegisters)
{
    // BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) -- stdcall, 3 args.
    // Packer stubs call this to drop a scratch buffer once decompression is done. We report
    // success and, crucially, clean the 3 arguments off the stack (stdcall callee-cleanup);
    // failing to do so leaves ESP 0xC low and the caller's later RET lands on garbage. The
    // region is intentionally left mapped -- unmapping it here could fault later readers and
    // is not needed to run the stub to its OEP.
    XADDR nAddress = (XADDR)_arg(pRegisters, 0);
    quint64 nSize = _arg(pRegisters, 1);
    quint32 nFreeType = (quint32)_arg(pRegisters, 2);

    _log(QStringLiteral("VirtualFree(0x%1, 0x%2, 0x%3) = 1").arg(nAddress, 0, 16).arg(nSize, 0, 16).arg(nFreeType, 0, 16));
    _return(pRegisters, 1, 3);
}

void XEmuWinApi::_apiVirtualFreeEx(XEmuRegisters *pRegisters)
{
    // BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) -- stdcall, 4 args.
    // The emulated address space is process-global, so hProcess is ignored.
    // Keep the region mapped so later reads still succeed when callers reuse the pointer.
    XADDR nAddress = (XADDR)_arg(pRegisters, 1);
    quint64 nSize = _arg(pRegisters, 2);
    quint32 nFreeType = (quint32)_arg(pRegisters, 3);

    _log(QStringLiteral("VirtualFreeEx(0x%1, 0x%2, 0x%3) = 1").arg(nAddress, 0, 16).arg(nSize, 0, 16).arg(nFreeType, 0, 16));
    _return(pRegisters, 1, 4);
}

void XEmuWinApi::_apiVirtualProtectEx(XEmuRegisters *pRegisters)
{
    // BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
    // -- stdcall, 5 args.
    // The process handle is ignored; this emulates the current mapping directly.
    XADDR nAddress = (XADDR)_arg(pRegisters, 1);
    quint64 nRegionSize = _arg(pRegisters, 2);
    quint32 nNewProtect = (quint32)_arg(pRegisters, 3);
    XADDR nOldProtectPtr = (XADDR)_arg(pRegisters, 4);

    XADDR nAligned = XEmuMemoryManager::alignDown(nAddress, XEmuMemoryManager::N_PAGE_SIZE);
    quint64 nSize = XEmuMemoryManager::alignUp(nRegionSize + (nAddress - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

    bool bOk = m_pMemoryManager->protect(nAligned, nSize, _flagsFromProtect(nNewProtect));

    if (nOldProtectPtr != 0) {
        m_pMemoryManager->writeDword(nOldProtectPtr, 0x40);
    }

    _log(QStringLiteral("VirtualProtectEx(0x%1, 0x%2, 0x%3, 0x%4) = %5").arg(nAddress, 0, 16).arg(nRegionSize, 0, 16).arg(nNewProtect, 0, 16).arg(nOldProtectPtr, 0, 16).arg(bOk ? 1 : 0));
    _return(pRegisters, bOk ? 1 : 0, 5);
}

void XEmuWinApi::_apiLoadLibraryA(XEmuRegisters *pRegisters)
{
    XADDR nNamePtr = (XADDR)_arg(pRegisters, 0);

    if (nNamePtr == 0) {
        _return(pRegisters, 0, 1);
        return;
    }

    QString sName = _readAnsi(nNamePtr).toLower();

    // Windows appends ".dll" when the name carries no extension.
    if (!sName.contains(QLatin1Char('.'))) {
        sName += QStringLiteral(".dll");
    }

    XADDR nHandle = _moduleHandle(sName, true);

    _log(QStringLiteral("LoadLibraryA(\"%1\") = 0x%2").arg(sName).arg(nHandle, 0, 16));
    _return(pRegisters, nHandle, 1);
}

void XEmuWinApi::_apiLoadLibraryExA(XEmuRegisters *pRegisters)
{
    XADDR nNamePtr = (XADDR)_arg(pRegisters, 0);

    if (nNamePtr == 0) {
        _return(pRegisters, 0, 3);
        return;
    }

    QString sName = _readAnsi(nNamePtr).toLower();

    // Windows appends ".dll" when the name carries no extension.
    if (!sName.contains(QLatin1Char('.'))) {
        sName += QStringLiteral(".dll");
    }

    XADDR nHandle = _moduleHandle(sName, true);

    _log(QStringLiteral("LoadLibraryExA(\"%1\") = 0x%2").arg(sName).arg(nHandle, 0, 16));
    _return(pRegisters, nHandle, 3);
}

void XEmuWinApi::_apiGetModuleHandleA(XEmuRegisters *pRegisters)
{
    XADDR nNamePtr = (XADDR)_arg(pRegisters, 0);

    if (nNamePtr == 0) {
        // GetModuleHandleA(NULL) returns the base of the calling process image.
        _log(QStringLiteral("GetModuleHandleA(NULL) = 0x%1").arg(m_nMainModuleBase, 0, 16));
        _return(pRegisters, m_nMainModuleBase, 1);
        return;
    }

    QString sName = _readAnsi(nNamePtr).toLower();
    if (!sName.contains(QLatin1Char('.'))) {
        sName += QStringLiteral(".dll");
    }

    // Unlike LoadLibraryA, GetModuleHandleA does not load: return a handle only if the
    // module is already mapped/loaded, else 0.
    XADDR nHandle = _moduleHandle(sName, false);

    _log(QStringLiteral("GetModuleHandleA(\"%1\") = 0x%2").arg(sName).arg(nHandle, 0, 16));
    _return(pRegisters, nHandle, 1);
}

void XEmuWinApi::_allocReturn(XEmuRegisters *pRegisters, quint64 nSize, int nArgCount, const QString &sName)
{
    XADDR nBase = 0;

    if (nSize > 0) {
        quint64 nAligned = XEmuMemoryManager::alignUp(nSize, XEmuMemoryManager::N_PAGE_SIZE);
        // R/W/X: a decompression buffer is written and often executed from.
        nBase = m_pMemoryManager->allocate(0, nAligned, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), sName);
        if (nBase) m_heapSizes.insert(nBase, nSize);   // remember the requested size for HeapSize/RtlSizeHeap
    }

    _log(QStringLiteral("%1(0x%2) = 0x%3").arg(sName).arg(nSize, 0, 16).arg(nBase, 0, 16));
    _return(pRegisters, nBase, nArgCount);
}

void XEmuWinApi::_apiGlobalAlloc(XEmuRegisters *pRegisters)
{
    // HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes) -- stdcall, 2 args. Modelled as a
    // GMEM_FIXED allocation returning a usable pointer (freshly committed memory is zero,
    // satisfying GMEM_ZEROINIT). GMEM_MOVEABLE handles are not distinguished.
    _allocReturn(pRegisters, _arg(pRegisters, 1), 2, QStringLiteral("GlobalAlloc"));
}

void XEmuWinApi::_apiLocalAlloc(XEmuRegisters *pRegisters)
{
    // LPVOID LocalAlloc(UINT uFlags, SIZE_T uBytes) -- stdcall, 2 args.
    _allocReturn(pRegisters, _arg(pRegisters, 1), 2, QStringLiteral("LocalAlloc"));
}

void XEmuWinApi::_apiHeapAlloc(XEmuRegisters *pRegisters)
{
    // LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) -- stdcall, 3 args.
    _allocReturn(pRegisters, _arg(pRegisters, 2), 3, QStringLiteral("HeapAlloc"));
}

void XEmuWinApi::_apiGlobalFree(XEmuRegisters *pRegisters)
{
    // HGLOBAL GlobalFree(HGLOBAL hMem) -- stdcall, 1 arg. Returns NULL on success.
    _log(QStringLiteral("GlobalFree(0x%1)").arg(_arg(pRegisters, 0), 0, 16));
    _return(pRegisters, 0, 1);
}

void XEmuWinApi::_apiLocalFree(XEmuRegisters *pRegisters)
{
    // HLOCAL LocalFree(HLOCAL hMem) -- stdcall, 1 arg. Returns NULL on success.
    _log(QStringLiteral("LocalFree(0x%1)").arg(_arg(pRegisters, 0), 0, 16));
    _return(pRegisters, 0, 1);
}

void XEmuWinApi::_apiHeapFree(XEmuRegisters *pRegisters)
{
    // BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) -- stdcall, 3 args.
    _log(QStringLiteral("HeapFree(0x%1)").arg(_arg(pRegisters, 2), 0, 16));
    _return(pRegisters, 1, 3);
}

void XEmuWinApi::_apiGetProcAddress(XEmuRegisters *pRegisters)
{
    XADDR nModule = (XADDR)_arg(pRegisters, 0);
    XADDR nProcName = (XADDR)_arg(pRegisters, 1);

    QString sModule = _moduleName(nModule);
    QString sFunc;
    qint64 nOrdinal = -1;

    if (nProcName <= 0xFFFF) {
        // Imported by ordinal (name pointer is really MAKEINTRESOURCE(ordinal)).
        nOrdinal = (qint64)(nProcName & 0xFFFF);
        sFunc = QStringLiteral("#%1").arg(nOrdinal);
    } else {
        sFunc = _readAnsi(nProcName);
    }

    static const bool bApiLog = !qEnvironmentVariableIsEmpty("XEMU_APILOG");
    if (bApiLog) {
        QByteArray sFuncBytes = sFunc.toLatin1();
        fprintf(stderr, "[GPA-RAW] procName=0x%llx module=\"%s\" text=\"%s\"\n", (unsigned long long)nProcName, sModule.toLatin1().constData(), sFuncBytes.constData());
        fflush(stderr);
    }

    // Hand back a trampoline so the packer's rebuilt IAT holds a resolvable,
    // dispatchable address for the function.
    XADDR nStub = stubFor(sModule, sFunc, nOrdinal);

    _log(QStringLiteral("GetProcAddress(\"%1\", \"%2\") = 0x%3").arg(sModule, sFunc).arg(nStub, 0, 16));
    _return(pRegisters, nStub, 2);
}

void XEmuWinApi::_apiExitProcess(XEmuRegisters *pRegisters)
{
    // ExitProcess(uExitCode) / TerminateProcess: the guest is terminating. Record it so
    // the emulator stops cleanly on this step (the trampoline is never really "returned"
    // from). Don't touch the stack -- there is no return.
    const quint64 nCode = _arg(pRegisters, 0);
    m_bProcessExited = true;
    _log(QStringLiteral("ExitProcess(0x%1)").arg(nCode, 0, 16));
}

void XEmuWinApi::_apiCreateFile(XEmuRegisters *pRegisters)
{
    // CreateFileA/W(lpFileName, access, share, sec, disp, flags, hTemplate) -- 7 stdcall args.
    // Not backed by a real filesystem, so opens fail. Critically, a failed CreateFile returns
    // INVALID_HANDLE_VALUE (0xFFFFFFFF), NOT 0 (the generic no-op's value): packers probe for
    // kernel debuggers by opening device names like "\\.\SICE" / "\\.\NTICE" and branch on the
    // result; a bogus 0 (impossible from real CreateFile) sends them down an error path
    // (e.g. REVProt clobbers its relocation-base register and faults). -1 = "device absent" =
    // no debugger, which is what an un-instrumented run should report.
    const QString sName = _readAnsi((XADDR)_arg(pRegisters, 0));
    _log(QStringLiteral("CreateFile(\"%1\") = INVALID_HANDLE_VALUE").arg(sName));
    _return(pRegisters, 0xFFFFFFFFu, 7);
}

bool XEmuWinApi::_apiByName(XEmuRegisters *pRegisters, const QString &sFunc)
{
    if (sFunc.isEmpty()) {
        return false;
    }
    const XADDR a1 = (XADDR)_arg(pRegisters, 1);
    const XADDR a2 = (XADDR)_arg(pRegisters, 2);

    // --- environment / anti-analysis probes (return value + output buffer + stdcall cleanup) ---
    if (sFunc == QStringLiteral("IsWow64Process")) {              // BOOL(HANDLE, PBOOL)
        if (a1) m_pMemoryManager->writeDword(a1, 1);             // yes: a 32-bit process on 64-bit Windows (matches the real reference)
        _return(pRegisters, 1, 2);
        return true;
    }
    if (sFunc == QStringLiteral("GetProcessAffinityMask")) {      // BOOL(HANDLE, PDWORD, PDWORD)
        if (a1) m_pMemoryManager->writeDword(a1, 1);
        if (a2) m_pMemoryManager->writeDword(a2, 1);
        _return(pRegisters, 1, 3);
        return true;
    }
    if (sFunc == QStringLiteral("SetProcessAffinityMask")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("SetThreadAffinityMask")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("VirtualQuery")) {               // SIZE_T(LPCVOID, PMBI, SIZE_T) -- 32-bit MBI is 0x1C
        const XADDR nAddr = (XADDR)_arg(pRegisters, 0);
        if (a1) {
            m_pMemoryManager->writeDword(a1 + 0x00, (quint32)(nAddr & ~0xFFFu));  // BaseAddress
            m_pMemoryManager->writeDword(a1 + 0x04, (quint32)(nAddr & ~0xFFFu));  // AllocationBase
            m_pMemoryManager->writeDword(a1 + 0x08, 0x40);                        // AllocationProtect = PAGE_EXECUTE_READWRITE
            m_pMemoryManager->writeDword(a1 + 0x0C, 0x1000);                      // RegionSize
            m_pMemoryManager->writeDword(a1 + 0x10, 0x1000);                      // State = MEM_COMMIT
            m_pMemoryManager->writeDword(a1 + 0x14, 0x40);                        // Protect = PAGE_EXECUTE_READWRITE
            m_pMemoryManager->writeDword(a1 + 0x18, 0x20000);                     // Type = MEM_PRIVATE
        }
        _return(pRegisters, 0x1C, 3);
        return true;
    }
    if (sFunc == QStringLiteral("GetCommandLineA")) {   // LPSTR GetCommandLineA()
        static const char psz[] = "xvolkolakc";
        static XADDR nAddress = 0;
        if (nAddress == 0) {
            nAddress = m_pMemoryManager->allocate(0, (XADDR)(sizeof(psz)), XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("GetCommandLineA"));
            if (nAddress != 0) {
                for (int i = 0; i < (int)sizeof(psz); i++) {
                    m_pMemoryManager->writeByte(nAddress + (XADDR)i, (quint8)psz[i]);
                }
            }
        }
        _return(pRegisters, nAddress, 0);
        return true;
    }
    if (sFunc == QStringLiteral("GetCommandLineW")) {   // LPWSTR GetCommandLineW()
        static const char psz[] = "xvolkolakc";
        static XADDR nAddress = 0;
        if (nAddress == 0) {
            nAddress = m_pMemoryManager->allocate(0, (XADDR)(sizeof(psz) * 2 + 2), XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("GetCommandLineW"));
            if (nAddress != 0) {
                for (int i = 0; i < (int)sizeof(psz) - 1; i++) {
                    m_pMemoryManager->writeWord(nAddress + (XADDR)i * 2, (quint8)psz[i]);
                }
                m_pMemoryManager->writeWord(nAddress + (XADDR)(sizeof(psz) - 1) * 2, 0);
            }
        }
        _return(pRegisters, nAddress, 0);
        return true;
    }
    if ((sFunc == QStringLiteral("GetEnvironmentStrings")) || (sFunc == QStringLiteral("GetEnvironmentStringsA"))) {
        static const char env[] = "OS=Windows_NT\0\0";
        static XADDR nAddress = 0;
        if (nAddress == 0) {
            nAddress = m_pMemoryManager->allocate(0, (XADDR)(sizeof(env)), XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("GetEnvironmentStringsA"));
            if (nAddress != 0) {
                for (int i = 0; i < (int)sizeof(env); i++) {
                    m_pMemoryManager->writeByte(nAddress + (XADDR)i, (quint8)env[i]);
                }
            }
        }
        _return(pRegisters, nAddress, 0);
        return true;
    }
    if (sFunc == QStringLiteral("GetEnvironmentStringsW")) {
        static const char env[] = "O\0S\0=\0W\0i\0n\0d\0o\0w\0s\0_\0N\0T\0\0\0\0";
        static XADDR nAddress = 0;
        if (nAddress == 0) {
            nAddress = m_pMemoryManager->allocate(0, (XADDR)(sizeof(env)), XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("GetEnvironmentStringsW"));
            if (nAddress != 0) {
                for (int i = 0; i < (int)sizeof(env); i++) {
                    m_pMemoryManager->writeByte(nAddress + (XADDR)i, (quint8)env[i]);
                }
            }
        }
        _return(pRegisters, nAddress, 0);
        return true;
    }
    if ((sFunc == QStringLiteral("FreeEnvironmentStrings")) || (sFunc == QStringLiteral("FreeEnvironmentStringsA")) || (sFunc == QStringLiteral("FreeEnvironmentStringsW"))) { _return(pRegisters, 1, 1); return true; }

    // --- heap: a failed HeapCreate (generic no-op -> 0) makes the CRT/RTL memory-manager init
    //     fail, which VMProtect surfaces as ExitProcess(0xDEADC0DE) (its anti-analysis bail). Hand
    //     out a valid fake heap handle; HeapAlloc/Free below ignore the handle and use real memory.
    if (sFunc == QStringLiteral("HeapCreate")) { _return(pRegisters, 0x00E70000u, 3); return true; }   // HANDLE(flOptions, dwInit, dwMax)
    if (sFunc == QStringLiteral("GetProcessHeap")) { _return(pRegisters, 0x00E70000u, 0); return true; }
    if (sFunc == QStringLiteral("HeapDestroy")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("HeapReAlloc")) { _allocReturn(pRegisters, (quint64)_arg(pRegisters, 3), 4, QStringLiteral("HeapReAlloc")); return true; }
    if (sFunc == QStringLiteral("HeapSize")) {   // SIZE_T(hHeap, dwFlags, lpMem) -- real size if we tracked it, else 0x1000
        _return(pRegisters, m_heapSizes.value((XADDR)_arg(pRegisters, 2), 0x1000), 3); return true;
    }
    if (sFunc == QStringLiteral("HeapValidate")) { _return(pRegisters, 1, 3); return true; }
    if (sFunc == QStringLiteral("HeapSetInformation")) { _return(pRegisters, 1, 4); return true; }
    if (sFunc == QStringLiteral("GetProcessHeaps")) {   // DWORD(NumberOfHeaps, HANDLE* ProcessHeaps) -- write the one heap
        if (_arg(pRegisters, 0) >= 1 && _arg(pRegisters, 1)) m_pMemoryManager->writeDword((XADDR)_arg(pRegisters, 1), 0x00E70000u);
        _return(pRegisters, 1, 2); return true;
    }
    // ntdll heap allocator (kernel32 HeapAlloc/Free forward here; the CRT also calls it directly).
    // A generic no-op -> 0 fails the allocation -> CRT init unwinds -> VMProtect ExitProcess(0xDEADC0DE).
    if (sFunc == QStringLiteral("RtlAllocateHeap")) { _allocReturn(pRegisters, (quint64)_arg(pRegisters, 2), 3, QStringLiteral("RtlAllocateHeap")); return true; }   // (heap, flags, size)
    if (sFunc == QStringLiteral("RtlReAllocateHeap")) { _allocReturn(pRegisters, (quint64)_arg(pRegisters, 3), 4, QStringLiteral("RtlReAllocateHeap")); return true; } // (heap, flags, ptr, size)
    if (sFunc == QStringLiteral("RtlFreeHeap")) { _return(pRegisters, 1, 3); return true; }
    if (sFunc == QStringLiteral("RtlSizeHeap")) { _return(pRegisters, m_heapSizes.value((XADDR)_arg(pRegisters, 2), 0x1000), 3); return true; }
    // Fiber-local storage (the MSVC CRT startup allocates an FLS slot; 0 is a VALID index, but
    // FlsAlloc failure is FLS_OUT_OF_INDEXES (0xFFFFFFFF) -> hand out a small non-zero index).
    if (sFunc == QStringLiteral("FlsAlloc")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("FlsFree")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("FlsSetValue")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("FlsGetValue")) { _return(pRegisters, 0, 1); return true; }

    // --- version ---
    if (sFunc == QStringLiteral("GetVersion")) { _return(pRegisters, 0x23F00206u, 0); return true; }  // 6.2 build 9200
    if ((sFunc == QStringLiteral("GetVersionExA")) || (sFunc == QStringLiteral("GetVersionExW"))) {    // BOOL(LPOSVERSIONINFO)
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) { m_pMemoryManager->writeDword(p + 0x04, 6); m_pMemoryManager->writeDword(p + 0x08, 2); m_pMemoryManager->writeDword(p + 0x0C, 9200); m_pMemoryManager->writeDword(p + 0x10, 2); }
        _return(pRegisters, 1, 1);
        return true;
    }

    // --- identity / timing ---
    if (sFunc == QStringLiteral("GetCurrentProcess")) { _return(pRegisters, 0xFFFFFFFFu, 0); return true; }
    if (sFunc == QStringLiteral("GetCurrentThread")) { _return(pRegisters, 0xFFFFFFFEu, 0); return true; }
    if (sFunc == QStringLiteral("GetCurrentProcessId")) { _return(pRegisters, 0x00001230u, 0); return true; }
    if (sFunc == QStringLiteral("GetCurrentThreadId")) { _return(pRegisters, 0x00001234u, 0); return true; }
    if (sFunc == QStringLiteral("GetTickCount")) { _return(pRegisters, 0x00100000u, 0); return true; }
    if (sFunc == QStringLiteral("GetLocalTime")) {
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) {
            m_pMemoryManager->writeWord(p + 0x00, 2026); // wYear
            m_pMemoryManager->writeWord(p + 0x02, 8);    // wMonth
            m_pMemoryManager->writeWord(p + 0x04, 3);    // wDayOfWeek
            m_pMemoryManager->writeWord(p + 0x06, 1);    // wDay
            m_pMemoryManager->writeWord(p + 0x08, 12);   // wHour
            m_pMemoryManager->writeWord(p + 0x0A, 34);   // wMinute
            m_pMemoryManager->writeWord(p + 0x0C, 56);   // wSecond
            m_pMemoryManager->writeWord(p + 0x0E, 0);    // wMilliseconds
        }
        _return(pRegisters, 0, 1);
        return true;
    }
    if (sFunc == QStringLiteral("QueryPerformanceCounter")) {    // BOOL(LARGE_INTEGER*)
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) { m_pMemoryManager->writeDword(p, 0x00100000); m_pMemoryManager->writeDword(p + 4, 0); }
        _return(pRegisters, 1, 1);
        return true;
    }
    if (sFunc == QStringLiteral("QueryPerformanceFrequency")) {
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) { m_pMemoryManager->writeDword(p, 0x00989680); m_pMemoryManager->writeDword(p + 4, 0); }  // 10 MHz
        _return(pRegisters, 1, 1);
        return true;
    }
    if (sFunc == QStringLiteral("GetSystemTimeAsFileTime")) {    // void(LPFILETIME)
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) { m_pMemoryManager->writeDword(p, 0); m_pMemoryManager->writeDword(p + 4, 0x01DA0000); }
        _return(pRegisters, 0, 1);
        return true;
    }
    if (sFunc == QStringLiteral("GetDateFormatA")) {
        const XADDR pBuf = (XADDR)_arg(pRegisters, 3);
        const quint32 nChars = (quint32)_arg(pRegisters, 4);
        static const char sDate[] = "2026-08-01";
        int i = 0;
        if (pBuf && (nChars >= 1)) {
            for (; sDate[i] && (i + 1 < (int)nChars); i++) {
                m_pMemoryManager->writeByte(pBuf + (XADDR)i, (quint8)sDate[i]);
            }
            m_pMemoryManager->writeByte(pBuf + (XADDR)i, 0);
            _return(pRegisters, (quint32)i + 1, 6);
        } else {
            _return(pRegisters, 11, 6);
        }
        return true;
    }
    if (sFunc == QStringLiteral("GetCPInfo")) {
        const XADDR pInfo = (XADDR)_arg(pRegisters, 1);
        if (pInfo) {
            m_pMemoryManager->writeByte(pInfo + 0x00, 1); // MaxCharSize
            m_pMemoryManager->writeWord(pInfo + 0x02, 0);
            for (int i = 4; i < 20; i++) {
                m_pMemoryManager->writeByte(pInfo + (XADDR)i, 0);
            }
        }
        _return(pRegisters, 1, 2);
        return true;
    }
    if (sFunc == QStringLiteral("GlobalMemoryStatus")) {      // BOOL(LPMEMORYSTATUS)
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) {
            m_pMemoryManager->writeDword(p + 0x00, 0x20);
            m_pMemoryManager->writeDword(p + 0x04, 1);
            m_pMemoryManager->writeDword(p + 0x08, 0x7FFFFFFFu);
            m_pMemoryManager->writeDword(p + 0x0C, 0x00100000u);
            m_pMemoryManager->writeDword(p + 0x10, 0x00100000u);
            m_pMemoryManager->writeDword(p + 0x14, 0x00100000u);
            m_pMemoryManager->writeDword(p + 0x18, 0x00100000u);
            m_pMemoryManager->writeDword(p + 0x1C, 0);
            m_pMemoryManager->writeDword(p + 0x20, 0);
        }
        _return(pRegisters, 1, 1);
        return true;
    }

    // --- TLS ---
    if (sFunc == QStringLiteral("TlsAlloc")) { _return(pRegisters, 1, 0); return true; }
    if (sFunc == QStringLiteral("TlsSetValue")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("TlsGetValue")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("TlsFree")) { _return(pRegisters, 1, 1); return true; }

    // --- misc no-ops with a success return ---
    if (sFunc == QStringLiteral("Sleep")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("SleepEx")) { _return(pRegisters, 0, 2); return true; }
    if (sFunc == QStringLiteral("FreeLibrary")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("OpenProcess")) { _return(pRegisters, 0x00E70000u, 4); return true; }
    if (sFunc == QStringLiteral("SetErrorMode")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("CloseHandle")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("SetConsoleCtrlHandler")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("SetFilePointer")) { _return(pRegisters, 0, 4); return true; }
    if (sFunc == QStringLiteral("SetHandleCount")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("SetEnvironmentVariableA")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("SetStdHandle")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("SetUnhandledExceptionFilter")) { _return(pRegisters, 0, 1); return true; }
    // A process emulated here is not attached to a debugger. Windows therefore returns
    // EXCEPTION_EXECUTE_HANDLER (1); zero is EXCEPTION_CONTINUE_SEARCH and is reserved for
    // the debugger-present path. Returning zero makes Delphi's top-level filter ask the SEH
    // dispatcher to resume the faulting instruction, producing an endless exception loop.
    if (sFunc == QStringLiteral("UnhandledExceptionFilter")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("CharUpperA")) { _return(pRegisters, (quint32)_arg(pRegisters, 0), 1); return true; }
    if (sFunc == QStringLiteral("CreateEventA")) { _return(pRegisters, 0x00E70000u, 4); return true; }
    if (sFunc == QStringLiteral("CreateEventW")) { _return(pRegisters, 0x00E70000u, 4); return true; }
    if (sFunc == QStringLiteral("RaiseException")) { _return(pRegisters, 0, 4); return true; }
    if (sFunc == QStringLiteral("RtlUnwind")) { _return(pRegisters, 0, 4); return true; }
    if (sFunc == QStringLiteral("FindFirstFileA")) { _return(pRegisters, 0x00E70100u, 2); return true; }
    if (sFunc == QStringLiteral("FindNextFileA")) { _return(pRegisters, 0, 2); return true; }
    if (sFunc == QStringLiteral("FindClose")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("FileTimeToDosDateTime")) { _return(pRegisters, 1, 3); return true; }
    if (sFunc == QStringLiteral("EnumThreadWindows")) { _return(pRegisters, 0, 3); return true; }
    if (sFunc == QStringLiteral("EnumWindows")) { _return(pRegisters, 0, 4); return true; }
    if (sFunc == QStringLiteral("EnumDesktopWindows")) { _return(pRegisters, 0, 3); return true; }
    if ((sFunc == QStringLiteral("CreateProcessA")) || (sFunc == QStringLiteral("CreateProcessW"))) {
        const XADDR pProcessInformation = (XADDR)_arg(pRegisters, 9);
        if (pProcessInformation) {
            // PROCESS_INFORMATION{hProcess,hThread,dwProcessId,dwThreadId}
            m_pMemoryManager->writeDword(pProcessInformation + 0x00, 0x00E70000u);
            m_pMemoryManager->writeDword(pProcessInformation + 0x04, 0x00E70000u);
            m_pMemoryManager->writeDword(pProcessInformation + 0x08, 0x1234u);
            m_pMemoryManager->writeDword(pProcessInformation + 0x0C, 0x1235u);
        }
        _return(pRegisters, 1, 10);
        return true;
    }
    if (sFunc == QStringLiteral("WaitForSingleObject")) { _return(pRegisters, 0, 2); return true; }
    if (sFunc == QStringLiteral("GetLastError")) { _return(pRegisters, 0, 0); return true; }
    if (sFunc == QStringLiteral("SetLastError")) { _return(pRegisters, 0, 1); return true; }

    // --- module path / name ---
    if ((sFunc == QStringLiteral("GetModuleFileNameA")) || (sFunc == QStringLiteral("GetModuleFileNameW"))) {
        const bool bW = sFunc.endsWith(QLatin1Char('W'));
        const XADDR nBuf = a1;
        const quint32 nSize = (quint32)_arg(pRegisters, 2);
        static const char kPath[] = "C:\\delphi32_1.exe";
        const int nLen = (int)sizeof(kPath) - 1;
        int nWritten = 0;
        if (nBuf && nSize) {
            for (; (nWritten < nLen) && ((quint32)nWritten < nSize - 1); nWritten++) {
                if (bW) m_pMemoryManager->writeWord(nBuf + (XADDR)nWritten * 2, (quint8)kPath[nWritten]);
                else m_pMemoryManager->writeByte(nBuf + (XADDR)nWritten, (quint8)kPath[nWritten]);
            }
            if (bW) m_pMemoryManager->writeWord(nBuf + (XADDR)nWritten * 2, 0);
            else m_pMemoryManager->writeByte(nBuf + (XADDR)nWritten, 0);
        }
        _return(pRegisters, (quint32)nWritten, 3);
        return true;
    }
    if (sFunc == QStringLiteral("GetModuleHandleW")) {  // HMODULE(LPCWSTR) -- NULL -> main image; else resolve by name
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p == 0) { _return(pRegisters, m_nMainModuleBase, 1); return true; }
        QString sName;                                   // read the UTF-16 module name
        for (int i = 0; i < 260; i++) {
            bool okc = false; const quint16 wc = (quint16)m_pMemoryManager->readWord(p + (XADDR)(i * 2), &okc);
            if (!okc || wc == 0) break;
            sName += QChar(wc);
        }
        sName = sName.toLower();
        if (!sName.contains(QLatin1Char('.'))) sName += QStringLiteral(".dll");
        const XADDR nHandle = _moduleHandle(sName, false);   // resolve only (don't create), matching GetModuleHandleA
        _log(QStringLiteral("GetModuleHandleW(\"%1\") = 0x%2").arg(sName).arg(nHandle, 0, 16));
        _return(pRegisters, nHandle, 1);
        return true;
    }
    // EncodePointer/DecodePointer: the CRT/RTL obfuscates stored function pointers with these; a
    // generic no-op (->0) destroys the pointer and later DecodePointer(0) faults -> VMProtect bails.
    // Model as identity (no real obfuscation needed): the round-trip is preserved.
    if ((sFunc == QStringLiteral("EncodePointer")) || (sFunc == QStringLiteral("DecodePointer"))
        || (sFunc == QStringLiteral("EncodeSystemPointer")) || (sFunc == QStringLiteral("DecodeSystemPointer"))) {
        _return(pRegisters, (quint32)_arg(pRegisters, 0), 1);
        return true;
    }

    // --- system info / locale / cpu features ---
    if ((sFunc == QStringLiteral("GetStartupInfoA")) || (sFunc == QStringLiteral("GetStartupInfoW"))) {
        const XADDR p = (XADDR)_arg(pRegisters, 0);  // STARTUPINFO: 0x44 bytes on x86
        if (p) { for (int i = 0; i < 0x44; i += 4) m_pMemoryManager->writeDword(p + (XADDR)i, 0); m_pMemoryManager->writeDword(p, 0x44); }
        _return(pRegisters, 0, 1);
        return true;
    }
    if (sFunc == QStringLiteral("GetSystemInfo")) {     // void(LPSYSTEM_INFO) -- 0x24 bytes on x86
        const XADDR p = (XADDR)_arg(pRegisters, 0);
        if (p) {
            for (int i = 0; i < 0x24; i += 4) m_pMemoryManager->writeDword(p + (XADDR)i, 0);
            m_pMemoryManager->writeDword(p + 0x04, 0x1000);       // dwPageSize
            m_pMemoryManager->writeDword(p + 0x08, 0x00010000);   // lpMinimumApplicationAddress
            m_pMemoryManager->writeDword(p + 0x0C, 0x7FFE0000);   // lpMaximumApplicationAddress
            m_pMemoryManager->writeDword(p + 0x10, 1);            // dwActiveProcessorMask
            m_pMemoryManager->writeDword(p + 0x14, 1);            // dwNumberOfProcessors
            m_pMemoryManager->writeDword(p + 0x18, 586);          // dwProcessorType
            m_pMemoryManager->writeDword(p + 0x1C, 0x10000);      // dwAllocationGranularity
        }
        _return(pRegisters, 0, 1);
        return true;
    }
    if (sFunc == QStringLiteral("GetACP")) { _return(pRegisters, 1252, 0); return true; }
    if (sFunc == QStringLiteral("GetOEMCP")) { _return(pRegisters, 437, 0); return true; }
    if (sFunc == QStringLiteral("IsProcessorFeaturePresent")) { _return(pRegisters, 1, 1); return true; }
    if (sFunc == QStringLiteral("IsDebuggerPresent")) { _return(pRegisters, 0, 0); return true; }
    if (sFunc == QStringLiteral("CheckRemoteDebuggerPresent")) {  // BOOL(HANDLE, PBOOL)
        if (a1) m_pMemoryManager->writeDword(a1, 0);
        _return(pRegisters, 1, 2);
        return true;
    }
    if ((sFunc == QStringLiteral("GetCurrentDirectoryA")) || (sFunc == QStringLiteral("GetCurrentDirectoryW"))) {
        const bool bW = sFunc.endsWith(QLatin1Char('W'));
        const XADDR nBuf = a1;  // (nSize, lpBuffer)
        if (nBuf) {
            const char *d = "C:\\";
            for (int i = 0; i < 3; i++) { if (bW) m_pMemoryManager->writeWord(nBuf + (XADDR)i * 2, (quint8)d[i]); else m_pMemoryManager->writeByte(nBuf + (XADDR)i, (quint8)d[i]); }
            if (bW) m_pMemoryManager->writeWord(nBuf + 6, 0); else m_pMemoryManager->writeByte(nBuf + 3, 0);
        }
        _return(pRegisters, 3, 2);
        return true;
    }

    // --- console I/O (PPUPX and other console stubs) -------------------------------------------
    // These were unmodeled, so dispatch fell to the generic no-op _return(pR,0,0), which cleans
    // ZERO stdcall args and corrupts ESP -> the caller's next `pop`/`ret` grabs a stale value and
    // faults. The RETURN value is secondary; passing the correct stdcall arg count to _return is
    // the actual fix.
    if (sFunc == QStringLiteral("GetStdHandle")) { _return(pRegisters, 0x00000010u, 1); return true; }   // any non-null pseudo-handle
    if (sFunc == QStringLiteral("GetConsoleMode")) { if (a2) m_pMemoryManager->writeDword(a2, 0x1F7); _return(pRegisters, 1, 2); return true; }  // BOOL(hCon, lpMode)
    if (sFunc == QStringLiteral("SetConsoleMode")) { _return(pRegisters, 1, 2); return true; }
    if ((sFunc == QStringLiteral("WriteFile")) || (sFunc == QStringLiteral("WriteConsoleA")) || (sFunc == QStringLiteral("WriteConsoleW"))) {
        // BOOL(hFile, buf, nToWrite, lpWritten, lpOverlapped/lpReserved) -- report all bytes written.
        const quint32 nToWrite = (quint32)_arg(pRegisters, 2);
        const XADDR nWritten = (XADDR)_arg(pRegisters, 3);
        if (nWritten) m_pMemoryManager->writeDword(nWritten, nToWrite);
        _return(pRegisters, 1, 5);
        return true;
    }
    if ((sFunc == QStringLiteral("ReadFile")) || (sFunc == QStringLiteral("ReadConsoleA")) || (sFunc == QStringLiteral("ReadConsoleW"))) {
        const XADDR nRead = (XADDR)_arg(pRegisters, 3);   // lpNumberOfBytesRead
        if (nRead) m_pMemoryManager->writeDword(nRead, 0);  // EOF: 0 bytes
        _return(pRegisters, 1, 5);
        return true;
    }
    if (sFunc == QStringLiteral("MultiByteToWideChar")) {
        const XADDR pSrc = (XADDR)_arg(pRegisters, 2);
        const int nSrcLen = (int)_arg(pRegisters, 3);
        const XADDR pDst = (XADDR)_arg(pRegisters, 4);
        const int nDstLen = (int)_arg(pRegisters, 5);
        int nWritten = 0;
        if (nSrcLen >= 0) {
            for (int i = 0; (i < nSrcLen) && (nWritten < nDstLen); i++, nWritten++) {
                if (pDst) m_pMemoryManager->writeWord(pDst + (XADDR)nWritten * 2, (quint16)m_pMemoryManager->readByte(pSrc + (XADDR)i));
            }
        } else {
            int i = 0;
            if (pSrc) {
                while (true) {
                    quint8 ch = m_pMemoryManager->readByte(pSrc + (XADDR)i);
                    if (ch == 0) {
                        break;
                    }
                    if (pDst && (nWritten < nDstLen)) {
                        m_pMemoryManager->writeWord(pDst + (XADDR)nWritten * 2, (quint16)ch);
                    }
                    i++;
                    nWritten++;
                }
            }
        }
        if (pDst && (nWritten < nDstLen)) {
            m_pMemoryManager->writeWord(pDst + (XADDR)nWritten * 2, 0);
            nWritten++;
        }
        _return(pRegisters, nWritten, 6);
        return true;
    }
    if (sFunc == QStringLiteral("WideCharToMultiByte")) {
        const XADDR pSrc = (XADDR)_arg(pRegisters, 2);
        const int nSrcLen = (int)_arg(pRegisters, 3);
        const XADDR pDst = (XADDR)_arg(pRegisters, 4);
        const int nDstLen = (int)_arg(pRegisters, 5);
        int nWritten = 0;
        if (nSrcLen == -1) {
            if (pSrc) {
                int i = 0;
                for (; true; i++) {
                    quint16 ch = (quint16)m_pMemoryManager->readWord(pSrc + (XADDR)i * 2);
                    if (pSrc && (nWritten < nDstLen)) {
                        m_pMemoryManager->writeByte(pDst + (XADDR)nWritten, (quint8)(ch & 0xFF));
                    }
                    nWritten++;
                    if (ch == 0) {
                        break;
                    }
                }
            }
        } else {
            for (int i = 0; i < nSrcLen; i++) {
                if (pDst && (nWritten < nDstLen)) {
                    m_pMemoryManager->writeByte(pDst + (XADDR)nWritten, (quint8)(m_pMemoryManager->readWord(pSrc + (XADDR)i * 2) & 0xFF));
                }
                nWritten++;
            }
            if (pDst && (nWritten < nDstLen)) {
                m_pMemoryManager->writeByte(pDst + (XADDR)nWritten, 0);
                nWritten++;
            }
        }
        _return(pRegisters, nWritten, 8);
        return true;
    }
    if (sFunc == QStringLiteral("GetFileType")) { _return(pRegisters, 1, 1); return true; }     // FILE_TYPE_DISK
    if (sFunc == QStringLiteral("GetFileAttributesA")) { _return(pRegisters, 0x80u, 1); return true; }   // FILE_ATTRIBUTE_NORMAL
    if (sFunc == QStringLiteral("GetStringTypeW")) { _return(pRegisters, 1, 5); return true; }
    if (sFunc == QStringLiteral("GetStringTypeA")) { _return(pRegisters, 1, 4); return true; }

    // --- directory / temp-extraction APIs (PEBundle/Alloy bundled-file loader) -----------------
    // Same stdcall-cleanup bug class as above. Enough to keep the extraction path's ESP balanced.
    if ((sFunc == QStringLiteral("GetSystemDirectoryA")) || (sFunc == QStringLiteral("GetSystemDirectoryW")) ||
        (sFunc == QStringLiteral("GetWindowsDirectoryA")) || (sFunc == QStringLiteral("GetWindowsDirectoryW"))) {  // UINT(LPSTR|LPWSTR lpBuffer, UINT uSize)
        const XADDR nBuf = (XADDR)_arg(pRegisters, 0);
        const quint32 nSize = (quint32)_arg(pRegisters, 1);
        const bool bW = sFunc.endsWith(QLatin1Char('W'));
        const char *d = sFunc.startsWith(QStringLiteral("GetSystem")) ? "C:\\Windows\\System32" : "C:\\Windows";
        const int nLen = (int)qstrlen(d);
        if (nBuf && ((quint32)nLen < nSize)) {
            for (int i = 0; i <= nLen; i++) {
                if (bW) m_pMemoryManager->writeWord(nBuf + (XADDR)i * 2, (quint8)d[i]);
                else m_pMemoryManager->writeByte(nBuf + (XADDR)i, (quint8)d[i]);
            }
        }
        _return(pRegisters, (quint32)nLen, 2);
        return true;
    }
    if ((sFunc == QStringLiteral("GetTempPathA")) || (sFunc == QStringLiteral("GetTempPathW"))) {   // DWORD(nBufferLength, LPSTR|LPWSTR lpBuffer)
        const quint32 nSize = (quint32)_arg(pRegisters, 0);
        const XADDR nBuf = (XADDR)_arg(pRegisters, 1);
        const bool bW = sFunc.endsWith(QLatin1Char('W'));
        const char *d = "C:\\Temp\\";
        const int nLen = (int)qstrlen(d);
        if (nBuf && ((quint32)nLen < nSize)) {
            for (int i = 0; i <= nLen; i++) {
                if (bW) m_pMemoryManager->writeWord(nBuf + (XADDR)i * 2, (quint8)d[i]);
                else m_pMemoryManager->writeByte(nBuf + (XADDR)i, (quint8)d[i]);
            }
        }
        _return(pRegisters, (quint32)nLen, 2);
        return true;
    }
    if ((sFunc == QStringLiteral("CreateDirectoryA")) || (sFunc == QStringLiteral("CreateDirectoryW"))) { _return(pRegisters, 1, 2); return true; }

    // --- native (ntdll Nt*/Zw*) APIs: correct stdcall arg cleanup is critical (6-11 args) ---
    {
        const XADDR a0 = (XADDR)_arg(pRegisters, 0);
        const XADDR a3 = (XADDR)_arg(pRegisters, 3);
        // File I/O backed by the main module's REAL on-disk bytes, so an anti-tamper CRC of
        // its own file succeeds. Any open hands out a handle onto m_baMainFile (a packer only
        // opens its own image during unpacking).
        if ((sFunc == QStringLiteral("NtOpenFile")) || (sFunc == QStringLiteral("ZwOpenFile")) ||
            (sFunc == QStringLiteral("NtCreateFile")) || (sFunc == QStringLiteral("ZwCreateFile"))) {
            const int nArgs = sFunc.contains(QStringLiteral("Create")) ? 11 : 6;
            if (!m_baMainFile.isEmpty()) {
                const XADDR h = m_nNextFileHandle;
                m_nNextFileHandle += 4;
                m_mapFileOffset.insert(h, 0);
                if (a0) m_pMemoryManager->writeDword(a0, (quint32)h);
                if (a3) { m_pMemoryManager->writeDword(a3, 0); m_pMemoryManager->writeDword(a3 + 4, 1); }  // STATUS_SUCCESS, FILE_OPENED
                _return(pRegisters, 0, nArgs);
            } else {
                if (a0) m_pMemoryManager->writeDword(a0, 0);
                if (a3) { m_pMemoryManager->writeDword(a3, 0xC0000034); m_pMemoryManager->writeDword(a3 + 4, 0); }
                _return(pRegisters, 0xC0000034u, nArgs);
            }
            return true;
        }
        if ((sFunc == QStringLiteral("NtReadFile")) || (sFunc == QStringLiteral("ZwReadFile"))) {  // 9 args
            const XADDR pIosb = (XADDR)_arg(pRegisters, 4);
            const XADDR pBuf = (XADDR)_arg(pRegisters, 5);
            const quint32 nLen = (quint32)_arg(pRegisters, 6);
            const XADDR pOff = (XADDR)_arg(pRegisters, 7);
            qint64 nOff = m_mapFileOffset.value(a0, -1);
            if (nOff < 0) { if (pIosb) { m_pMemoryManager->writeDword(pIosb, 0xC0000008); m_pMemoryManager->writeDword(pIosb + 4, 0); } _return(pRegisters, 0xC0000008u, 9); return true; }
            if (pOff) nOff = (qint64)m_pMemoryManager->readDword(pOff) | ((qint64)m_pMemoryManager->readDword(pOff + 4) << 32);
            const qint64 nAvail = (qint64)m_baMainFile.size() - nOff;
            if (nAvail <= 0) { if (pIosb) { m_pMemoryManager->writeDword(pIosb, 0xC0000011); m_pMemoryManager->writeDword(pIosb + 4, 0); } _return(pRegisters, 0xC0000011u, 9); return true; }
            const quint32 nRead = (quint32)qMin<qint64>((qint64)nLen, nAvail);
            if (pBuf) m_pMemoryManager->write(pBuf, m_baMainFile.mid((int)nOff, (int)nRead));
            m_mapFileOffset[a0] = nOff + nRead;
            if (pIosb) { m_pMemoryManager->writeDword(pIosb, 0); m_pMemoryManager->writeDword(pIosb + 4, nRead); }
            _return(pRegisters, 0, 9);
            return true;
        }
        if ((sFunc == QStringLiteral("NtQueryInformationFile")) || (sFunc == QStringLiteral("ZwQueryInformationFile"))) {  // 5 args
            const int nClass = (int)_arg(pRegisters, 4);
            if (nClass == 5 && a2) {  // FileStandardInformation: AllocationSize(0), EndOfFile(8)
                m_pMemoryManager->writeDword(a2 + 0x00, (quint32)m_baMainFile.size());
                m_pMemoryManager->writeDword(a2 + 0x04, 0);
                m_pMemoryManager->writeDword(a2 + 0x08, (quint32)m_baMainFile.size());
                m_pMemoryManager->writeDword(a2 + 0x0C, 0);
            }
            if (a1) { m_pMemoryManager->writeDword(a1, 0); m_pMemoryManager->writeDword(a1 + 4, 0x18); }
            _return(pRegisters, 0, 5);
            return true;
        }
        if ((sFunc == QStringLiteral("NtSetInformationFile")) || (sFunc == QStringLiteral("ZwSetInformationFile"))) {  // 5 args
            const int nClass = (int)_arg(pRegisters, 4);
            if (nClass == 14 && a2 && m_mapFileOffset.contains(a0)) {  // FilePositionInformation
                m_mapFileOffset[a0] = (qint64)m_pMemoryManager->readDword(a2) | ((qint64)m_pMemoryManager->readDword(a2 + 4) << 32);
            }
            if (a1) { m_pMemoryManager->writeDword(a1, 0); m_pMemoryManager->writeDword(a1 + 4, 0); }
            _return(pRegisters, 0, 5);
            return true;
        }
        if ((sFunc == QStringLiteral("NtClose")) || (sFunc == QStringLiteral("ZwClose"))) { m_mapFileOffset.remove(a0); m_mapSectionIsFile.remove(a0); _return(pRegisters, 0, 1); return true; }

        // Section (memory-mapped file) I/O: VMProtect CRCs its own file via a section view.
        if ((sFunc == QStringLiteral("NtCreateSection")) || (sFunc == QStringLiteral("ZwCreateSection"))) {  // 7 args
            const XADDR hFile = (XADDR)_arg(pRegisters, 6);
            const XADDR hSec = m_nNextFileHandle;
            m_nNextFileHandle += 4;
            m_mapSectionIsFile.insert(hSec, m_mapFileOffset.contains(hFile) && !m_baMainFile.isEmpty());
            if (a0) m_pMemoryManager->writeDword(a0, (quint32)hSec);
            _return(pRegisters, 0, 7);
            return true;
        }
        if ((sFunc == QStringLiteral("NtMapViewOfSection")) || (sFunc == QStringLiteral("ZwMapViewOfSection"))) {  // 10 args
            const XADDR pBase = a2;
            const XADDR pViewSize = (XADDR)_arg(pRegisters, 6);
            const bool bFile = m_mapSectionIsFile.value(a0, false);
            quint64 nSize = bFile ? (quint64)m_baMainFile.size() : (pViewSize ? m_pMemoryManager->readDword(pViewSize) : 0x1000);
            if (nSize == 0) nSize = 0x1000;
            const quint64 nAligned = (nSize + 0xFFF) & ~0xFFFULL;
            XADDR nGot = m_pMemoryManager->allocate(0, nAligned, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("section_view"));
            if (nGot != 0 && bFile) m_pMemoryManager->write(nGot, m_baMainFile);  // serve the real file bytes into the view
            if (pBase) m_pMemoryManager->writeDword(pBase, (quint32)nGot);
            if (pViewSize) m_pMemoryManager->writeDword(pViewSize, (quint32)nSize);
            _return(pRegisters, nGot ? 0 : 0xC0000018u, 10);
            return true;
        }
        if ((sFunc == QStringLiteral("NtUnmapViewOfSection")) || (sFunc == QStringLiteral("ZwUnmapViewOfSection"))) { _return(pRegisters, 0, 2); return true; }
        if ((sFunc == QStringLiteral("NtQuerySection")) || (sFunc == QStringLiteral("ZwQuerySection"))) { _return(pRegisters, 0, 5); return true; }

        // Anti-debug queries: report a clean, non-debugged process.
        if ((sFunc == QStringLiteral("NtQueryInformationProcess")) || (sFunc == QStringLiteral("ZwQueryInformationProcess"))) {  // 5 args
            // Anti-debug info classes must report "not being debugged", each with its OWN convention -- a
            // uniform 0 fill is WRONG for ProcessDebugFlags (0 there means DEBUGGED, seen in VMProtect 2.0.3).
            const quint32 nClass = (quint32)_arg(pRegisters, 1);
            const XADDR pInfo = (XADDR)_arg(pRegisters, 2);
            const quint32 nLen = (quint32)_arg(pRegisters, 3);
            quint32 nStatus = 0;             // STATUS_SUCCESS
            quint32 nVal = 0;                // buffer value for a non-debugged process
            if (nClass == 0x1E) {            // ProcessDebugFlags: 1 = NOT debugged (0 = debugged)
                nVal = 1;
            } else if (nClass == 0x1F) {     // ProcessDebugObjectHandle: no debug object -> STATUS_PORT_NOT_SET, handle 0
                nStatus = 0xC0000353u;
            }                                // 0x07 ProcessDebugPort and the rest: 0 = not debugged
            const quint32 nFill = qMin<quint32>(nLen & ~3u, 0x20u);   // whole dwords only, capped
            if (pInfo) for (quint32 i = 0; i < nFill; i += 4) m_pMemoryManager->writeDword(pInfo + i, (i == 0) ? nVal : 0u);
            const XADDR pRet = (XADDR)_arg(pRegisters, 4);            // optional ReturnLength
            if (pRet) m_pMemoryManager->writeDword(pRet, qMin<quint32>(nLen, 4u));
            _return(pRegisters, nStatus, 5);
            return true;
        }
        if ((sFunc == QStringLiteral("NtSetInformationThread")) || (sFunc == QStringLiteral("ZwSetInformationThread"))) { _return(pRegisters, 0, 4); return true; }  // ThreadHideFromDebugger no-op
        if ((sFunc == QStringLiteral("NtQuerySystemInformation")) || (sFunc == QStringLiteral("ZwQuerySystemInformation"))) { _return(pRegisters, 0, 4); return true; }

        // Native memory management: model like the kernel32 Virtual* equivalents (in/out pointers).
        if ((sFunc == QStringLiteral("NtAllocateVirtualMemory")) || (sFunc == QStringLiteral("ZwAllocateVirtualMemory"))) {  // 6 args
            const XADDR pBase = (XADDR)_arg(pRegisters, 1);
            const XADDR pSize = (XADDR)_arg(pRegisters, 3);
            quint64 nSize = pSize ? m_pMemoryManager->readDword(pSize) : 0x1000;
            if (nSize == 0) nSize = 0x1000;
            XADDR nWant = pBase ? (XADDR)m_pMemoryManager->readDword(pBase) : 0;
            XADDR nGot = m_pMemoryManager->allocate(nWant, nSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("NtAlloc"));
            if (nGot == 0) nGot = m_pMemoryManager->allocate(0, nSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("NtAlloc"));
            if (pBase) m_pMemoryManager->writeDword(pBase, (quint32)nGot);
            if (pSize) m_pMemoryManager->writeDword(pSize, (quint32)((nSize + 0xFFF) & ~0xFFFULL));
            _return(pRegisters, nGot ? 0 : 0xC0000017u, 6);
            return true;
        }
        if ((sFunc == QStringLiteral("NtProtectVirtualMemory")) || (sFunc == QStringLiteral("ZwProtectVirtualMemory"))) {  // 5 args
            const XADDR pOld = (XADDR)_arg(pRegisters, 4);
            if (pOld) m_pMemoryManager->writeDword(pOld, 0x40);  // *OldProtect = PAGE_EXECUTE_READWRITE
            _return(pRegisters, 0, 5);
            return true;
        }
        if ((sFunc == QStringLiteral("NtFreeVirtualMemory")) || (sFunc == QStringLiteral("ZwFreeVirtualMemory"))) { _return(pRegisters, 0, 4); return true; }
        if ((sFunc == QStringLiteral("NtQueryVirtualMemory")) || (sFunc == QStringLiteral("ZwQueryVirtualMemory"))) {  // 6 args
            const XADDR pOut = (XADDR)_arg(pRegisters, 2);
            const XADDR nAddr = (XADDR)_arg(pRegisters, 1);
            if (pOut) {
                m_pMemoryManager->writeDword(pOut + 0x00, (quint32)(nAddr & ~0xFFFu));
                m_pMemoryManager->writeDword(pOut + 0x04, (quint32)(nAddr & ~0xFFFu));
                m_pMemoryManager->writeDword(pOut + 0x08, 0x40);
                m_pMemoryManager->writeDword(pOut + 0x0C, 0x1000);
                m_pMemoryManager->writeDword(pOut + 0x10, 0x1000);
                m_pMemoryManager->writeDword(pOut + 0x14, 0x40);
                m_pMemoryManager->writeDword(pOut + 0x18, 0x20000);
            }
            _return(pRegisters, 0, 6);
            return true;
        }
    }

    // --- interactive-session probe (VMProtect bails with ExitProcess(0xDEADC0DE) if the
    //     process looks like a non-interactive service/sandbox). Report an interactive
    //     "WinSta0" window station + "Default" desktop. ---
    if (sFunc == QStringLiteral("GetProcessWindowStation")) { _return(pRegisters, 0x10000, 0); return true; }
    if (sFunc == QStringLiteral("GetThreadDesktop")) { _return(pRegisters, 0x10004, 1); return true; }
    if ((sFunc == QStringLiteral("OpenWindowStationW")) || (sFunc == QStringLiteral("OpenWindowStationA"))) { _return(pRegisters, 0x10000, 4); return true; }
    if ((sFunc == QStringLiteral("OpenDesktopW")) || (sFunc == QStringLiteral("OpenDesktopA"))) { _return(pRegisters, 0x10004, 6); return true; }
    if ((sFunc == QStringLiteral("GetUserObjectInformationW")) || (sFunc == QStringLiteral("GetUserObjectInformationA"))) {  // 5 args
        const int nIndex = (int)_arg(pRegisters, 1);     // UOI_FLAGS=1, UOI_NAME=2, UOI_TYPE=3
        const XADDR pInfo = (XADDR)_arg(pRegisters, 2);
        const XADDR pNeeded = (XADDR)_arg(pRegisters, 4);
        const bool bW = sFunc.endsWith(QLatin1Char('W'));
        const XADDR hObj = (XADDR)_arg(pRegisters, 0);
        if (nIndex == 1 && pInfo) {  // UOI_FLAGS -> USEROBJECTFLAGS{fInherit,fReserved,dwFlags}; WSF_VISIBLE=1 => interactive
            m_pMemoryManager->writeDword(pInfo + 0x00, 0);
            m_pMemoryManager->writeDword(pInfo + 0x04, 0);
            m_pMemoryManager->writeDword(pInfo + 0x08, 0x0001);  // WSF_VISIBLE -> not a service/sandbox
        } else if (pInfo) {  // UOI_NAME / UOI_TYPE
            const char *sVal = (nIndex == 3) ? "WindowStation" : ((hObj == 0x10004) ? "Default" : "WinSta0");
            int i = 0;
            for (; sVal[i]; i++) { if (bW) m_pMemoryManager->writeWord(pInfo + (XADDR)i * 2, (quint8)sVal[i]); else m_pMemoryManager->writeByte(pInfo + (XADDR)i, (quint8)sVal[i]); }
            if (bW) m_pMemoryManager->writeWord(pInfo + (XADDR)i * 2, 0); else m_pMemoryManager->writeByte(pInfo + (XADDR)i, 0);
        }
        if (pNeeded) m_pMemoryManager->writeDword(pNeeded, 0x20);
        _return(pRegisters, 1, 5);
        return true;
    }
    if (sFunc == QStringLiteral("FindWindowA") || sFunc == QStringLiteral("FindWindowW")) { _return(pRegisters, 0x00E70000u, 2); return true; }
    if (sFunc == QStringLiteral("GetWindowThreadProcessId")) {
        const XADDR pOut = (XADDR)_arg(pRegisters, 1);
        if (pOut) m_pMemoryManager->writeDword(pOut, 0x1234);
        _return(pRegisters, 0x1000u, 2);
        return true;
    }
    if (sFunc == QStringLiteral("GetUserObjectSecurity")) { _return(pRegisters, 1, 5); return true; }

    // MessageBox: a packer shows this on a failed anti-tamper/anti-debug/anti-VM check. LOG the
    // text so the exact failing check is revealed, then answer IDOK (1) and clean the args.
    if ((sFunc == QStringLiteral("MessageBoxW")) || (sFunc == QStringLiteral("MessageBoxA")) ||
        (sFunc == QStringLiteral("MessageBoxExW")) || (sFunc == QStringLiteral("MessageBoxExA"))) {
        const bool bW = sFunc.contains(QLatin1Char('W'));
        const XADDR pText = (XADDR)_arg(pRegisters, 1);
        const XADDR pCap = (XADDR)_arg(pRegisters, 2);
        QString sText, sCap;
        for (int i = 0; i < 1024 && pText; i++) { quint32 c = bW ? (quint32)m_pMemoryManager->readWord(pText + (XADDR)i * 2) : (quint32)m_pMemoryManager->readByte(pText + (XADDR)i); if (!c) break; sText.append(QChar(c)); }
        for (int i = 0; i < 256 && pCap; i++) { quint32 c = bW ? (quint32)m_pMemoryManager->readWord(pCap + (XADDR)i * 2) : (quint32)m_pMemoryManager->readByte(pCap + (XADDR)i); if (!c) break; sCap.append(QChar(c)); }
        fprintf(stderr, "[MSGBOX] caption=\"%s\" text=\"%s\"\n", sCap.toUtf8().constData(), sText.toUtf8().constData());
        fflush(stderr);
        _return(pRegisters, 1, sFunc.contains(QStringLiteral("Ex")) ? 5 : 4);  // IDOK
        return true;
    }

    // --- resources / locale / registry / anti-tamper hash-resolvers --------------------------
    if ((sFunc == QStringLiteral("FindResourceA")) || (sFunc == QStringLiteral("FindResourceW"))) { _return(pRegisters, 0x00E70000u, 3); return true; }
    if (sFunc == QStringLiteral("LoadResource")) { _return(pRegisters, 0x00E70010u, 2); return true; }
    if (sFunc == QStringLiteral("SizeofResource")) { _return(pRegisters, 0x40, 2); return true; }
    if (sFunc == QStringLiteral("LoadStringA")) {
        const XADDR pDst = (XADDR)_arg(pRegisters, 2);
        const quint32 nLen = (quint32)_arg(pRegisters, 3);
        if (pDst && (nLen >= 1)) {
            m_pMemoryManager->writeByte(pDst, 'X');
            m_pMemoryManager->writeByte(pDst + 1, 0);
        }
        _return(pRegisters, 1, 4);
        return true;
    }
    if (sFunc == QStringLiteral("GetLocaleInfoA") || sFunc == QStringLiteral("GetLocaleInfoW")) {
        const XADDR pBuf = (XADDR)_arg(pRegisters, 2);
        const quint32 nLen = (quint32)_arg(pRegisters, 3);
        if (pBuf && (nLen >= 3)) {
            const bool bW = sFunc.endsWith(QLatin1Char('W'));
            if (bW) {
                m_pMemoryManager->writeWord(pBuf, '0');
                m_pMemoryManager->writeWord(pBuf + 2, 0);
            } else {
                m_pMemoryManager->writeByte(pBuf, '0');
                m_pMemoryManager->writeByte(pBuf + 1, 0);
            }
        }
        _return(pRegisters, nLen ? 2 : 0, 4);
        return true;
    }
    if ((sFunc == QStringLiteral("RegOpenKeyExA")) || (sFunc == QStringLiteral("RegOpenKeyExW"))) {
        const XADDR pOut = (XADDR)_arg(pRegisters, 4);
        if (pOut) m_pMemoryManager->writeDword(pOut, 0x00E70000u);
        _return(pRegisters, 0, 5);
        return true;
    }
    if ((sFunc == QStringLiteral("RegQueryValueExA")) || (sFunc == QStringLiteral("RegQueryValueExW"))) {
        const XADDR pType = (XADDR)_arg(pRegisters, 2);
        const XADDR pData = (XADDR)_arg(pRegisters, 3);
        const XADDR pDataSize = (XADDR)_arg(pRegisters, 4);
        if (pType) m_pMemoryManager->writeDword(pType, 1);
        if (pData) m_pMemoryManager->writeByte(pData, 0);
        if (pDataSize) m_pMemoryManager->writeDword(pDataSize, 0);
        _return(pRegisters, 0, 6);
        return true;
    }
    if ((sFunc == QStringLiteral("RegCloseKey")) || (sFunc == QStringLiteral("RegCloseKeyW")) || (sFunc == QStringLiteral("RegCloseKeyA"))) {
        _return(pRegisters, 0, 1);
        return true;
    }

    // Ntdll exports that some hash resolvers probe before their own table walk.
    if ((sFunc == QStringLiteral("LdrGetProcedureAddress")) || (sFunc == QStringLiteral("LdrGetDllHandle")) ||
        (sFunc == QStringLiteral("LdrLoadDll"))) {
        const XADDR pAddress = (XADDR)_arg(pRegisters, 3);
        if (pAddress) {
            m_pMemoryManager->writeDword(pAddress, 0x00E70000u);
            m_pMemoryManager->writeDword(pAddress + 4, 0x00E70010u);
        }
        _return(pRegisters, 0, sFunc == QStringLiteral("LdrGetDllHandle") ? 5 : 4);
        return true;
    }
    if (sFunc == QStringLiteral("RtlGetVersion")) {
        const XADDR pInfo = (XADDR)_arg(pRegisters, 0);  // RTL_OSVERSIONINFOEXW*
        if (pInfo) {
            m_pMemoryManager->writeDword(pInfo + 0x04, 6);    // dwMajorVersion
            m_pMemoryManager->writeDword(pInfo + 0x08, 2);    // dwMinorVersion
            m_pMemoryManager->writeDword(pInfo + 0x0C, 9200); // dwBuildNumber
        }
        _return(pRegisters, 0, 1);
        return true;
    }

    // --- critical sections / synchronisation (no-op, arg-count-correct) ---
    if (sFunc == QStringLiteral("InitializeCriticalSection")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("InitializeCriticalSectionAndSpinCount")) { _return(pRegisters, 1, 2); return true; }
    if (sFunc == QStringLiteral("InitializeCriticalSectionEx")) { _return(pRegisters, 1, 3); return true; }
    if (sFunc == QStringLiteral("EnterCriticalSection")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("LeaveCriticalSection")) { _return(pRegisters, 0, 1); return true; }
    if (sFunc == QStringLiteral("DeleteCriticalSection")) { _return(pRegisters, 0, 1); return true; }

    return false;
}
