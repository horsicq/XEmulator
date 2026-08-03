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
#include "xemulinuxsyscalls.h"

// mmap protection / flag bits (Linux asm-generic values).
static const quint64 PROT_READ = 0x1;
static const quint64 PROT_WRITE = 0x2;
static const quint64 PROT_EXEC = 0x4;
static const quint64 MAP_FIXED = 0x10;
static const quint64 MAP_FAILED = (quint64)-1;

// arch_prctl codes.
static const quint64 ARCH_SET_GS = 0x1001;
static const quint64 ARCH_SET_FS = 0x1002;
static const quint64 ARCH_GET_FS = 0x1003;
static const quint64 ARCH_GET_GS = 0x1004;

static const quint64 LNX_ENOSYS = 38;

static inline quint64 errnoRet(quint64 nErrno)
{
    return (quint64)(-(qint64)nErrno);
}

XEmuLinuxSyscalls::XEmuLinuxSyscalls(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64)
    : m_pMemoryManager(pMemoryManager), m_pArch(pArch), m_bIs64(bIs64), m_nBrkBase(0), m_nBrkCurrent(0), m_nBrkLimit(0), m_nNextFd(3), m_bExited(false),
      m_nExitCode(0), m_bExeced(false)
{
}

void XEmuLinuxSyscalls::setLogger(const LOG_CALLBACK &fnLog)
{
    m_fnLog = fnLog;
}

void XEmuLinuxSyscalls::_log(const QString &sText) const
{
    if (m_fnLog) {
        m_fnLog(sText);
    }
}

void XEmuLinuxSyscalls::reset()
{
    m_bExited = false;
    m_nExitCode = 0;
    m_nBrkBase = 0;
    m_nBrkCurrent = 0;
    m_nBrkLimit = 0;
    m_nNextFd = 3;
    m_files.clear();
    m_sharedMaps.clear();
    m_bExeced = false;
    m_baExecImage.clear();
}

bool XEmuLinuxSyscalls::hasExeced() const
{
    return m_bExeced;
}

QByteArray XEmuLinuxSyscalls::execImage() const
{
    return m_baExecImage;
}

void XEmuLinuxSyscalls::setSelfExe(const QByteArray &baBytes, const QString &sPath)
{
    m_baSelfExe = baBytes;
    m_sSelfPath = sPath;
}

int XEmuLinuxSyscalls::_newFd()
{
    return m_nNextFd++;
}

void XEmuLinuxSyscalls::_syncMapsToFile(int nFd)
{
    // Copy the current contents of every shared mapping of this descriptor back into
    // the file buffer, so a subsequent mapping of the same fd sees the latest bytes
    // (this is how the stub's writable decompression mapping becomes visible in the
    // executable mapping it creates afterwards).
    if (!m_files.contains(nFd)) {
        return;
    }

    QByteArray &baFile = m_files[nFd].baData;

    for (int i = 0; i < m_sharedMaps.size(); i++) {
        const SHARED_MAP &map = m_sharedMaps.at(i);
        if (map.nFd != nFd) {
            continue;
        }

        bool bOk = false;
        QByteArray baLive = m_pMemoryManager->read(map.nBase, map.nLen, &bOk);
        if (!bOk) {
            continue;
        }

        quint64 nNeeded = map.nFileOffset + (quint64)baLive.size();
        if ((quint64)baFile.size() < nNeeded) {
            baFile.resize((int)nNeeded);
        }
        memcpy(baFile.data() + map.nFileOffset, baLive.constData(), baLive.size());
    }
}

bool XEmuLinuxSyscalls::hasExited() const
{
    return m_bExited;
}

int XEmuLinuxSyscalls::exitCode() const
{
    return m_nExitCode;
}

XEmuLinuxSyscalls::SCK_KIND XEmuLinuxSyscalls::_classify(quint64 nNumber) const
{
    if (m_bIs64) {
        switch (nNumber) {
            case 9: return SCK_MMAP;
            case 10: return SCK_MPROTECT;
            case 11: return SCK_MUNMAP;
            case 26: return SCK_MSYNC;
            case 12: return SCK_BRK;
            case 158: return SCK_ARCH_PRCTL;
            case 0: return SCK_READ;
            case 1: return SCK_WRITE;
            case 2: return SCK_OPEN;
            case 257: return SCK_OPEN;   // openat
            case 319: return SCK_MEMFD;  // memfd_create
            case 77: return SCK_FTRUNCATE;
            case 8: return SCK_LSEEK;
            case 18: return SCK_PWRITE;  // pwrite64
            case 5: return SCK_FSTAT;
            case 262: return SCK_FSTAT;  // newfstatat
            case 3: return SCK_CLOSE;
            case 32: return SCK_DUP;
            case 33: return SCK_DUP;  // dup2
            case 59: return SCK_EXECVE;
            case 322: return SCK_EXECVEAT;
            case 60: return SCK_EXIT;
            case 231: return SCK_EXIT_GROUP;
            case 89: return SCK_READLINK;
            case 267: return SCK_READLINK;  // readlinkat
            // Known-but-irrelevant-before-OEP.
            case 13:   // rt_sigaction
            case 14:   // rt_sigprocmask
            case 21:   // access
            case 218:  // set_tid_address
            case 273:  // set_robust_list
            case 302:  // prlimit64
            case 334:  // rseq
            case 228:  // clock_gettime
            case 318:  // getrandom
                return SCK_IGNORED;
            default: return SCK_UNKNOWN;
        }
    }

    // i386 (int 0x80).
    switch (nNumber) {
        case 192: return SCK_MMAP2;  // mmap2 (page offset)
        case 90: return SCK_MMAP;    // old_mmap
        case 125: return SCK_MPROTECT;
        case 91: return SCK_MUNMAP;
        case 144: return SCK_MSYNC;
        case 45: return SCK_BRK;
        case 243: return SCK_SET_THREAD_AREA;
        case 3: return SCK_READ;
        case 4: return SCK_WRITE;
        case 5: return SCK_OPEN;
        case 295: return SCK_OPEN;   // openat
        case 356: return SCK_MEMFD;  // memfd_create
        case 93: return SCK_FTRUNCATE;
        case 194: return SCK_FTRUNCATE;  // ftruncate64
        case 19: return SCK_LSEEK;
        case 181: return SCK_PWRITE;  // pwrite64
        case 197: return SCK_FSTAT;   // fstat64
        case 6: return SCK_CLOSE;
        case 41: return SCK_DUP;
        case 63: return SCK_DUP;  // dup2
        case 11: return SCK_EXECVE;
        case 358: return SCK_EXECVEAT;
        case 1: return SCK_EXIT;
        case 252: return SCK_EXIT_GROUP;
        case 85: return SCK_READLINK;
        case 305: return SCK_READLINK;  // readlinkat
        case 33:   // access
        case 175:  // rt_sigprocmask
        case 174:  // rt_sigaction
        case 258:  // set_tid_address
        case 311:  // set_robust_list
            return SCK_IGNORED;
        default: return SCK_UNKNOWN;
    }
}

quint64 XEmuLinuxSyscalls::_number(XEmuRegisters *pRegisters) const
{
    return pRegisters->getGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4);
}

quint64 XEmuLinuxSyscalls::_arg(XEmuRegisters *pRegisters, int nIndex) const
{
    if (m_bIs64) {
        static const int s_regs[6] = {XEmuRegisters::GPR_RDI, XEmuRegisters::GPR_RSI, XEmuRegisters::GPR_RDX,
                                      XEmuRegisters::GPR_R10, XEmuRegisters::GPR_R8,  XEmuRegisters::GPR_R9};
        return (nIndex >= 0 && nIndex < 6) ? pRegisters->getGPR(s_regs[nIndex], 8) : 0;
    }

    static const int s_regs32[6] = {XEmuRegisters::GPR_RBX, XEmuRegisters::GPR_RCX, XEmuRegisters::GPR_RDX,
                                    XEmuRegisters::GPR_RSI, XEmuRegisters::GPR_RDI, XEmuRegisters::GPR_RBP};
    return (nIndex >= 0 && nIndex < 6) ? pRegisters->getGPR(s_regs32[nIndex], 4) : 0;
}

void XEmuLinuxSyscalls::_return(XEmuRegisters *pRegisters, quint64 nValue)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4, nValue);
}

QByteArray XEmuLinuxSyscalls::_readMem(XADDR nAddress, quint64 nSize) const
{
    bool bOk = false;
    QByteArray ba = m_pMemoryManager->read(nAddress, nSize, &bOk);
    return bOk ? ba : QByteArray();
}

XEmuMemoryManager::MEMORY_FLAGS XEmuLinuxSyscalls::_flagsFromProt(quint64 nProt) const
{
    bool bRead = (nProt & PROT_READ) != 0;
    bool bWrite = (nProt & PROT_WRITE) != 0;
    bool bExec = (nProt & PROT_EXEC) != 0;

    // PROT_NONE regions are still committed (readable) so the stub can populate them.
    return XEmuMemoryManager::MEMORY_FLAGS(bRead || bWrite || bExec || (nProt == 0), bWrite, bExec);
}

quint64 XEmuLinuxSyscalls::_sysMmap(XEmuRegisters *pRegisters, bool bPageOffset)
{
    XADDR nAddr = (XADDR)_arg(pRegisters, 0);
    quint64 nLen = _arg(pRegisters, 1);
    quint64 nProt = _arg(pRegisters, 2);
    quint64 nFlags = _arg(pRegisters, 3);
    qint64 nFd = (qint64)_arg(pRegisters, 4);
    quint64 nFileOffset = _arg(pRegisters, 5);

    if (bPageOffset) {
        nFileOffset *= XEmuMemoryManager::N_PAGE_SIZE;  // mmap2: offset is in pages
    }

    if (nLen == 0) {
        return errnoRet(22);  // EINVAL
    }

    bool bFileBacked = (nFd >= 0) && m_files.contains((int)nFd);

    // Flush existing shared mappings of this fd back into the file *before* we touch
    // any memory, so a re-map of the same fd captures the freshly decompressed bytes
    // (even when it re-maps the very buffer being flushed).
    if (bFileBacked) {
        _syncMapsToFile((int)nFd);
    }

    quint64 nSize = XEmuMemoryManager::alignUp(nLen, XEmuMemoryManager::N_PAGE_SIZE);
    XEmuMemoryManager::MEMORY_FLAGS flags = _flagsFromProt(nProt);
    XADDR nBase = 0;

    if ((nFlags & MAP_FIXED) && (nAddr != 0)) {
        XADDR nAligned = XEmuMemoryManager::alignDown(nAddr, XEmuMemoryManager::N_PAGE_SIZE);
        nSize = XEmuMemoryManager::alignUp(nLen + (nAddr - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

        // MAP_FIXED replaces only the requested range. Repurpose it in place rather
        // than releasing the enclosing allocation, which would wrongly free the
        // memory above it (a packer often re-maps the low part of its own image while
        // still reading compressed data from the tail of that same mapping).
        const quint64 MAP_ANONYMOUS = 0x20;
        if (m_pMemoryManager->isCommitted(nAligned, 1)) {
            m_pMemoryManager->protect(nAligned, nSize, flags);
            nBase = nAligned;
        } else {
            nBase = m_pMemoryManager->allocate(nAligned, nSize, flags, QStringLiteral("mmap"));
            if ((nBase == 0) && m_pMemoryManager->commit(nAligned, nSize, flags)) {
                nBase = nAligned;
            }
        }

        // Anonymous mappings are zero-filled; the stub decompresses its output here.
        if ((nBase != 0) && !bFileBacked && (nFlags & MAP_ANONYMOUS)) {
            m_pMemoryManager->write(nBase, QByteArray((int)nSize, 0));
        }

        // Drop shared-map records overlapping the reused range.
        for (int i = m_sharedMaps.size() - 1; i >= 0; i--) {
            const SHARED_MAP &m = m_sharedMaps.at(i);
            if ((m.nBase < nAligned + nSize) && (nAligned < m.nBase + m.nLen)) {
                m_sharedMaps.removeAt(i);
            }
        }
    } else {
        nBase = m_pMemoryManager->allocate(nAddr, nSize, flags, QStringLiteral("mmap"));
        if ((nBase == 0) && (nAddr != 0)) {
            nBase = m_pMemoryManager->allocate(0, nSize, flags, QStringLiteral("mmap"));
        }
    }

    // File-backed mapping: initialise the region from the descriptor's contents so
    // the executable mapping the stub creates reflects what it wrote to the fd.
    if ((nBase != 0) && bFileBacked) {
        const QByteArray &baFile = m_files[(int)nFd].baData;
        if ((quint64)baFile.size() > nFileOffset) {
            quint64 nCopy = qMin<quint64>(nLen, (quint64)baFile.size() - nFileOffset);
            m_pMemoryManager->write(nBase, QByteArray(baFile.constData() + nFileOffset, (int)nCopy));
        }

        SHARED_MAP map = {nBase, nSize, (int)nFd, nFileOffset};
        m_sharedMaps.append(map);
    }

    _log(QStringLiteral("mmap(0x%1, 0x%2, prot=%3, flags=0x%4, fd=%5) = 0x%6")
             .arg(nAddr, 0, 16)
             .arg(nLen, 0, 16)
             .arg(nProt)
             .arg(nFlags, 0, 16)
             .arg(nFd)
             .arg(nBase, 0, 16));

    return (nBase != 0) ? (quint64)nBase : MAP_FAILED;
}

quint64 XEmuLinuxSyscalls::_sysOpen(XEmuRegisters *pRegisters, bool bMemfd, quint64 nFlags, const QString &sPath)
{
    Q_UNUSED(pRegisters)

    const quint64 O_ACCMODE = 0x3;
    const quint64 O_CREAT = 0x40;
    bool bReadOnly = !bMemfd && ((nFlags & O_ACCMODE) == 0) && ((nFlags & O_CREAT) == 0);

    // Distinguish the packed executable itself (which the stub re-opens through
    // /proc/self/exe to read its payload) from an unrelated path such as the dynamic
    // linker or a shared library. Backing *every* read-only open with the packed
    // file would make the loader map diec.upx as "ld.so" and re-run the whole stub.
    bool bSelf = sPath.isEmpty() || sPath.contains(QStringLiteral("/proc/self/exe")) || sPath.contains(QStringLiteral("/proc/self/fd/")) ||
                 (!m_sSelfPath.isEmpty() && (sPath == m_sSelfPath));

    int nFd = _newFd();
    FAKE_FILE file;
    bool bBacked = false;

    if (bReadOnly && bSelf && !m_baSelfExe.isEmpty()) {
        file.baData = m_baSelfExe;
        bBacked = true;
    } else if (bReadOnly && !bSelf) {
        // Missing file (e.g. the interpreter / a shared library): report ENOENT.
        _log(QStringLiteral("open(\"%1\") = -ENOENT").arg(sPath));
        return errnoRet(2);
    }

    m_files.insert(nFd, file);
    _log(QStringLiteral("%1(\"%2\") = fd %3 (%4 bytes)%5")
             .arg(bMemfd ? QStringLiteral("memfd_create") : QStringLiteral("open"))
             .arg(sPath)
             .arg(nFd)
             .arg(file.baData.size())
             .arg(bBacked ? QStringLiteral(" [self]") : QString()));
    return (quint64)nFd;
}

quint64 XEmuLinuxSyscalls::_sysReadlink(XEmuRegisters *pRegisters)
{
    // readlink(path, buf, bufsiz): report the packed executable's path (the stub
    // resolves /proc/self/exe to find and re-open itself).
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nBufSize = _arg(pRegisters, 2);

    QByteArray baPath = (m_sSelfPath.isEmpty() ? QStringLiteral("/proc/self/exe") : m_sSelfPath).toUtf8();
    quint64 nLen = qMin<quint64>((quint64)baPath.size(), nBufSize);
    if ((nBuf != 0) && (nLen > 0)) {
        m_pMemoryManager->write(nBuf, QByteArray(baPath.constData(), (int)nLen));
    }
    return nLen;
}

quint64 XEmuLinuxSyscalls::_sysFtruncate(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    quint64 nLen = _arg(pRegisters, 1);

    if (!m_files.contains(nFd)) {
        return errnoRet(9);  // EBADF
    }
    m_files[nFd].baData.resize((int)nLen);  // zero-extends or truncates
    return 0;
}

quint64 XEmuLinuxSyscalls::_sysLseek(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    qint64 nOffset = (qint64)_arg(pRegisters, 1);
    quint64 nWhence = _arg(pRegisters, 2);

    if (!m_files.contains(nFd)) {
        return errnoRet(9);
    }

    FAKE_FILE &file = m_files[nFd];
    qint64 nNew = (nWhence == 1) ? (qint64)file.nOffset + nOffset : ((nWhence == 2) ? (qint64)file.baData.size() + nOffset : nOffset);
    if (nNew < 0) {
        nNew = 0;
    }
    file.nOffset = (quint64)nNew;
    return file.nOffset;
}

quint64 XEmuLinuxSyscalls::_sysPwrite(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nCount = _arg(pRegisters, 2);
    quint64 nOffset = _arg(pRegisters, 3);

    if (!m_files.contains(nFd)) {
        return errnoRet(9);
    }

    QByteArray baBuf = _readMem(nBuf, nCount);
    QByteArray &baFile = m_files[nFd].baData;
    quint64 nNeeded = nOffset + (quint64)baBuf.size();
    if ((quint64)baFile.size() < nNeeded) {
        baFile.resize((int)nNeeded);
    }
    memcpy(baFile.data() + nOffset, baBuf.constData(), baBuf.size());
    return (quint64)baBuf.size();
}

quint64 XEmuLinuxSyscalls::_sysFstat(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nStatBuf = (XADDR)_arg(pRegisters, 1);

    // newfstatat passes the buffer in arg2; a fake path in arg1.
    if (!m_files.contains(nFd) && m_files.contains((int)_arg(pRegisters, 0))) {
        // (kept simple: only the fd form is modelled)
    }

    if (m_files.contains(nFd) && (nStatBuf != 0)) {
        // struct stat (x86-64): st_size is a 64-bit field at offset 48.
        m_pMemoryManager->writeQword(nStatBuf + 48, (quint64)m_files[nFd].baData.size());
        return 0;
    }
    return 0;
}

quint64 XEmuLinuxSyscalls::_sysRead(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nCount = _arg(pRegisters, 2);

    if (!m_files.contains(nFd)) {
        return 0;  // no data for stdin / unknown fds
    }

    FAKE_FILE &file = m_files[nFd];
    if (file.nOffset >= (quint64)file.baData.size()) {
        return 0;  // EOF
    }
    quint64 nAvail = qMin<quint64>(nCount, (quint64)file.baData.size() - file.nOffset);
    m_pMemoryManager->write(nBuf, QByteArray(file.baData.constData() + file.nOffset, (int)nAvail));
    file.nOffset += nAvail;
    return nAvail;
}

quint64 XEmuLinuxSyscalls::_sysMprotect(XEmuRegisters *pRegisters)
{
    XADDR nAddr = (XADDR)_arg(pRegisters, 0);
    quint64 nLen = _arg(pRegisters, 1);
    quint64 nProt = _arg(pRegisters, 2);

    XADDR nAligned = XEmuMemoryManager::alignDown(nAddr, XEmuMemoryManager::N_PAGE_SIZE);
    quint64 nSize = XEmuMemoryManager::alignUp(nLen + (nAddr - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

    bool bOk = m_pMemoryManager->protect(nAligned, nSize, _flagsFromProt(nProt));
    _log(QStringLiteral("mprotect(0x%1, 0x%2, prot=%3) = %4").arg(nAddr, 0, 16).arg(nLen, 0, 16).arg(nProt).arg(bOk ? 0 : -1));

    return bOk ? 0 : errnoRet(12);  // ENOMEM
}

quint64 XEmuLinuxSyscalls::_sysBrk(XEmuRegisters *pRegisters)
{
    XADDR nRequested = (XADDR)_arg(pRegisters, 0);

    // Lazily establish a heap region on first use.
    if (m_nBrkBase == 0) {
        const quint64 nHeapReserve = 0x1000000;  // 16 MiB heap window
        m_nBrkBase = m_pMemoryManager->allocate(0, nHeapReserve, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("heap"));
        m_nBrkCurrent = m_nBrkBase;
        m_nBrkLimit = m_nBrkBase + nHeapReserve;
    }

    if ((nRequested != 0) && (nRequested >= m_nBrkBase) && (nRequested <= m_nBrkLimit)) {
        m_nBrkCurrent = nRequested;
    }

    return (quint64)m_nBrkCurrent;
}

quint64 XEmuLinuxSyscalls::_sysArchPrctl(XEmuRegisters *pRegisters)
{
    quint64 nCode = _arg(pRegisters, 0);
    XADDR nAddr = (XADDR)_arg(pRegisters, 1);

    if (nCode == ARCH_SET_FS) {
        pRegisters->nFSBase = nAddr;
    } else if (nCode == ARCH_SET_GS) {
        pRegisters->nGSBase = nAddr;
    } else if (nCode == ARCH_GET_FS) {
        m_pMemoryManager->writeQword(nAddr, pRegisters->nFSBase);
    } else if (nCode == ARCH_GET_GS) {
        m_pMemoryManager->writeQword(nAddr, pRegisters->nGSBase);
    } else {
        return errnoRet(22);  // EINVAL
    }

    return 0;
}

quint64 XEmuLinuxSyscalls::_sysWrite(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nCount = _arg(pRegisters, 2);

    // Write into an emulated file at its current offset (this is how the stub fills
    // the descriptor it will later mmap as executable).
    if (m_files.contains(nFd)) {
        QByteArray baBuf = _readMem(nBuf, nCount);
        FAKE_FILE &file = m_files[nFd];
        quint64 nNeeded = file.nOffset + (quint64)baBuf.size();
        if ((quint64)file.baData.size() < nNeeded) {
            file.baData.resize((int)nNeeded);
        }
        memcpy(file.baData.data() + file.nOffset, baBuf.constData(), baBuf.size());
        file.nOffset += (quint64)baBuf.size();
        return (quint64)baBuf.size();
    }

    if (((nFd == 1) || (nFd == 2)) && (nCount > 0) && (nCount < 0x10000)) {
        QByteArray ba = _readMem(nBuf, nCount);
        if (!ba.isEmpty()) {
            _log(QStringLiteral("write(%1): %2").arg(nFd).arg(QString::fromUtf8(ba).trimmed()));
        }
    }

    return nCount;  // pretend the whole buffer was written
}

QString XEmuLinuxSyscalls::_readStr(XADDR nAddress, int nMax) const
{
    if (nAddress == 0) {
        return QString();
    }

    QByteArray ba;
    for (int i = 0; i < nMax; i++) {
        bool bOk = false;
        quint8 c = m_pMemoryManager->readByte(nAddress + i, &bOk);
        if (!bOk || (c == 0)) {
            break;
        }
        ba.append((char)c);
    }
    return QString::fromLatin1(ba);
}

int XEmuLinuxSyscalls::_fdFromPath(const QString &sPath) const
{
    // Recognise the /proc/self/fd/N and /proc/<pid>/fd/N forms the stub uses to name
    // the descriptor it filled.
    int nPos = sPath.lastIndexOf(QStringLiteral("/fd/"));
    if (nPos >= 0) {
        bool bOk = false;
        int nFd = sPath.mid(nPos + 4).toInt(&bOk);
        if (bOk) {
            return nFd;
        }
    }
    return -1;
}

int XEmuLinuxSyscalls::_largestFile() const
{
    int nBest = -1;
    int nBestSize = -1;
    for (QMap<int, FAKE_FILE>::const_iterator it = m_files.constBegin(); it != m_files.constEnd(); ++it) {
        if (it.value().baData.size() > nBestSize) {
            nBestSize = it.value().baData.size();
            nBest = it.key();
        }
    }
    return nBest;
}

bool XEmuLinuxSyscalls::_sysExecve(XEmuRegisters *pRegisters, bool bExecveAt)
{
    int nTargetFd = -1;

    if (bExecveAt) {
        // execveat(dirfd, pathname, argv, envp, flags)
        int nDirFd = (int)_arg(pRegisters, 0);
        QString sPath = _readStr((XADDR)_arg(pRegisters, 1));
        quint64 nFlags = _arg(pRegisters, 4);
        const quint64 AT_EMPTY_PATH = 0x1000;

        if (sPath.isEmpty() || (nFlags & AT_EMPTY_PATH)) {
            nTargetFd = nDirFd;  // exec the descriptor directly
        } else {
            nTargetFd = _fdFromPath(sPath);
        }
    } else {
        // execve(pathname, argv, envp)
        nTargetFd = _fdFromPath(_readStr((XADDR)_arg(pRegisters, 0)));
    }

    // Make sure any decompression that happened through a shared mapping is flushed
    // into the descriptor before we snapshot it.
    if (m_files.contains(nTargetFd)) {
        _syncMapsToFile(nTargetFd);
    } else {
        nTargetFd = _largestFile();  // fall back to the descriptor that got the most data
        if (m_files.contains(nTargetFd)) {
            _syncMapsToFile(nTargetFd);
        }
    }

    if (m_files.contains(nTargetFd)) {
        m_baExecImage = m_files[nTargetFd].baData;
        m_bExeced = true;
        _log(QStringLiteral("%1 fd %2 -> unpacked image (%3 bytes)")
                 .arg(bExecveAt ? QStringLiteral("execveat") : QStringLiteral("execve"))
                 .arg(nTargetFd)
                 .arg(m_baExecImage.size()));
    } else {
        _log(QStringLiteral("execve: could not resolve a target descriptor"));
    }

    return false;  // the process image is replaced -> stop emulation
}

bool XEmuLinuxSyscalls::dispatch(XEmuRegisters *pRegisters)
{
    quint64 nNumber = _number(pRegisters);
    SCK_KIND kind = _classify(nNumber);

    switch (kind) {
        case SCK_MMAP: _return(pRegisters, _sysMmap(pRegisters, false)); return true;
        case SCK_MMAP2: _return(pRegisters, _sysMmap(pRegisters, true)); return true;
        case SCK_MPROTECT: _return(pRegisters, _sysMprotect(pRegisters)); return true;
        case SCK_MUNMAP:
            // Keep the memory mapped (we want it for the dump, and a shared mapping
            // is flushed to its file on the next mmap of the same fd); report success.
            _log(QStringLiteral("munmap(0x%1, 0x%2) = 0 (kept)").arg(_arg(pRegisters, 0), 0, 16).arg(_arg(pRegisters, 1), 0, 16));
            _return(pRegisters, 0);
            return true;
        case SCK_MSYNC: {
            // Flush the shared mapping(s) covering the range back into their files, so
            // the executable re-map the stub makes next reflects the decompressed data.
            XADDR nAddr = (XADDR)_arg(pRegisters, 0);
            quint64 nLen = _arg(pRegisters, 1);
            for (int i = 0; i < m_sharedMaps.size(); i++) {
                const SHARED_MAP &m = m_sharedMaps.at(i);
                if ((m.nBase < nAddr + nLen) && (nAddr < m.nBase + m.nLen)) {
                    _syncMapsToFile(m.nFd);
                }
            }
            _log(QStringLiteral("msync(0x%1, 0x%2) = 0").arg(nAddr, 0, 16).arg(nLen, 0, 16));
            _return(pRegisters, 0);
            return true;
        }
        case SCK_BRK: _return(pRegisters, _sysBrk(pRegisters)); return true;
        case SCK_ARCH_PRCTL: _return(pRegisters, _sysArchPrctl(pRegisters)); return true;
        case SCK_SET_THREAD_AREA: _return(pRegisters, 0); return true;
        case SCK_WRITE: _return(pRegisters, _sysWrite(pRegisters)); return true;
        case SCK_READ: _return(pRegisters, _sysRead(pRegisters)); return true;
        case SCK_OPEN: {
            // open(path, flags, mode): path/flags in arg0/arg1; openat(dirfd, path, flags, mode): arg1/arg2.
            bool bAt = (nNumber == 257) || (nNumber == 295);
            quint64 nFlags = bAt ? _arg(pRegisters, 2) : _arg(pRegisters, 1);
            QString sPath = _readStr((XADDR)_arg(pRegisters, bAt ? 1 : 0));
            _return(pRegisters, _sysOpen(pRegisters, false, nFlags, sPath));
            return true;
        }
        case SCK_MEMFD: _return(pRegisters, _sysOpen(pRegisters, true, 0, QString())); return true;
        case SCK_READLINK: _return(pRegisters, _sysReadlink(pRegisters)); return true;
        case SCK_FTRUNCATE: _return(pRegisters, _sysFtruncate(pRegisters)); return true;
        case SCK_LSEEK: _return(pRegisters, _sysLseek(pRegisters)); return true;
        case SCK_PWRITE: _return(pRegisters, _sysPwrite(pRegisters)); return true;
        case SCK_FSTAT: _return(pRegisters, _sysFstat(pRegisters)); return true;
        case SCK_CLOSE: _return(pRegisters, 0); return true;  // keep the file for later mmap
        case SCK_DUP: _return(pRegisters, _arg(pRegisters, 0)); return true;
        case SCK_EXECVE: return _sysExecve(pRegisters, false);
        case SCK_EXECVEAT: return _sysExecve(pRegisters, true);
        case SCK_IGNORED: _return(pRegisters, 0); return true;
        case SCK_EXIT:
        case SCK_EXIT_GROUP:
            m_bExited = true;
            m_nExitCode = (int)_arg(pRegisters, 0);
            _log(QStringLiteral("%1(%2)").arg(kind == SCK_EXIT ? QStringLiteral("exit") : QStringLiteral("exit_group")).arg(m_nExitCode));
            return false;  // stop execution
        case SCK_UNKNOWN:
        default:
            _log(QStringLiteral("unhandled syscall %1 -> -ENOSYS").arg(nNumber));
            _return(pRegisters, errnoRet(LNX_ENOSYS));
            return true;
    }
}
