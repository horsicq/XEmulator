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
#include "xemubsdsyscalls.h"

// BSD/Darwin mmap protection / flag bits.
static const quint64 PROT_READ = 0x1;
static const quint64 PROT_WRITE = 0x2;
static const quint64 PROT_EXEC = 0x4;
static const quint64 MAP_FIXED = 0x10;
static const quint64 MAP_ANON = 0x1000;  // NB: differs from Linux (0x20)
static const quint64 MAP_FAILED = (quint64)-1;

// Darwin tags a syscall number with its class in the high byte; 0x2000000 = BSD/Unix.
static const quint64 SYSCALL_CLASS_MASK = 0xFF000000;
static const quint64 SYSCALL_CLASS_UNIX = 0x2000000;
static const quint64 SYSCALL_NUMBER_MASK = 0x00FFFFFF;

static const quint64 BSD_ENOSYS = 78;

XEmuBSDSyscalls::XEmuBSDSyscalls(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64, FLAVOR flavor)
    : m_pMemoryManager(pMemoryManager), m_pArch(pArch), m_bIs64(bIs64), m_flavor(flavor), m_nNextFd(3), m_bExited(false), m_nExitCode(0)
{
}

void XEmuBSDSyscalls::setLogger(const LOG_CALLBACK &fnLog)
{
    m_fnLog = fnLog;
}

void XEmuBSDSyscalls::_log(const QString &sText) const
{
    if (m_fnLog) {
        m_fnLog(sText);
    }
}

void XEmuBSDSyscalls::reset()
{
    m_bExited = false;
    m_nExitCode = 0;
    m_nNextFd = 3;
    m_files.clear();
}

void XEmuBSDSyscalls::setSelfExe(const QByteArray &baBytes, const QString &sPath)
{
    m_baSelfExe = baBytes;
    m_sSelfPath = sPath;
}

bool XEmuBSDSyscalls::hasExited() const
{
    return m_bExited;
}

int XEmuBSDSyscalls::exitCode() const
{
    return m_nExitCode;
}

int XEmuBSDSyscalls::_newFd()
{
    return m_nNextFd++;
}

XEmuBSDSyscalls::SCK_KIND XEmuBSDSyscalls::_classify(quint64 nNumber) const
{
    // FreeBSD and Darwin share the classic BSD numbering for the calls we model.
    switch (nNumber) {
        case 1: return SCK_EXIT;
        case 3: return SCK_READ;
        case 4: return SCK_WRITE;
        case 5: return SCK_OPEN;
        case 6: return SCK_CLOSE;
        case 73: return SCK_MUNMAP;
        case 74: return SCK_MPROTECT;
        case 75: return SCK_MADVISE;
        case 78: return SCK_MINCORE;
        case 197: return SCK_MMAP;    // classic mmap
        case 477: return SCK_MMAP;    // FreeBSD modern mmap
        case 199: return SCK_LSEEK;   // classic lseek
        case 478: return SCK_LSEEK;   // FreeBSD modern lseek
        case 189: return SCK_FSTAT;   // Darwin fstat / FreeBSD fstat(551 on modern)
        case 551: return SCK_FSTAT;
        case 202: return SCK_SYSCTL;  // __sysctl
        // Known-but-irrelevant-before-OEP.
        case 20:   // getpid
        case 24:   // getuid
        case 43:   // getegid
        case 47:   // getgid
        case 48:   // getppid / sigprocmask (flavour-dependent)
        case 58:   // readlink
        case 327:  // issetugid
        case 336:  // sysctlbyname-ish
            return SCK_IGNORED;
        default: return SCK_UNKNOWN;
    }
}

quint64 XEmuBSDSyscalls::_number(XEmuRegisters *pRegisters) const
{
    quint64 nRax = pRegisters->getGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4);

    // Strip Darwin's syscall class tag (0x2000000 for BSD/Unix).
    if ((m_flavor == FLAVOR_DARWIN) && ((nRax & SYSCALL_CLASS_MASK) == SYSCALL_CLASS_UNIX)) {
        return nRax & SYSCALL_NUMBER_MASK;
    }
    return nRax;
}

quint64 XEmuBSDSyscalls::_arg(XEmuRegisters *pRegisters, int nIndex) const
{
    if (m_bIs64) {
        static const int s_regs[6] = {XEmuRegisters::GPR_RDI, XEmuRegisters::GPR_RSI, XEmuRegisters::GPR_RDX,
                                      XEmuRegisters::GPR_R10, XEmuRegisters::GPR_R8,  XEmuRegisters::GPR_R9};
        return (nIndex >= 0 && nIndex < 6) ? pRegisters->getGPR(s_regs[nIndex], 8) : 0;
    }

    // 32-bit BSD passes arguments on the stack, above the return address.
    XADDR nEsp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, 4);
    return m_pMemoryManager->readDword(nEsp + 4 + (quint64)nIndex * 4);
}

void XEmuBSDSyscalls::_returnOk(XEmuRegisters *pRegisters, quint64 nValue)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4, nValue);
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);  // BSD success: carry clear
}

void XEmuBSDSyscalls::_returnErr(XEmuRegisters *pRegisters, quint64 nErrno)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, m_bIs64 ? 8 : 4, nErrno);
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, true);  // BSD error: carry set, errno in RAX
}

QString XEmuBSDSyscalls::_readStr(XADDR nAddress, int nMax) const
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

XEmuMemoryManager::MEMORY_FLAGS XEmuBSDSyscalls::_flagsFromProt(quint64 nProt) const
{
    bool bRead = (nProt & PROT_READ) != 0;
    bool bWrite = (nProt & PROT_WRITE) != 0;
    bool bExec = (nProt & PROT_EXEC) != 0;
    return XEmuMemoryManager::MEMORY_FLAGS(bRead || bWrite || bExec || (nProt == 0), bWrite, bExec);
}

quint64 XEmuBSDSyscalls::_sysMmap(XEmuRegisters *pRegisters)
{
    XADDR nAddr = (XADDR)_arg(pRegisters, 0);
    quint64 nLen = _arg(pRegisters, 1);
    quint64 nProt = _arg(pRegisters, 2);
    quint64 nFlags = _arg(pRegisters, 3);
    qint64 nFd = (qint64)_arg(pRegisters, 4);
    quint64 nOffset = _arg(pRegisters, 5);

    if (nLen == 0) {
        return MAP_FAILED;
    }

    quint64 nSize = XEmuMemoryManager::alignUp(nLen, XEmuMemoryManager::N_PAGE_SIZE);
    XEmuMemoryManager::MEMORY_FLAGS flags = _flagsFromProt(nProt);
    XADDR nBase = 0;

    if ((nFlags & MAP_FIXED) && (nAddr != 0)) {
        XADDR nAligned = XEmuMemoryManager::alignDown(nAddr, XEmuMemoryManager::N_PAGE_SIZE);
        nSize = XEmuMemoryManager::alignUp(nLen + (nAddr - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

        if (m_pMemoryManager->isCommitted(nAligned, 1)) {
            m_pMemoryManager->protect(nAligned, nSize, flags);
            nBase = nAligned;
        } else {
            nBase = m_pMemoryManager->allocate(nAligned, nSize, flags, QStringLiteral("mmap"));
            if ((nBase == 0) && m_pMemoryManager->commit(nAligned, nSize, flags)) {
                nBase = nAligned;
            }
        }
        if ((nBase != 0) && (nFlags & MAP_ANON)) {
            m_pMemoryManager->write(nBase, QByteArray((int)nSize, 0));
        }
    } else {
        nBase = m_pMemoryManager->allocate(nAddr, nSize, flags, QStringLiteral("mmap"));
        if ((nBase == 0) && (nAddr != 0)) {
            nBase = m_pMemoryManager->allocate(0, nSize, flags, QStringLiteral("mmap"));
        }
    }

    // File-backed mapping: copy the descriptor's bytes into the region.
    if ((nBase != 0) && !(nFlags & MAP_ANON) && (nFd >= 0) && m_files.contains((int)nFd)) {
        const QByteArray &baFile = m_files[(int)nFd].baData;
        if ((quint64)baFile.size() > nOffset) {
            quint64 nCopy = qMin<quint64>(nLen, (quint64)baFile.size() - nOffset);
            m_pMemoryManager->write(nBase, QByteArray(baFile.constData() + nOffset, (int)nCopy));
        }
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

quint64 XEmuBSDSyscalls::_sysMprotect(XEmuRegisters *pRegisters)
{
    XADDR nAddr = (XADDR)_arg(pRegisters, 0);
    quint64 nLen = _arg(pRegisters, 1);
    quint64 nProt = _arg(pRegisters, 2);

    XADDR nAligned = XEmuMemoryManager::alignDown(nAddr, XEmuMemoryManager::N_PAGE_SIZE);
    quint64 nSize = XEmuMemoryManager::alignUp(nLen + (nAddr - nAligned), XEmuMemoryManager::N_PAGE_SIZE);

    bool bOk = m_pMemoryManager->protect(nAligned, nSize, _flagsFromProt(nProt));
    _log(QStringLiteral("mprotect(0x%1, 0x%2, prot=%3) = %4").arg(nAddr, 0, 16).arg(nLen, 0, 16).arg(nProt).arg(bOk ? 0 : -1));
    return bOk ? 0 : 12;  // ENOMEM
}

quint64 XEmuBSDSyscalls::_sysOpen(XEmuRegisters *pRegisters, quint64 nFlags, const QString &sPath)
{
    Q_UNUSED(pRegisters)

    const quint64 O_ACCMODE = 0x3;
    const quint64 O_CREAT = 0x200;  // BSD/Darwin O_CREAT (differs from Linux 0x40)
    bool bReadOnly = ((nFlags & O_ACCMODE) == 0) && ((nFlags & O_CREAT) == 0);

    bool bSelf = sPath.isEmpty() || (!m_sSelfPath.isEmpty() && (sPath == m_sSelfPath)) || sPath.contains(QStringLiteral("/self"));

    int nFd = _newFd();
    FAKE_FILE file;
    if (bReadOnly && bSelf && !m_baSelfExe.isEmpty()) {
        file.baData = m_baSelfExe;
    } else if (bReadOnly && !bSelf) {
        _log(QStringLiteral("open(\"%1\") = ENOENT").arg(sPath));
        return (quint64)-1;  // caller path returns error via CF
    }

    m_files.insert(nFd, file);
    _log(QStringLiteral("open(\"%1\") = fd %2 (%3 bytes)").arg(sPath).arg(nFd).arg(file.baData.size()));
    return (quint64)nFd;
}

quint64 XEmuBSDSyscalls::_sysRead(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nCount = _arg(pRegisters, 2);

    if (!m_files.contains(nFd)) {
        return 0;
    }
    FAKE_FILE &file = m_files[nFd];
    if (file.nOffset >= (quint64)file.baData.size()) {
        return 0;
    }
    quint64 nAvail = qMin<quint64>(nCount, (quint64)file.baData.size() - file.nOffset);
    m_pMemoryManager->write(nBuf, QByteArray(file.baData.constData() + file.nOffset, (int)nAvail));
    file.nOffset += nAvail;
    return nAvail;
}

quint64 XEmuBSDSyscalls::_sysWrite(XEmuRegisters *pRegisters)
{
    int nFd = (int)_arg(pRegisters, 0);
    XADDR nBuf = (XADDR)_arg(pRegisters, 1);
    quint64 nCount = _arg(pRegisters, 2);

    if (m_files.contains(nFd)) {
        bool bOk = false;
        QByteArray baBuf = m_pMemoryManager->read(nBuf, nCount, &bOk);
        FAKE_FILE &file = m_files[nFd];
        quint64 nNeeded = file.nOffset + (quint64)baBuf.size();
        if ((quint64)file.baData.size() < nNeeded) {
            file.baData.resize((int)nNeeded);
        }
        if (bOk) {
            memcpy(file.baData.data() + file.nOffset, baBuf.constData(), baBuf.size());
        }
        file.nOffset += (quint64)baBuf.size();
    }
    return nCount;
}

bool XEmuBSDSyscalls::dispatch(XEmuRegisters *pRegisters)
{
    quint64 nNumber = _number(pRegisters);

    switch (_classify(nNumber)) {
        case SCK_MMAP: {
            quint64 r = _sysMmap(pRegisters);
            if (r == MAP_FAILED) {
                _returnErr(pRegisters, 12);  // ENOMEM
            } else {
                _returnOk(pRegisters, r);
            }
            return true;
        }
        case SCK_MPROTECT: {
            quint64 r = _sysMprotect(pRegisters);
            (r == 0) ? _returnOk(pRegisters, 0) : _returnErr(pRegisters, r);
            return true;
        }
        case SCK_MUNMAP:
            _log(QStringLiteral("munmap(0x%1, 0x%2) = 0 (kept)").arg(_arg(pRegisters, 0), 0, 16).arg(_arg(pRegisters, 1), 0, 16));
            _returnOk(pRegisters, 0);
            return true;
        case SCK_MADVISE:
        case SCK_MINCORE:
        case SCK_SYSCTL:
        case SCK_IGNORED: _returnOk(pRegisters, 0); return true;
        case SCK_OPEN: {
            QString sPath = _readStr((XADDR)_arg(pRegisters, 0));
            quint64 nFlags = _arg(pRegisters, 1);
            quint64 r = _sysOpen(pRegisters, nFlags, sPath);
            if (r == (quint64)-1) {
                _returnErr(pRegisters, 2);  // ENOENT
            } else {
                _returnOk(pRegisters, r);
            }
            return true;
        }
        case SCK_READ: _returnOk(pRegisters, _sysRead(pRegisters)); return true;
        case SCK_WRITE: _returnOk(pRegisters, _sysWrite(pRegisters)); return true;
        case SCK_CLOSE: _returnOk(pRegisters, 0); return true;
        case SCK_LSEEK: {
            int nFd = (int)_arg(pRegisters, 0);
            quint64 nOff = _arg(pRegisters, 1);
            if (m_files.contains(nFd)) {
                m_files[nFd].nOffset = nOff;  // SEEK_SET only (sufficient for stubs)
            }
            _returnOk(pRegisters, nOff);
            return true;
        }
        case SCK_FSTAT: _returnOk(pRegisters, 0); return true;
        case SCK_EXIT:
            m_bExited = true;
            m_nExitCode = (int)_arg(pRegisters, 0);
            _log(QStringLiteral("exit(%1)").arg(m_nExitCode));
            return false;  // stop
        case SCK_UNKNOWN:
        default:
            _log(QStringLiteral("unhandled syscall %1 -> -ENOSYS").arg(nNumber));
            _returnErr(pRegisters, BSD_ENOSYS);
            return true;
    }
}
