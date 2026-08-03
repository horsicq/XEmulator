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
#include "xemumsdosint.h"

#include <QDate>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTime>

#include "xemumemorymanager.h"
#include "xemuregisters.h"

namespace {
quint8 ah(XEmuRegisters *pRegisters)
{
    return (quint8)((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2) >> 8) & 0xFF);
}
void setAL(XEmuRegisters *pRegisters, quint8 v)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, v);
}
void setAH(XEmuRegisters *pRegisters, quint8 v)
{
    quint64 nAx = pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, (nAx & 0x00FF) | ((quint64)v << 8));
}
void setAX(XEmuRegisters *pRegisters, quint16 v)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, v);
}
void setBX(XEmuRegisters *pRegisters, quint16 v)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, v);
}
void setCX(XEmuRegisters *pRegisters, quint16 v)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, v);
}
void setDX(XEmuRegisters *pRegisters, quint16 v)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, v);
}
void setCF(XEmuRegisters *pRegisters, bool b)
{
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, b);
}

// DOS error codes returned in AX when CF is set.
enum { DOSERR_FILE_NOT_FOUND = 2, DOSERR_PATH_NOT_FOUND = 3, DOSERR_TOO_MANY_OPEN = 4, DOSERR_ACCESS_DENIED = 5, DOSERR_INVALID_HANDLE = 6 };

// DOS reserved character-device names, matched on the base name (path + extension stripped),
// case-insensitively. Returns 1 for NUL/PRN/AUX/LPTn/COMn (writes discarded, reads EOF), 2 for
// CON (console), 0 for an ordinary file. Programs open "NUL" to discard output (PGMPAK does).
int deviceKind(const QByteArray &baDosName)
{
    QByteArray b = baDosName.toUpper();
    int nCut = b.lastIndexOf('\\');
    nCut = qMax(nCut, b.lastIndexOf('/'));
    nCut = qMax(nCut, (int)b.lastIndexOf(':'));
    b = b.mid(nCut + 1);
    int nDot = b.indexOf('.');
    if (nDot >= 0) {
        b = b.left(nDot);
    }
    b = b.trimmed();
    if ((b == "NUL") || (b == "PRN") || (b == "AUX") || (b == "LPT1") || (b == "LPT2") || (b == "LPT3") ||
        (b == "COM1") || (b == "COM2") || (b == "COM3") || (b == "COM4")) {
        return 1;
    }
    if (b == "CON") {
        return 2;
    }
    return 0;
}
}  // namespace

XEmuMsdosInt::XEmuMsdosInt(XEmuMemoryManager *pMemoryManager) : m_pMemoryManager(pMemoryManager), m_nPspSeg(0), m_nTempSeq(0), m_nAllocSeg(0xC000), m_nFirstMcb(0), m_nDtaAddr(0), m_nDtaSeg(0), m_nDtaOff(0), m_nFindIndex(0)
{
}

// --- DOS memory-control-block chain (real MCB format, kept in guest memory so programs can walk it) ---
// MCB @ segment S: byte[0]='M'(0x4D more)/'Z'(0x5A last), word[1]=owner PSP (0=free), word[3]=size paras.
// The block's usable memory is S+1 for <size> paragraphs; the next MCB is at S + 1 + size.
quint8 XEmuMsdosInt::_mcbType(quint16 nMcb) const { return m_pMemoryManager->readByte((XADDR)nMcb << 4); }
quint16 XEmuMsdosInt::_mcbOwner(quint16 nMcb) const { return m_pMemoryManager->readWord(((XADDR)nMcb << 4) + 1); }
quint16 XEmuMsdosInt::_mcbSize(quint16 nMcb) const { return m_pMemoryManager->readWord(((XADDR)nMcb << 4) + 3); }
void XEmuMsdosInt::_mcbWrite(quint16 nMcb, quint8 nType, quint16 nOwner, quint16 nSize)
{
    const XADDR b = (XADDR)nMcb << 4;
    m_pMemoryManager->writeByte(b, nType);
    m_pMemoryManager->writeWord(b + 1, nOwner);
    m_pMemoryManager->writeWord(b + 3, nSize);
}

void XEmuMsdosInt::mcbSetup(quint16 nEnvSeg, quint16 nEnvParas, quint16 nPspSeg, quint16 nPspParas, quint16 nMemTop)
{
    // Initial chain matching DOS: the environment block (owned by the PSP) directly below the PSP, then
    // the program block, then -- for a normal program that didn't grab everything -- a trailing free block
    // up to the conventional-memory top. The program shrinks/splits its block with AH=4A to make room for
    // children.
    const quint16 nEnvMcb = (quint16)(nEnvSeg - 1);
    const quint16 nPspMcb = (quint16)(nPspSeg - 1);
    _mcbWrite(nEnvMcb, 0x4D, nPspSeg, nEnvParas);  // 'M' env block
    const quint16 nAfterPsp = (quint16)(nPspSeg + nPspParas);
    if (nAfterPsp < nMemTop) {  // program block plus a trailing free block
        _mcbWrite(nPspMcb, 0x4D, nPspSeg, nPspParas);
        _mcbWrite(nAfterPsp, 0x5A, 0, (quint16)(nMemTop - nAfterPsp - 1));
    } else {  // program owns everything up to the top
        _mcbWrite(nPspMcb, 0x5A, nPspSeg, (quint16)(nMemTop - nPspSeg));
    }
    m_nFirstMcb = nEnvMcb;
}

// Claim the block starting at nSeg for nOwner, splitting the block that currently contains it so nSeg
// becomes a distinct owned block. Used by AH=55 (create child PSP) which reserves a block mid-arena --
// this keeps the free regions on either side separate (DOS does not coalesce across an owned block).
void XEmuMsdosInt::_mcbClaim(quint16 nSeg, quint16 nOwner)
{
    if (!m_nFirstMcb) {
        return;
    }
    for (quint16 nMcb = m_nFirstMcb;;) {
        const quint16 nType = _mcbType(nMcb);
        const quint16 nSize = _mcbSize(nMcb);
        const quint16 nStart = (quint16)(nMcb + 1);
        if ((nSeg >= nStart) && (nSeg < nStart + nSize)) {
            if (nSeg == nStart) {  // whole block
                _mcbWrite(nMcb, nType, nOwner, nSize);
            } else {  // split: [nMcb .. nSeg-2] keeps its owner, [nSeg-1 MCB, block nSeg] -> nOwner
                const quint16 nSize1 = (quint16)(nSeg - nStart - 1);
                const quint16 nSize2 = (quint16)(nStart + nSize - nSeg);
                _mcbWrite((quint16)(nSeg - 1), nType, nOwner, nSize2);
                _mcbWrite(nMcb, 0x4D, _mcbOwner(nMcb), nSize1);
            }
            return;
        }
        if (nType == 0x5A) {
            return;
        }
        nMcb = (quint16)(nMcb + 1 + nSize);
    }
}

// AH=48: first-fit allocate nParas paragraphs. On success *pnSeg = block segment. On failure returns
// false with *pnMaxParas = the largest free block available (DOS convention).
bool XEmuMsdosInt::_memAlloc(quint16 nParas, quint16 *pnSeg, quint16 *pnMaxParas)
{
    quint16 nBest = 0;
    for (quint16 nMcb = m_nFirstMcb;;) {
        const quint16 nSize = _mcbSize(nMcb);
        if (_mcbOwner(nMcb) == 0) {  // free block
            if (nSize > nBest) {
                nBest = nSize;
            }
            if (nSize >= nParas) {
                if (nSize > nParas + 1) {  // split: keep a trailing free MCB
                    const quint16 nRest = (quint16)(nMcb + 1 + nParas);
                    _mcbWrite(nRest, _mcbType(nMcb), 0, (quint16)(nSize - nParas - 1));
                    _mcbWrite(nMcb, 0x4D, m_nPspSeg, nParas);
                } else {
                    _mcbWrite(nMcb, _mcbType(nMcb), m_nPspSeg, nSize);  // take the whole block
                }
                *pnSeg = (quint16)(nMcb + 1);
                return true;
            }
        }
        if (_mcbType(nMcb) == 0x5A) {
            break;  // last block
        }
        nMcb = (quint16)(nMcb + 1 + nSize);
    }
    *pnMaxParas = nBest;
    return false;
}

bool XEmuMsdosInt::_memFree(quint16 nSeg)
{
    const quint16 nMcb = (quint16)(nSeg - 1);
    if (_mcbOwner(nMcb) == 0) {
        return true;  // already free
    }
    _mcbWrite(nMcb, _mcbType(nMcb), 0, _mcbSize(nMcb));  // mark free (coalescing happens in _memAlloc walk lazily)
    // Coalesce with the following block if it is also free.
    while (_mcbType(nMcb) != 0x5A) {
        const quint16 nNext = (quint16)(nMcb + 1 + _mcbSize(nMcb));
        if (_mcbOwner(nNext) != 0) {
            break;
        }
        _mcbWrite(nMcb, _mcbType(nNext), 0, (quint16)(_mcbSize(nMcb) + 1 + _mcbSize(nNext)));
    }
    return true;
}

// AH=4A: resize the block at nSeg to nParas. Grows into a trailing free block if possible, else shrinks.
bool XEmuMsdosInt::_memResize(quint16 nSeg, quint16 nParas, quint16 *pnMaxParas)
{
    const quint16 nMcb = (quint16)(nSeg - 1);
    quint16 nCur = _mcbSize(nMcb);
    quint16 nType = _mcbType(nMcb);
    quint16 nOwner = _mcbOwner(nMcb);
    // Absorb an immediately-following free block so we know the largest we can become.
    while (nType != 0x5A) {
        const quint16 nNext = (quint16)(nMcb + 1 + nCur);
        if (_mcbOwner(nNext) != 0) {
            break;
        }
        nCur = (quint16)(nCur + 1 + _mcbSize(nNext));
        nType = _mcbType(nNext);
    }
    if (nParas > nCur) {  // cannot grow this far
        _mcbWrite(nMcb, nType, nOwner, nCur);  // leave it at the max we could reach
        *pnMaxParas = nCur;
        return false;
    }
    if (nParas < nCur - 1) {  // shrink: split off a trailing free block
        const quint16 nRest = (quint16)(nMcb + 1 + nParas);
        _mcbWrite(nRest, nType, 0, (quint16)(nCur - nParas - 1));
        _mcbWrite(nMcb, 0x4D, nOwner, nParas);
    } else {
        _mcbWrite(nMcb, nType, nOwner, nCur);  // exact fit (or 1-para remainder absorbed)
    }
    return true;
}

void XEmuMsdosInt::_fillFindRecord(const QString &sFileName)
{
    // 43-byte find record at the DTA (bytes 0..20 are the search-state area we don't need to
    // populate because find-next state lives in this object): +0x15 attribute, +0x16 time,
    // +0x18 date, +0x1A size (dword), +0x1E filename ("NAME.EXT", ASCIIZ, up to 13 bytes).
    QFileInfo fi(m_sFindDir + QLatin1Char('/') + sFileName);
    XADDR nDta = m_nDtaAddr;

    // Search-state area (bytes 0..20): real DOS stores the drive, the 11-byte FCB-format search
    // template and the search attribute here. Some tools rebuild the open path from the FCB
    // template rather than the ASCIIZ name, so populate it.
    QString sBase = sFileName.section(QLatin1Char('.'), 0, 0).toUpper();
    QString sExt = sFileName.contains(QLatin1Char('.')) ? sFileName.section(QLatin1Char('.'), 1).toUpper() : QString();
    m_pMemoryManager->writeByte(nDta + 0x00, 0x03);  // search drive (C:)
    for (int i = 0; i < 8; i++) {
        m_pMemoryManager->writeByte(nDta + 0x01 + i, (i < sBase.size()) ? (quint8)sBase.at(i).toLatin1() : (quint8)' ');
    }
    for (int i = 0; i < 3; i++) {
        m_pMemoryManager->writeByte(nDta + 0x09 + i, (i < sExt.size()) ? (quint8)sExt.at(i).toLatin1() : (quint8)' ');
    }
    m_pMemoryManager->writeByte(nDta + 0x0C, 0x00);  // search attribute
    m_pMemoryManager->writeWord(nDta + 0x0D, (quint16)m_nFindIndex);  // directory entry index

    m_pMemoryManager->writeByte(nDta + 0x15, 0x20);   // archive attribute
    m_pMemoryManager->writeWord(nDta + 0x16, 0x0000);  // time
    m_pMemoryManager->writeWord(nDta + 0x18, 0x0021);  // date = 1980-01-01
    quint32 nSize = (quint32)qMin<qint64>(fi.size(), 0xFFFFFFFFll);
    m_pMemoryManager->writeWord(nDta + 0x1A, (quint16)(nSize & 0xFFFF));
    m_pMemoryManager->writeWord(nDta + 0x1C, (quint16)((nSize >> 16) & 0xFFFF));
    QByteArray baName = sFileName.toUpper().toLatin1();
    baName.truncate(12);
    for (int i = 0; i < 13; i++) {
        m_pMemoryManager->writeByte(nDta + 0x1E + i, (i < baName.size()) ? (quint8)baName.at(i) : 0);
    }
}

XEmuMsdosInt::~XEmuMsdosInt()
{
    for (QFile *pFile : m_mapFiles) {
        delete pFile;  // QFile closes on destruction
    }
    m_mapFiles.clear();
}

QByteArray XEmuMsdosInt::_readAsciiz(quint64 nBase, quint16 nOffset, int nMax) const
{
    QByteArray ba;
    for (int i = 0; i < nMax; i++) {
        bool bOk = false;
        quint8 c = m_pMemoryManager->readByte(nBase + ((nOffset + i) & 0xFFFF), &bOk);
        if (!bOk || (c == 0)) {
            break;
        }
        ba.append((char)c);
    }
    return ba;
}

QString XEmuMsdosInt::_resolvePath(const QByteArray &baDosName) const
{
    QString s = QString::fromLatin1(baDosName);
    s.replace(QLatin1Char('\\'), QLatin1Char('/'));

    // Drop a drive specifier ("C:...") -- everything lives under the working directory.
    if ((s.size() >= 2) && (s.at(1) == QLatin1Char(':'))) {
        s = s.mid(2);
    }
    while (s.startsWith(QLatin1Char('/'))) {  // treat an absolute DOS path as relative to the root
        s = s.mid(1);
    }

    // A trailing '.' is an empty DOS extension ("XT000000." == "XT000000"); strip it from the final
    // path component so host lookups match the name the file was created under. Programs (PGMPAK)
    // create a temp without an extension then reference it dotted -- a mismatch loses the delete.
    int nSlash = s.lastIndexOf(QLatin1Char('/'));
    QString sComp = s.mid(nSlash + 1);
    if ((sComp != QLatin1String(".")) && (sComp != QLatin1String(".."))) {
        while (sComp.endsWith(QLatin1Char('.'))) {
            sComp.chop(1);
        }
        s = (nSlash >= 0 ? s.left(nSlash + 1) : QString()) + sComp;
    }

    QString sBase = m_sWorkingDirectory.isEmpty() ? QDir::currentPath() : m_sWorkingDirectory;
    if (s.isEmpty()) {
        return sBase;
    }
    return QDir(sBase).filePath(s);
}

// Real DOS routes every handle through one shared buffer cache, so a program may write a file
// through one handle and read those bytes back through a SECOND handle opened on the same file
// without closing the first. Each of our handles is an independent QFile with its own write buffer,
// so the reader would see a stale (often empty) file. Flushing the other handles on the same path
// restores the DOS-visible behaviour. Protect! EXE-COM 6.0 depends on this: for inputs large enough
// to spill, it writes PREXCM.TMP, then re-opens it while the writing handle is still open.
void XEmuMsdosInt::_syncPath(const QString &sPath, int nExceptHandle)
{
    if (m_mapFiles.size() < 2) {  // called on every read: nothing to synchronise against
        return;
    }
    for (QMap<int, QFile *>::const_iterator it = m_mapFiles.constBegin(); it != m_mapFiles.constEnd(); ++it) {
        if (it.key() == nExceptHandle) {
            continue;
        }
        QFile *pFile = it.value();
        if (pFile && pFile->isOpen() && pFile->isWritable() && (QDir::cleanPath(pFile->fileName()).compare(QDir::cleanPath(sPath), Qt::CaseInsensitive) == 0)) {
            pFile->flush();
        }
    }
}

// DOS allocates the LOWEST free entry of the process's Job File Table, so a program that closes a
// handle and immediately reopens gets the SAME number back. Handing out a monotonically increasing
// counter instead looks harmless but is not: Protect! EXE-COM 6.0 closes handles 14 and 15, reopens
// its output, and then keeps addressing handle 14 -- which is correct under DOS and a dead handle
// under a counter, so every following seek/read/write failed and it aborted with "An error occured
// during a file read or write". Handles 0..4 are the inherited standard ones.
int XEmuMsdosInt::_lowestFreeHandle() const
{
    int nHandle = 5;
    while (m_mapFiles.contains(nHandle) || m_conHandles.contains(nHandle) || m_nulHandles.contains(nHandle)) {
        nHandle++;
    }
    return nHandle;
}

int XEmuMsdosInt::_allocHandle(QFile *pFile)
{
    int nHandle = _lowestFreeHandle();
    m_mapFiles.insert(nHandle, pFile);
    return nHandle;
}

// DOS lets a file be deleted, or renamed over, while handles to it are still open: the directory
// entry simply goes away and the stale handle is the program's problem. Windows refuses any such
// operation while a handle is open, which breaks the universal self-replacing-packer idiom
// "open input / write temp / delete input / rename temp -> input" at the final step (AVPack fails
// with "Can't rename temporary file"). Release our host handles for that path first; the DOS handle
// stays allocated, so a program that keeps using it just reads nothing, as it would on real DOS.
void XEmuMsdosInt::_releaseHostFile(const QString &sPath)
{
    const QString sTarget = QFileInfo(sPath).absoluteFilePath();
    for (QMap<int, QFile *>::const_iterator it = m_mapFiles.constBegin(); it != m_mapFiles.constEnd(); ++it) {
        QFile *pFile = it.value();
        if (pFile && pFile->isOpen() && (QFileInfo(pFile->fileName()).absoluteFilePath() == sTarget)) {
            pFile->close();
        }
    }
}

bool XEmuMsdosInt::_fileFunction(quint8 nAH, XEmuRegisters *pRegisters)
{
    quint64 nDsBase = ((quint64)pRegisters->nDS) << 4;
    quint16 nDX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2);
    quint16 nCX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RCX, 2);
    quint16 nBX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2);

    auto fail = [&](quint16 nCode) {
        setAX(pRegisters, nCode);
        setCF(pRegisters, true);
    };

    switch (nAH) {
        case 0x3C: {  // create/truncate file: DS:DX=name, CX=attributes -> AX=handle
            QByteArray baName = _readAsciiz(nDsBase, nDX);
            if (int nDev = deviceKind(baName)) {  // creating on a device (e.g. NUL): hand out a device handle
                int nHandle = _lowestFreeHandle();
                (nDev == 2 ? m_conHandles : m_nulHandles).insert(nHandle);
                setAX(pRegisters, (quint16)nHandle);
                setCF(pRegisters, false);
                return true;
            }
            QString sPath = _resolvePath(baName);
            QFile *pFile = new QFile(sPath);
            if (!pFile->open(QIODevice::ReadWrite | QIODevice::Truncate)) {
                delete pFile;
                _log(QStringLiteral("INT 21h.3C create '%1' failed").arg(sPath));
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            int nHandle = _allocHandle(pFile);
            setAX(pRegisters, (quint16)nHandle);
            setCF(pRegisters, false);
            _log(QStringLiteral("INT 21h.3C create '%1' -> handle %2").arg(sPath).arg(nHandle));
            return true;
        }

        case 0x5A: {  // create unique/temporary file: DS:DX = ASCIIZ dir path (empty or ending in '\'),
                      // CX = attributes. DOS appends a generated unique name to the buffer at DS:DX,
                      // creates the file, and returns AX = handle. PGMPAK uses this for its scratch file.
            QByteArray baDir = _readAsciiz(nDsBase, nDX);
            QByteArray baName, baFull;
            QString sHostPath;
            for (int i = 0; i < 100000; i++) {
                baName = QByteArrayLiteral("XT") + QByteArray::number((uint)(m_nTempSeq++ & 0xFFFFFF), 16).toUpper().rightJustified(6, '0');
                baFull = baDir + baName;  // the directory buffer already ends in a separator (or is empty)
                sHostPath = _resolvePath(baFull);
                if (!QFileInfo::exists(sHostPath)) {
                    break;
                }
            }
            QFile *pFile = new QFile(sHostPath);
            if (!pFile->open(QIODevice::ReadWrite | QIODevice::Truncate)) {
                delete pFile;
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            int nHandle = _allocHandle(pFile);
            m_pMemoryManager->write(nDsBase + nDX, baFull);                       // full path back to DS:DX
            m_pMemoryManager->writeByte(nDsBase + nDX + baFull.size(), 0x00);     // ASCIIZ terminator
            setAX(pRegisters, (quint16)nHandle);
            setCF(pRegisters, false);
            _log(QStringLiteral("INT 21h.5A create-temp '%1' -> handle %2").arg(QString::fromLatin1(baFull)).arg(nHandle));
            return true;
        }

        case 0x6C: {  // extended open/create (DOS 4+): BX=mode, CX=attr, DX=action, DS:SI=name
                      // DX: bits 0-3 = if the file exists (0 fail, 1 open, 2 replace/truncate),
                      //     bits 4-7 = if it does not  (0 fail, 1 create).
                      // Returns AX = handle and CX = what happened (1 opened, 2 created, 3 replaced).
            quint16 nSI = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 2);
            QByteArray baName = _readAsciiz(nDsBase, nSI);
            if (int nDev = deviceKind(baName)) {
                int nHandle = _lowestFreeHandle();
                (nDev == 2 ? m_conHandles : m_nulHandles).insert(nHandle);
                setAX(pRegisters, (quint16)nHandle);
                pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 1);  // "opened"
                setCF(pRegisters, false);
                return true;
            }
            QString sPath = _resolvePath(baName);
            const bool bExists = QFileInfo::exists(sPath);
            const int nIfExists = nDX & 0x0F;
            const int nIfNew = (nDX >> 4) & 0x0F;
            if ((bExists && (nIfExists == 0)) || (!bExists && (nIfNew == 0))) {
                fail(bExists ? DOSERR_ACCESS_DENIED : DOSERR_FILE_NOT_FOUND);
                return true;
            }
            const bool bTruncate = bExists && (nIfExists == 2);
            QIODevice::OpenMode openMode = ((nBX & 0x07) == 0) ? QIODevice::ReadOnly : QIODevice::ReadWrite;
            if (bTruncate) {
                openMode = QIODevice::ReadWrite | QIODevice::Truncate;
            }
            QFile *pFile = new QFile(sPath);
            if (!pFile->open(openMode)) {
                delete pFile;
                _log(QStringLiteral("INT 21h.6C open/create '%1' failed").arg(sPath));
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            int nHandle = _allocHandle(pFile);
            setAX(pRegisters, (quint16)nHandle);
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, (quint16)(bTruncate ? 3 : (bExists ? 1 : 2)));
            setCF(pRegisters, false);
            _log(QStringLiteral("INT 21h.6C open/create '%1' -> handle %2").arg(sPath).arg(nHandle));
            return true;
        }

        case 0x5B: {  // create NEW file: like AH=3Ch but fails if the file already exists
            QByteArray baName = _readAsciiz(nDsBase, nDX);
            if (int nDev = deviceKind(baName)) {
                int nHandle = _lowestFreeHandle();
                (nDev == 2 ? m_conHandles : m_nulHandles).insert(nHandle);
                setAX(pRegisters, (quint16)nHandle);
                setCF(pRegisters, false);
                return true;
            }
            QString sPath = _resolvePath(baName);
            if (QFileInfo::exists(sPath)) {
                fail(0x50);  // DOS error 80: file already exists -- the whole point of AH=5Bh
                return true;
            }
            QFile *pFile = new QFile(sPath);
            if (!pFile->open(QIODevice::ReadWrite | QIODevice::Truncate)) {
                delete pFile;
                _log(QStringLiteral("INT 21h.5B create-new '%1' failed").arg(sPath));
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            int nHandle = _allocHandle(pFile);
            setAX(pRegisters, (quint16)nHandle);
            setCF(pRegisters, false);
            _log(QStringLiteral("INT 21h.5B create-new '%1' -> handle %2").arg(sPath).arg(nHandle));
            return true;
        }

        case 0x3D: {  // open existing file: DS:DX=name, AL=mode(0=r,1=w,2=rw) -> AX=handle
            quint8 nMode = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0x07);
            QByteArray baName = _readAsciiz(nDsBase, nDX);
            if (int nDev = deviceKind(baName)) {  // NUL/PRN/AUX/CON: hand out a device handle
                int nHandle = _lowestFreeHandle();
                (nDev == 2 ? m_conHandles : m_nulHandles).insert(nHandle);
                setAX(pRegisters, (quint16)nHandle);
                setCF(pRegisters, false);
                return true;
            }
            QString sPath = _resolvePath(baName);
            _syncPath(sPath);  // another handle may still be holding buffered writes to this file
            QFile *pFile = new QFile(sPath);
            // AH=3D opens an EXISTING file only -- it must never create one (that is AH=3Ch's job).
            // ExistingOnly stops QIODevice::ReadWrite from creating a missing file, which otherwise
            // breaks the "delete temp, reopen, expect failure, recreate fresh" idiom (PGMPAK/PKZIP).
            QIODevice::OpenMode openMode = (nMode == 0) ? QIODevice::ReadOnly : (QIODevice::ReadWrite | QIODevice::ExistingOnly);
            if (!pFile->open(openMode)) {
                delete pFile;
                _log(QStringLiteral("INT 21h.3D open '%1' (mode %2) failed").arg(sPath).arg(nMode));
                fail(QFileInfo::exists(sPath) ? DOSERR_ACCESS_DENIED : DOSERR_FILE_NOT_FOUND);
                return true;
            }
            int nHandle = _allocHandle(pFile);
            setAX(pRegisters, (quint16)nHandle);
            setCF(pRegisters, false);
            _log(QStringLiteral("INT 21h.3D open '%1' (mode %2) -> handle %3").arg(sPath).arg(nMode).arg(nHandle));
            return true;
        }

        case 0x3E: {  // close file: BX=handle
            if (nBX <= 4) {  // standard handles: nothing to do
                setCF(pRegisters, false);
                return true;
            }
            if (m_conHandles.remove((int)nBX) || m_nulHandles.remove((int)nBX)) {  // device handle: drop it
                setCF(pRegisters, false);
                return true;
            }
            QFile *pFile = m_mapFiles.value((int)nBX, nullptr);
            if (!pFile) {
                fail(DOSERR_INVALID_HANDLE);
                return true;
            }
            pFile->close();
            delete pFile;
            m_mapFiles.remove((int)nBX);
            setCF(pRegisters, false);
            return true;
        }

        case 0x45: {  // DUP: BX=handle -> AX=new handle referring to the same open file/device
            int nNew = _lowestFreeHandle();
            if ((nBX <= 2) || m_conHandles.contains((int)nBX)) {  // stdin/out/err (or a console DUP)
                m_conHandles.insert(nNew);
            } else {
                QFile *pFile = m_mapFiles.value((int)nBX, nullptr);
                if (!pFile) {
                    fail(DOSERR_INVALID_HANDLE);
                    return true;
                }
                // Re-open the same path at the same position so the duplicate is independently usable.
                QFile *pDup = new QFile(pFile->fileName());
                if (!pDup->open(pFile->openMode())) {
                    delete pDup;
                    fail(DOSERR_ACCESS_DENIED);
                    return true;
                }
                pDup->seek(pFile->pos());
                m_mapFiles.insert(nNew, pDup);
            }
            setAX(pRegisters, (quint16)nNew);
            setCF(pRegisters, false);
            return true;
        }

        case 0x46: {  // DUP2 / FORCEDUP: make handle CX refer to whatever BX refers to
            int nSrc = (int)nBX, nDst = (int)nCX;
            // Close whatever the destination currently held.
            if (QFile *pOld = m_mapFiles.value(nDst, nullptr)) {
                pOld->close();
                delete pOld;
                m_mapFiles.remove(nDst);
            }
            m_conHandles.remove(nDst);
            if ((nSrc <= 2) || m_conHandles.contains(nSrc)) {  // source is the console
                if (nDst > 2) {
                    m_conHandles.insert(nDst);
                }
            } else if (QFile *pSrc = m_mapFiles.value(nSrc, nullptr)) {
                QFile *pDup = new QFile(pSrc->fileName());
                if (pDup->open(pSrc->openMode())) {
                    pDup->seek(pSrc->pos());
                    m_mapFiles.insert(nDst, pDup);
                } else {
                    delete pDup;
                }
            }
            setCF(pRegisters, false);  // redirecting a standard handle always "succeeds" here
            return true;
        }

        case 0x3F: {  // read: BX=handle, CX=count, DS:DX=buffer -> AX=bytes read
            if (nBX == 0) {  // stdin: model an immediate Enter
                if (nCX >= 1) {
                    m_pMemoryManager->writeByte(nDsBase + nDX, 0x0D);
                }
                setAX(pRegisters, nCX ? 1 : 0);
                setCF(pRegisters, false);
                return true;
            }
            if (m_nulHandles.contains((int)nBX) || m_conHandles.contains((int)nBX)) {  // device: report EOF
                setAX(pRegisters, 0);
                setCF(pRegisters, false);
                return true;
            }
            QFile *pFile = m_mapFiles.value((int)nBX, nullptr);
            if (!pFile) {
                fail(DOSERR_INVALID_HANDLE);
                return true;
            }
            _syncPath(pFile->fileName(), (int)nBX);  // see writes another handle has buffered
            QByteArray baData = pFile->read((qint64)nCX);
            // A short read is normal at EOF, but a short read with the file NOT at EOF means the host
            // refused it -- report that instead of silently handing the guest fewer bytes, which
            // surfaces to the program as a generic "file read error" with nothing in our log.
            if ((baData.size() < (int)nCX) && !pFile->atEnd()) {
                _log(QStringLiteral("INT 21h.3F read handle %1: short read %2/%3 not at EOF: %4")
                         .arg(nBX)
                         .arg(baData.size())
                         .arg(nCX)
                         .arg(pFile->errorString()));
            }
            if (!baData.isEmpty()) {
                m_pMemoryManager->write(nDsBase + nDX, baData);
            }
            setAX(pRegisters, (quint16)baData.size());
            setCF(pRegisters, false);
            return true;
        }

        case 0x40: {  // write: BX=handle, CX=count, DS:DX=buffer -> AX=bytes written
            if (m_nulHandles.contains((int)nBX)) {  // NUL/PRN/AUX: discard, report all bytes written
                setAX(pRegisters, nCX);
                setCF(pRegisters, false);
                return true;
            }
            if ((nBX == 1) || (nBX == 2) || m_conHandles.contains((int)nBX)) {  // stdout / stderr / their DUPs -> console
                for (int i = 0; i < nCX; i++) {
                    bool bOk = false;
                    quint8 c = m_pMemoryManager->readByte(nDsBase + ((nDX + i) & 0xFFFF), &bOk);
                    if (!bOk) {
                        break;
                    }
                    _out((char)c);
                }
                setAX(pRegisters, nCX);
                setCF(pRegisters, false);
                return true;
            }
            QFile *pFile = m_mapFiles.value((int)nBX, nullptr);
            if (!pFile) {
                fail(DOSERR_INVALID_HANDLE);
                return true;
            }
            if (nCX == 0) {  // CX=0 truncates the file at the current position
                pFile->resize(pFile->pos());
                setAX(pRegisters, 0);
                setCF(pRegisters, false);
                return true;
            }
            QByteArray baData = m_pMemoryManager->read(nDsBase + nDX, nCX);
            // A short read from GUEST memory means the source buffer is not fully mapped; DOS would
            // have written all CX bytes, so silently writing fewer corrupts the output file.
            if (baData.size() < (int)nCX) {
                _log(QStringLiteral("INT 21h.40 write handle %1: guest buffer %2:%3 only %4/%5 bytes readable")
                         .arg(nBX)
                         .arg(nDsBase >> 4, 4, 16, QChar('0'))
                         .arg(nDX, 4, 16, QChar('0'))
                         .arg(baData.size())
                         .arg(nCX));
            }
            qint64 nWritten = pFile->write(baData);
            if (nWritten < 0) {
                _log(QStringLiteral("INT 21h.40 write handle %1 failed: %2").arg(nBX).arg(pFile->errorString()));
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            if (nWritten < (qint64)nCX) {
                _log(QStringLiteral("INT 21h.40 write handle %1: short write %2/%3: %4").arg(nBX).arg(nWritten).arg(nCX).arg(pFile->errorString()));
            }
            setAX(pRegisters, (quint16)nWritten);
            setCF(pRegisters, false);
            return true;
        }

        case 0x42: {  // lseek: BX=handle, AL=origin(0/1/2), CX:DX=offset -> DX:AX=new position
            quint8 nOrigin = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
            if (m_nulHandles.contains((int)nBX) || m_conHandles.contains((int)nBX)) {  // device: position 0
                setAX(pRegisters, 0);
                setDX(pRegisters, 0);
                setCF(pRegisters, false);
                return true;
            }
            QFile *pFile = m_mapFiles.value((int)nBX, nullptr);
            if (!pFile) {
                fail(DOSERR_INVALID_HANDLE);
                return true;
            }
            qint32 nDelta = (qint32)(((quint32)nCX << 16) | (quint32)nDX);
            if (nOrigin == 2) {
                // seek-from-END is the standard way to ask "how big is this file?"; the answer must
                // include bytes another handle has written but not yet flushed.
                _syncPath(pFile->fileName(), (int)nBX);
            }
            qint64 nAnchor = (nOrigin == 1) ? pFile->pos() : (nOrigin == 2) ? pFile->size() : 0;
            qint64 nPos = nAnchor + nDelta;
            if (nPos < 0) {
                nPos = 0;
            }
            pFile->seek(nPos);
            setDX(pRegisters, (quint16)((nPos >> 16) & 0xFFFF));
            setAX(pRegisters, (quint16)(nPos & 0xFFFF));
            setCF(pRegisters, false);
            return true;
        }

        case 0x41: {  // delete file: DS:DX=name
            QString sPath = _resolvePath(_readAsciiz(nDsBase, nDX));
            _releaseHostFile(sPath);  // DOS allows deleting a file that still has open handles
            if (!QFile::remove(sPath)) {
                fail(DOSERR_FILE_NOT_FOUND);
                return true;
            }
            setCF(pRegisters, false);
            return true;
        }

        case 0x43: {  // get/set file attributes: AL=0 get, AL=1 set -> succeed
            quint8 nSub = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
            if (nSub == 0) {
                QString sPath = _resolvePath(_readAsciiz(nDsBase, nDX));
                if (!QFileInfo::exists(sPath)) {
                    fail(DOSERR_FILE_NOT_FOUND);
                    return true;
                }
                setCX(pRegisters, 0x0020);  // archive
            }
            setCF(pRegisters, false);
            return true;
        }

        case 0x44: {  // IOCTL: AL=0 get device info -> DX
            quint8 nSub = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
            if (nSub == 0) {
                // Standard handles are character devices; real file handles are disk files.
                setDX(pRegisters, (nBX <= 4) ? 0x80D3 : 0x0000);
                setCF(pRegisters, false);
                return true;
            }
            setCF(pRegisters, false);
            return true;
        }

        case 0x56: {  // rename file: DS:DX = old ASCIIZ name, ES:DI = new ASCIIZ name
            QString sOld = _resolvePath(_readAsciiz(nDsBase, nDX));
            quint64 nEsBase = ((quint64)pRegisters->nES) << 4;
            quint16 nDI = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDI, 2);
            QString sNew = _resolvePath(_readAsciiz(nEsBase, nDI));
            _releaseHostFile(sOld);  // ... and renaming one, or renaming over an open destination
            _releaseHostFile(sNew);
            if (!QFileInfo::exists(sOld)) {
                _log(QStringLiteral("INT 21h.56 rename '%1' -> '%2' : source missing").arg(sOld).arg(sNew));
                fail(DOSERR_FILE_NOT_FOUND);
                return true;
            }
            QFile::remove(sNew);  // self-replacing packers rename temp -> original; allow overwrite
            if (!QFile::rename(sOld, sNew)) {
                _log(QStringLiteral("INT 21h.56 rename '%1' -> '%2' FAILED").arg(sOld).arg(sNew));
                fail(DOSERR_ACCESS_DENIED);
                return true;
            }
            _log(QStringLiteral("INT 21h.56 rename '%1' -> '%2'").arg(sOld).arg(sNew));
            setCF(pRegisters, false);
            return true;
        }

        case 0x57:  // get/set file date & time -> report success (timestamps not modelled)
            setCF(pRegisters, false);
            return true;

        default:
            return false;  // not a file function
    }
}

void XEmuMsdosInt::int21(XEmuRegisters *pRegisters, bool *pbTerminate)
{
    if (pbTerminate) {
        *pbTerminate = false;
    }

    quint8 nAH = ah(pRegisters);
    quint16 nDX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2);
    quint64 nDsBase = ((quint64)pRegisters->nDS) << 4;
    setCF(pRegisters, false);

    static const bool s_bInt21Trace = !qEnvironmentVariableIsEmpty("INT21_TRACE");
    if (s_bInt21Trace) {
        _log(QStringLiteral("int21 AH=%1 AL=%2 BX=%3 CX=%4 DX=%5 DS=%6 DS:DX->'%7'")
                 .arg(nAH, 2, 16, QChar('0'))
                 .arg(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1), 2, 16, QChar('0'))
                 .arg(pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2), 4, 16, QChar('0'))
                 .arg(pRegisters->getGPR(XEmuRegisters::GPR_RCX, 2), 4, 16, QChar('0'))
                 .arg(nDX, 4, 16, QChar('0'))
                 .arg(pRegisters->nDS, 4, 16, QChar('0'))
                 .arg(QString::fromLatin1(m_pMemoryManager->read(nDsBase + nDX, 16).left(14))));
    }

    // Handle-based file API first (AH=3Ch..44h, 57h).
    if (_fileFunction(nAH, pRegisters)) {
        return;
    }

    switch (nAH) {
        case 0x00:  // terminate
        case 0x4C: {  // terminate with return code (AL)
            _log(QStringLiteral("INT 21h AH=%1: exit (code %2)").arg(nAH, 2, 16, QChar('0')).arg(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1)));
            // A child process (its PSP names a different parent) returns control to the parent via the
            // terminate address (INT 22h) saved in the child PSP, rather than ending the whole program.
            // PGMPAK runs its bundled PKZIP as a manual child (AH=55) and resumes afterwards to wrap the ZIP.
            quint16 nCur = m_nPspSeg;
            quint16 nParent = nCur ? m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x16) : 0;
            quint16 nTermOff = nCur ? m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x0A) : 0;
            quint16 nTermSeg = nCur ? m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x0C) : 0;
            if (nParent && (nParent != nCur) && (nParent != 0xFFFF) && nTermSeg) {
                // Restore INT 22/23/24 handlers from the terminating PSP, switch back to the parent,
                // and transfer to the terminate address; the parent's handler restores its own SS:SP.
                m_pMemoryManager->writeWord(0x22 * 4, nTermOff);
                m_pMemoryManager->writeWord(0x22 * 4 + 2, nTermSeg);
                m_pMemoryManager->writeWord(0x23 * 4, m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x0E));
                m_pMemoryManager->writeWord(0x23 * 4 + 2, m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x10));
                m_pMemoryManager->writeWord(0x24 * 4, m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x12));
                m_pMemoryManager->writeWord(0x24 * 4 + 2, m_pMemoryManager->readWord(((XADDR)nCur << 4) + 0x14));
                m_nPspSeg = nParent;
                pRegisters->nCS = nTermSeg;
                pRegisters->nRIP = ((XADDR)nTermSeg << 4) + nTermOff;
                break;  // execution continues at the parent's terminate handler
            }
            if (pbTerminate) {
                *pbTerminate = true;
            }
            break;
        }

        case 0x02:  // display DL
            _out((char)(pRegisters->getGPR(XEmuRegisters::GPR_RDX, 1) & 0xFF));
            setAL(pRegisters, (quint8)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 1));
            break;

        case 0x06:  // direct console I/O
            if ((nDX & 0xFF) == 0xFF) {                             // input request
                setAL(pRegisters, 0);
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, true);  // no character ready
            } else {
                _out((char)(nDX & 0xFF));
            }
            break;

        case 0x09:  // print '$'-terminated string at DS:DX
            for (int i = 0; i < 0x10000; i++) {
                bool bOk = false;
                quint8 c = m_pMemoryManager->readByte(nDsBase + ((nDX + i) & 0xFFFF), &bOk);
                if (!bOk || (c == '$')) {
                    break;
                }
                _out((char)c);
            }
            // NOTE: real DOS documents AL as destroyed / left = 24h ('$') here, but the DOSBox 0.74
            // reference leaves AL UNCHANGED, and programs carry it forward: DaRKSToP does
            // `int 21h AH=09 / mov ah,30 / int 21h / ... / jmp near ax`, so a stray 24h in AL changes
            // its computed jump target. Match the reference environment the corpus is calibrated to.
            break;

        case 0x01:  // read char with echo
        case 0x07:  // read char, no echo
        case 0x08:  // read char, no echo, no break-check
            setAL(pRegisters, 0x0D);  // model an immediate Enter so blocking reads make progress
            break;

        case 0x0A: {  // buffered keyboard input: DS:DX -> [maxlen][count][chars..CR]
            // Headless: return an empty line (just Enter) so callers proceed with a default
            // instead of blocking or aborting on an unmodelled function.
            XADDR nBuf = nDsBase + nDX;
            m_pMemoryManager->writeByte(nBuf + 1, 0x00);  // 0 characters entered
            m_pMemoryManager->writeByte(nBuf + 2, 0x0D);  // terminating CR
            break;
        }

        case 0x0D:  // disk reset: flush buffers. Nothing is buffered here, so just succeed.
            setCF(pRegisters, false);
            break;

        case 0x0B:  // check input status
        case 0x0C:  // flush buffer + invoke input function AL
            setAL(pRegisters, 0x00);  // no character available
            break;

        case 0x29: {  // parse filename at DS:SI into an FCB at ES:DI
            XADDR nSrc = nDsBase + (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 2);
            XADDR nFcb = ((XADDR)pRegisters->nES << 4) + (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDI, 2);
            int i = 0;
            auto rd = [&](int k) { bool ok = false; return (char)m_pMemoryManager->readByte(nSrc + k, &ok); };
            auto up = [](char c) -> char { return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c; };
            while (rd(i) == ' ' || rd(i) == '\t') i++;                       // skip leading blanks
            quint8 nDrive = 0;                                              // 0 = default drive
            char c0 = rd(i);
            if (c0 && rd(i + 1) == ':') { nDrive = (quint8)((up(c0) - 'A') + 1); i += 2; }
            m_pMemoryManager->writeByte(nFcb + 0, nDrive);
            bool bWild = false;
            auto fill = [&](int off, int width) {
                for (int k = 0; k < width; k++) {
                    char c = rd(i);
                    if (c == 0 || c == ' ' || c == '.' || c == '\r' || c == '\t') { m_pMemoryManager->writeByte(nFcb + off + k, ' '); continue; }
                    if (c == '*') { for (int j = k; j < width; j++) m_pMemoryManager->writeByte(nFcb + off + j, '?'); bWild = true; i++; return; }
                    if (c == '?') bWild = true;
                    m_pMemoryManager->writeByte(nFcb + off + k, (quint8)up(c));
                    i++;
                }
                while (rd(i) && rd(i) != ' ' && rd(i) != '.' && rd(i) != '\r' && rd(i) != '\t') i++;  // skip overflow
            };
            fill(1, 8);                                                     // 8-char name
            if (rd(i) == '.') { i++; fill(9, 3); }                          // optional .ext
            else { for (int k = 0; k < 3; k++) m_pMemoryManager->writeByte(nFcb + 9 + k, ' '); }
            pRegisters->setGPR(XEmuRegisters::GPR_RSI, 2, (quint16)((quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 2) + i));
            setAL(pRegisters, bWild ? 0x01 : 0x00);
            break;
        }

        case 0x47: {  // get current directory: DL = drive (0 = default), DS:SI <- ASCIIZ path
            // All INT 21h file I/O is rooted at the working directory, so the current directory is
            // always the root. DOS returns the path WITHOUT the drive letter and WITHOUT the leading
            // backslash, i.e. an empty string at the root. Tools call this to build temp-file paths.
            XADDR nBuf = nDsBase + (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 2);
            m_pMemoryManager->writeByte(nBuf, 0x00);
            setAX(pRegisters, 0x0100);  // DOS leaves AX = 0100h on success
            setCF(pRegisters, false);
            break;
        }

        case 0x19:  // get current default drive
            setAL(pRegisters, 0x02);  // C:
            break;

        case 0x1A:  // set Disk Transfer Address (DS:DX) -- where find-first/next write their record
            m_nDtaAddr = nDsBase + nDX;
            m_nDtaSeg = pRegisters->nDS;
            m_nDtaOff = nDX;
            break;

        case 0x52: {  // get "list of lists" (undocumented but universally used) -> ES:BX
            // The only field programs reliably use is the WORD at [ES:BX-2]: the segment of the first
            // MCB, i.e. the head of the memory-block chain. Everything else in the structure is
            // version-specific, so publish a minimal record at a fixed low address and make that one
            // field correct. Without this, anything that enumerates memory blocks or TSRs got CF and
            // an untouched ES:BX -- whatever the caller happened to leave there.
            const XADDR nLolSeg = 0x0080, nLolOff = 0x0026;  // same placement DOSBox 0.74 uses
            const XADDR nLolLinear = (nLolSeg << 4) + nLolOff;
            m_pMemoryManager->writeWord(nLolLinear - 2, m_nFirstMcb);
            pRegisters->nES = (quint16)nLolSeg;
            setBX(pRegisters, (quint16)nLolOff);
            break;
        }

        case 0x2F: {  // get Disk Transfer Address -> ES:BX
            // Programs that save the current DTA, point it somewhere of their own, and restore it
            // afterwards need this; without it they restored garbage. The DTA defaults to PSP:0080h,
            // so report that when nothing has set one yet rather than 0.
            // DOS keeps the DTA as a far pointer and hands back exactly what was set, so return the
            // stored seg:off rather than re-deriving one from the linear address (which would
            // normalise PSP:0080 into something like 0198:0000 -- a different pointer to the same
            // byte, but not what a program comparing against its own saved value expects).
            if (m_nDtaAddr == 0) {
                pRegisters->nES = m_nPspSeg;
                setBX(pRegisters, 0x0080);
            } else {
                pRegisters->nES = m_nDtaSeg;
                setBX(pRegisters, m_nDtaOff);
            }
            break;
        }

        case 0x4E: {  // find first file: DS:DX = ASCIIZ mask, CX = attribute -> DTA record
            if (m_nDtaAddr == 0) {
                m_nDtaAddr = nDsBase + 0x80;  // default DTA at PSP:0080h
            }
            QString sHost = _resolvePath(_readAsciiz(nDsBase, nDX));
            QFileInfo fiMask(sHost);
            QDir dir(fiMask.absolutePath());
            m_sFindDir = dir.absolutePath();
            m_findResults = dir.entryList(QStringList() << fiMask.fileName(), QDir::Files, QDir::Name);
            m_nFindIndex = 0;
            if (m_findResults.isEmpty()) {
                setAX(pRegisters, 0x0012);  // no more files
                setCF(pRegisters, true);
            } else {
                _fillFindRecord(m_findResults.at(0));
                setCF(pRegisters, false);
            }
            break;
        }

        case 0x4F:  // find next file (continues the AH=4Eh search)
            m_nFindIndex++;
            if (m_nFindIndex >= m_findResults.size()) {
                setAX(pRegisters, 0x0012);  // no more files
                setCF(pRegisters, true);
            } else {
                _fillFindRecord(m_findResults.at(m_nFindIndex));
                setCF(pRegisters, false);
            }
            break;

        case 0x25: {  // set interrupt vector (AL = vector; DS:DX = handler)
            int nVec = (int)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
            m_mapIvt.insert(nVec, ((quint32)pRegisters->nDS << 16) | nDX);
            // Also write the resident IVT at 0000:vec*4 so the CPU's exception/INT dispatch
            // (e.g. divide-error INT 0 used by anti-debug crypters) finds the handler.
            m_pMemoryManager->writeWord((XADDR)nVec * 4, nDX);
            m_pMemoryManager->writeWord((XADDR)nVec * 4 + 2, pRegisters->nDS);
            break;
        }

        case 0x30:  // get DOS version
            // Report MS-DOS 5.00, which is what the DOSBox 0.74 reference reports -- the packer corpus is
            // calibrated against that environment and programs branch on it (DaRKSToP computes a jump
            // target as version+0Ch, so 6.22 vs 5.00 sends it to a different address entirely).
            // XEMU_DOS_VER="maj.min" overrides (e.g. "6.22").
            {
                quint8 nMaj = 5, nMin = 0;
                if (!qEnvironmentVariableIsEmpty("XEMU_DOS_VER")) {
                    const QStringList l = qEnvironmentVariable("XEMU_DOS_VER").split(QLatin1Char('.'));
                    if (l.size() == 2) { nMaj = (quint8)l.at(0).toUShort(); nMin = (quint8)l.at(1).toUShort(); }
                }
                setAL(pRegisters, nMaj);
                setAH(pRegisters, nMin);
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, 0xFF00);  // BH = OEM (MS-DOS)
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 0x0000);
            break;

        case 0x37:  // AL=0 get / AL=1 set SWITCHAR (command-line option prefix). DOS + DOSBox default
                    // is '/', which tools like DIET query to decide whether "-X" is an option or a
                    // filename. Returning the real default keeps option parsing matching the reference.
            if ((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF) == 0x00) {
                setAL(pRegisters, 0x00);                                    // function supported
                pRegisters->setGPR(XEmuRegisters::GPR_RDX, 1, (quint8)'/');  // DL = switch character
            } else {
                setAL(pRegisters, 0x00);  // set/other subfunctions: accept as no-op
            }
            break;

        case 0x2A: {  // get system date -> the host date (DOSBox does the same; anti-tamper
                      // packers like $PIRIT seed their crypto from it)
            // XEMU_FIXED_DATE="CCCC,DDDD" (hex CX,DX) pins the reported date. Programs that seed a PRNG
            // from the clock (TINYPROG uses the 015A4E35 LCG) are otherwise irreproducible run to run,
            // which makes a trace-diff against a reference emulator impossible past the seeding point.
            if (!qEnvironmentVariableIsEmpty("XEMU_FIXED_DATE")) {
                const QStringList l = qEnvironmentVariable("XEMU_FIXED_DATE").split(QLatin1Char(','));
                if (l.size() == 2) {
                    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, l.at(0).toUShort(nullptr, 16));
                    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, l.at(1).toUShort(nullptr, 16));
                    setAL(pRegisters, 0);
                    break;
                }
            }
            QDate d = QDate::currentDate();
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, (quint16)d.year());
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, (quint16)(((d.month() & 0xFF) << 8) | (d.day() & 0xFF)));
            setAL(pRegisters, (quint8)(d.dayOfWeek() % 7));  // Qt 1..7 (Mon..Sun) -> DOS 0..6 (Sun..Sat)
            break;
        }

        case 0x2C: {  // get system time -> the host time (CH=hour CL=min DH=sec DL=1/100s)
            if (!qEnvironmentVariableIsEmpty("XEMU_FIXED_TIME")) {  // see XEMU_FIXED_DATE above
                const QStringList l = qEnvironmentVariable("XEMU_FIXED_TIME").split(QLatin1Char(','));
                if (l.size() == 2) {
                    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, l.at(0).toUShort(nullptr, 16));
                    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, l.at(1).toUShort(nullptr, 16));
                    break;
                }
            }
            QTime t = QTime::currentTime();
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, (quint16)(((t.hour() & 0xFF) << 8) | (t.minute() & 0xFF)));
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, (quint16)(((t.second() & 0xFF) << 8) | ((t.msec() / 10) & 0xFF)));
            break;
        }

        case 0x4A: {  // resize memory block (SETBLOCK): ES = segment, BX = new paragraphs
            if (m_nFirstMcb) {
                quint16 nMax = 0;
                if (_memResize(pRegisters->nES, (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2), &nMax)) {
                    setCF(pRegisters, false);
                } else {
                    pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, nMax);
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0008);
                    setCF(pRegisters, true);
                }
                break;
            }
            setCF(pRegisters, false);  // no MCB chain: all RAM is backed, so succeed
            break;
        }

        case 0x48: {  // allocate memory block: BX paragraphs -> AX = segment (else CF, AX=8, BX=largest)
            quint16 nParas = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2);
            if (m_nFirstMcb) {  // proper MCB chain (matches DOS: freed conventional memory is reusable)
                quint16 nSeg = 0, nMax = 0;
                if (_memAlloc(nParas, &nSeg, &nMax)) {
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nSeg);
                    setCF(pRegisters, false);
                } else {
                    pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, nMax);
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0008);
                    setCF(pRegisters, true);
                }
                break;
            }
            if (nParas == 0) {
                nParas = 1;
            }
            const quint16 nAllocTop = 0xFF00;  // fallback bump allocator (no MCB chain set up)
            if ((quint32)m_nAllocSeg + nParas > nAllocTop) {
                pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, (quint16)(nAllocTop - m_nAllocSeg));
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0008);
                setCF(pRegisters, true);
                break;
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, m_nAllocSeg);
            m_nAllocSeg = (quint16)(m_nAllocSeg + nParas);
            setCF(pRegisters, false);
            break;
        }

        case 0x49:  // free memory block: ES = segment
            if (m_nFirstMcb) {
                _memFree(pRegisters->nES);
            }
            setCF(pRegisters, false);
            break;

        case 0x33:  // Ctrl-Break check: AL=0 get -> DL=state(off); AL=1 set; others benign
            if ((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF) == 0x00) {
                pRegisters->setGPR(XEmuRegisters::GPR_RDX, 1, 0x00);  // break checking off
            }
            setCF(pRegisters, false);
            break;

        case 0x50:  // set current PSP (DOS tracks which PSP owns the command tail / FCBs)
            m_nPspSeg = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2);
            setCF(pRegisters, false);
            break;

        case 0x51:  // get current PSP -> BX
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, m_nPspSeg ? m_nPspSeg : pRegisters->nDS);
            break;

        case 0x38:  // get/set country info: report success with the caller's buffer untouched (US default)
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, 0x0001);  // country code 1 (USA)
            setCF(pRegisters, false);
            break;

        case 0x55: {  // create child PSP at DX:0000 -- DOS copies the parent PSP (command tail + default
                      // FCBs) into it. Programs (PGMPAK) then read their arguments from the new PSP, so
                      // the copy is essential; without it the child PSP's command tail is empty.
            quint16 nNewPsp = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2);
            quint16 nSrc = m_nPspSeg ? m_nPspSeg : pRegisters->nDS;
            if (nNewPsp && (nNewPsp != nSrc)) {
                QByteArray baPsp = m_pMemoryManager->read((XADDR)nSrc << 4, 256);
                m_pMemoryManager->write((XADDR)nNewPsp << 4, baPsp);
                // PSP+0x16 = parent PSP; PSP+0x02 = segment past the block (from SI if given).
                m_pMemoryManager->writeWord(((XADDR)nNewPsp << 4) + 0x16, nSrc);
                quint16 nSi = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSI, 2);
                if (nSi) {
                    m_pMemoryManager->writeWord(((XADDR)nNewPsp << 4) + 0x02, nSi);
                }
                _mcbClaim(nNewPsp, nNewPsp);  // reserve the child's block so free regions stay separate
            }
            m_nPspSeg = nNewPsp;  // the new PSP becomes current (subsequent AH=62/51 report it)
            setCF(pRegisters, false);
            break;
        }

        case 0x4D:  // get return code of a sub-process
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0000);  // exit code 0, normal termination
            break;

        case 0x62:  // get current PSP segment (tracked across AH=50/55; falls back to DS for a .COM)
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, m_nPspSeg ? m_nPspSeg : pRegisters->nDS);
            break;

        case 0x35: {  // get interrupt vector (AL = vector) -> ES:BX (from the resident IVT)
            int nVec = (int)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
            quint16 nOff = m_pMemoryManager->readWord((XADDR)nVec * 4);
            quint16 nSeg = m_pMemoryManager->readWord((XADDR)nVec * 4 + 2);
            pRegisters->nES = nSeg;
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, nOff);
            break;
        }

        default:
            _log(QStringLiteral("INT 21h AH=0x%1 not modelled (AX=0x%2) -> CF")
                     .arg(nAH, 2, 16, QChar('0'))
                     .arg(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2), 4, 16, QChar('0')));
            setCF(pRegisters, true);  // report "unsupported" rather than terminate
            break;
    }
}
