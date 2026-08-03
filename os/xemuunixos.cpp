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
#include "xemuunixos.h"

#include <functional>

#include "linux_syscalls/xemulinuxsyscalls.h"

// Little-endian read of up to 8 bytes from a raw byte buffer.
static quint64 unixReadLE(const uchar *e, int nOff, int nSize)
{
    quint64 v = 0;
    for (int i = 0; i < nSize; i++) {
        v |= (quint64)e[nOff + i] << (i * 8);
    }
    return v;
}

XEmuUnixOS::XEmuUnixOS(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent)
    : XEmuOperatingSystem(pMemoryManager, pArch, pParent), m_bIs64(true), m_archType(XARCH_UNKNOWN), m_pSyscalls(nullptr)
{
}

void XEmuUnixOS::_forwardSyscallLog(const QString &sText)
{
    emit infoMessage(sText);
}

XEmuUnixOS::~XEmuUnixOS()
{
    delete m_pSyscalls;
}

XEmuSyscalls *XEmuUnixOS::createSyscalls()
{
    return new XEmuLinuxSyscalls(m_pMemoryManager, m_pArch, m_bIs64);
}

bool XEmuUnixOS::handleSyscall(XEmuRegisters *pRegisters)
{
    if (m_pSyscalls == nullptr) {
        return false;
    }

    return m_pSyscalls->dispatch(pRegisters);
}

bool XEmuUnixOS::getReplacementImage(QByteArray *pbaImage)
{
    if ((m_pSyscalls == nullptr) || !m_pSyscalls->hasExeced()) {
        return false;
    }

    if (pbaImage) {
        *pbaImage = m_pSyscalls->execImage();
    }
    return true;
}

int XEmuUnixOS::_ptrSize() const
{
    return m_bIs64 ? 8 : 4;
}

void XEmuUnixOS::_pushPtr(XADDR nAddress, quint64 nValue)
{
    if (m_bIs64) {
        m_pMemoryManager->writeQword(nAddress, nValue);
    } else {
        m_pMemoryManager->writeDword(nAddress, (quint32)nValue);
    }
}

XADDR XEmuUnixOS::_chooseBase(XEmuFileFormat *pFormat)
{
    XADDR nPreferred = pFormat->getPreferredImageBase();
    quint64 nImageSize = pFormat->getImageSize();

    if ((nPreferred != 0) && m_pMemoryManager->isRangeFree(nPreferred, nImageSize)) {
        return nPreferred;
    }
    // Position-independent images (preferred base 0) get a conventional load base.
    XADDR nStart = (nPreferred != 0) ? m_pMemoryManager->getMinAddress() : (m_bIs64 ? Q_UINT64_C(0x555555554000) : 0x08048000);
    return m_pMemoryManager->findFree(nImageSize, nStart, XEmuMemoryManager::N_ALLOCATION_GRANULARITY);
}

void XEmuUnixOS::_setupX86Segments(XEmuRegisters *pRegisters)
{
    if (m_archType == XARCH_X86_64) {
        pRegisters->nCS = 0x33;
        pRegisters->nSS = 0x2B;
        pRegisters->nDS = 0x2B;
        pRegisters->nES = 0x2B;
    } else if (m_archType == XARCH_X86_32) {
        pRegisters->nCS = 0x23;
        pRegisters->nSS = 0x2B;
        pRegisters->nDS = 0x2B;
        pRegisters->nES = 0x2B;
    }
}

XADDR XEmuUnixOS::buildInitialStack(XEmuFileFormat *pMainFormat, const XEmuFileFormat::MODULE &mainModule, XADDR nStackTop, XEmuRegisters *pRegisters)
{
    Q_UNUSED(pRegisters)

    int nPtr = _ptrSize();

    // Program-name string plus 16 "random" bytes (AT_RANDOM) near the stack top.
    QByteArray baName = mainModule.sName.toUtf8();
    baName.append('\0');
    XADDR nNameAddress = XEmuMemoryManager::alignDown(nStackTop - 0x200, 16);
    m_pMemoryManager->write(nNameAddress, baName);

    XADDR nRandomAddress = XEmuMemoryManager::alignDown(nNameAddress - 16, 16);
    m_pMemoryManager->write(nRandomAddress, QByteArray(16, 0x5A));

    // Recover the program-header table location from the ELF file header; a packer
    // stub (and the C runtime) reads AT_PHDR/AT_PHNUM to find its own segments.
    quint64 nPhdrAddr = 0;
    quint64 nPhEnt = m_bIs64 ? 56 : 32;
    quint64 nPhNum = 0;
    if (m_baImageFile.size() >= 64) {
        const uchar *e = reinterpret_cast<const uchar *>(m_baImageFile.constData());
        if (m_bIs64) {
            nPhdrAddr = mainModule.nBaseAddress + unixReadLE(e, 0x20, 8);  // base + e_phoff
            nPhEnt = unixReadLE(e, 0x36, 2);
            nPhNum = unixReadLE(e, 0x38, 2);
        } else {
            nPhdrAddr = mainModule.nBaseAddress + unixReadLE(e, 0x1C, 4);
            nPhEnt = unixReadLE(e, 0x2A, 2);
            nPhNum = unixReadLE(e, 0x2C, 2);
        }
    }

    // ELF auxiliary vector (type/value pairs). AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5,
    // AT_PAGESZ=6, AT_BASE=7, AT_FLAGS=8, AT_ENTRY=9, AT_UID/EUID/GID/EGID=11..14,
    // AT_HWCAP=16, AT_CLKTCK=17, AT_SECURE=23, AT_RANDOM=25, AT_EXECFN=31, AT_NULL=0.
    struct {
        quint64 nType;
        quint64 nValue;
    } auxv[] = {{3, nPhdrAddr},
                {4, nPhEnt},
                {5, nPhNum},
                {6, XEmuMemoryManager::N_PAGE_SIZE},
                {7, 0},
                {8, 0},
                {9, mainModule.nEntryPointAddress},
                {11, 0},
                {12, 0},
                {13, 0},
                {14, 0},
                {16, 0},
                {17, 100},
                {23, 0},
                {25, nRandomAddress},
                {31, nNameAddress},
                {0, 0}};

    int nSlots = 1 /*argc*/ + 1 /*argv0*/ + 1 /*argv null*/ + 1 /*envp null*/ + (int)(sizeof(auxv) / sizeof(auxv[0])) * 2;
    XADDR nSp = XEmuMemoryManager::alignDown(nRandomAddress - (XADDR)nSlots * nPtr, 16);

    // The System V ABI requires (argc pointer) % 16 == 0 after argc is pushed; keep
    // 16-byte alignment of the argc slot.
    if (((nSp) & 0xF) != 0) {
        nSp = XEmuMemoryManager::alignDown(nSp, 16);
    }

    XADDR nCursor = nSp;
    _pushPtr(nCursor, 1);
    nCursor += nPtr;  // argc
    _pushPtr(nCursor, nNameAddress);
    nCursor += nPtr;  // argv[0]
    _pushPtr(nCursor, 0);
    nCursor += nPtr;  // argv NULL
    _pushPtr(nCursor, 0);
    nCursor += nPtr;  // envp NULL
    for (size_t i = 0; i < sizeof(auxv) / sizeof(auxv[0]); i++) {
        _pushPtr(nCursor, auxv[i].nType);
        nCursor += nPtr;
        _pushPtr(nCursor, auxv[i].nValue);
        nCursor += nPtr;
    }

    return nSp;
}

bool XEmuUnixOS::setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options)
{
    m_listModules.clear();

    if (!pMainFormat || !pMainFormat->isValid()) {
        emit errorMessage(tr("Invalid main module"));
        return false;
    }

    m_archType = pMainFormat->getArchType();
    m_bIs64 = (xemuArchBits(m_archType) == 64);

    m_pMemoryManager->clear();
    m_pMemoryManager->setBits(m_bIs64 ? 64 : 32);
    m_pArch->setBits(m_bIs64 ? 64 : 32);

    // Emulated syscall layer: services the memory-shaping calls a packer stub makes
    // (mmap/mprotect/munmap/brk/arch_prctl) so it can run without a real kernel.
    delete m_pSyscalls;
    m_pSyscalls = createSyscalls();
    m_pSyscalls->setLogger(std::bind(&XEmuUnixOS::_forwardSyscallLog, this, std::placeholders::_1));
    m_pSyscalls->reset();
    m_pSyscalls->setSelfExe(m_baImageFile, QString());

    XADDR nBase = _chooseBase(pMainFormat);
    if (nBase == 0) {
        emit errorMessage(tr("No free address space to map the image"));
        return false;
    }

    XEmuFileFormat::MODULE mainModule;
    if (!pMainFormat->map(m_pMemoryManager, nBase, &mainModule)) {
        emit errorMessage(tr("Cannot map the main image"));
        return false;
    }
    m_listModules.append(mainModule);

    XADDR nStack = m_pMemoryManager->allocate(0, options.nStackSize, XEmuMemoryManager::MEMORY_FLAGS(true, true, false), QStringLiteral("stack"));
    if (nStack == 0) {
        emit errorMessage(tr("Cannot allocate the thread stack"));
        return false;
    }
    XADDR nStackTop = nStack + options.nStackSize;

    pRegisters->reset();
    XADDR nSp = buildInitialStack(pMainFormat, mainModule, nStackTop, pRegisters);

    m_pArch->setStackPointer(pRegisters, nSp);
    m_pArch->setPC(pRegisters, mainModule.nEntryPointAddress ? mainModule.nEntryPointAddress : nBase);
    _setupX86Segments(pRegisters);

    emit infoMessage(tr("%1 process ready: entry point %2, sp %3").arg(getOSName()).arg(pRegisters->nRIP, 0, 16).arg(nSp, 0, 16));
    return true;
}
