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
#include "xemuemulator.h"

#include <QFile>
#include <QFileInfo>

#include "arch/xemuarm.h"
#include "arch/xemuarm64.h"
#include "arch/xemux86.h"
#include "format/xemucom.h"
#include "format/xemuelf.h"
#include "format/xemumacho.h"
#include "format/xemumsdos.h"
#include "format/xemupe.h"
#include "os/xemudos.h"
#include "os/xemufreebsd.h"
#include "os/xemulinux.h"
#include "os/xemumacos.h"
#include "os/xemuwindows.h"
// Underlying Formats parsers, used only for format detection.
#include "xelf.h"
#include "xmach.h"
#include "xmsdos.h"
#include "xpe.h"

XEmuEmulator::XEmuEmulator(QObject *pParent) : QObject(pParent), m_memoryManager(this), m_pArch(nullptr), m_pOS(nullptr), m_pFormat(nullptr), m_bReady(false)
{
    connect(&m_memoryManager, &XEmuMemoryManager::errorMessage, this, &XEmuEmulator::errorMessage);
}

XEmuEmulator::~XEmuEmulator()
{
    _cleanup();
}

void XEmuEmulator::_cleanup()
{
    if (m_pOS) {
        delete m_pOS;
        m_pOS = nullptr;
    }

    if (m_pArch) {
        delete m_pArch;
        m_pArch = nullptr;
    }

    if (m_pFormat) {
        delete m_pFormat;
        m_pFormat = nullptr;
    }

    m_memoryManager.clear();
    m_registers.reset();
    m_bReady = false;
}

bool XEmuEmulator::loadFile(const QString &sFileName, const OPTIONS &options)
{
    _cleanup();

    // --- 1. Detect the object-file format (PE must be checked before MZ) ---------
    QFile file(sFileName);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorMessage(tr("Cannot open file: %1").arg(sFileName));
        return false;
    }

    XEmuFileFormat *pFormat = nullptr;
    if (XPE::isValid(&file)) {
        pFormat = new XEmuPE(this);
    } else if (XELF::isValid(&file)) {
        pFormat = new XEmuELF(this);
    } else if (XMACH::isValid(&file)) {
        pFormat = new XEmuMachO(this);
    } else if (XMSDOS::isValid(&file)) {
        pFormat = new XEmuMSDOS(this);
    }
    file.close();

    // A COM image has no signature at all, and DOS decides EXE-vs-COM purely on the MZ magic --
    // never on the file name. A .EXE without MZ is loaded as a COM image, which is not a corner
    // case: MASK 2.4 is an EXE->COM protector that writes its COM output back over the input's
    // .exe name, and DOSBox 0.74 runs the result correctly. So anything signature-less that is
    // small enough to BE a COM image (64 KiB minus the PSP) is loaded as one; a larger unrecognised
    // file still errors instead of being executed as garbage.
    if (!pFormat && (QFileInfo(sFileName).size() <= 0xFF00)) {
        pFormat = new XEmuCOM(this);
    }

    if (!pFormat) {
        emit errorMessage(tr("Unsupported file format (PE, ELF, Mach-O, MZ and COM are recognised)"));
        return false;
    }

    connect(pFormat, &XEmuFileFormat::infoMessage, this, &XEmuEmulator::infoMessage);
    connect(pFormat, &XEmuFileFormat::errorMessage, this, &XEmuEmulator::errorMessage);
    if (!pFormat->setFileName(sFileName)) {
        delete pFormat;
        return false;
    }
    m_pFormat = pFormat;

    XEmuArchType archType = m_pFormat->getArchType();
    XBinary::OSNAME osName = m_pFormat->getOSName();

    // --- 2. Pick the architecture personality -----------------------------------
    switch (archType) {
        case XARCH_X86_16: m_pArch = new XEmuX86(&m_memoryManager, 16); break;
        case XARCH_X86_32: m_pArch = new XEmuX86(&m_memoryManager, 32); break;
        case XARCH_X86_64: m_pArch = new XEmuX86(&m_memoryManager, 64); break;
        case XARCH_ARM: m_pArch = new XEmuArm(&m_memoryManager); break;
        case XARCH_ARM64: m_pArch = new XEmuArm64(&m_memoryManager); break;
        default:
            emit errorMessage(tr("Unsupported architecture for %1").arg(sFileName));
            _cleanup();
            return false;
    }

    // --- 3. Pick the operating-system personality -------------------------------
    XEmuOperatingSystem *pOS = nullptr;
    if (osName == XBinary::OSNAME_WINDOWS) {
        pOS = new XEmuWindows(&m_memoryManager, m_pArch, this);
    } else if (osName == XBinary::OSNAME_LINUX) {
        pOS = new XEmuLinux(&m_memoryManager, m_pArch, this);
    } else if (osName == XBinary::OSNAME_FREEBSD) {
        pOS = new XEmuFreeBSD(&m_memoryManager, m_pArch, this);
    } else if ((osName == XBinary::OSNAME_MACOS) || (osName == XBinary::OSNAME_OS_X) || (osName == XBinary::OSNAME_MAC_OS) || (osName == XBinary::OSNAME_MAC_OS_X)) {
        pOS = new XEmuMacOS(&m_memoryManager, m_pArch, this);
    } else if (osName == XBinary::OSNAME_MSDOS) {
        pOS = new XEmuDOS(&m_memoryManager, m_pArch, this);
    } else {
        // OS not recorded in the file header: infer it from the format.
        if (dynamic_cast<XEmuPE *>(m_pFormat)) {
            pOS = new XEmuWindows(&m_memoryManager, m_pArch, this);
        } else if (dynamic_cast<XEmuMachO *>(m_pFormat)) {
            pOS = new XEmuMacOS(&m_memoryManager, m_pArch, this);
        } else if (dynamic_cast<XEmuMSDOS *>(m_pFormat)) {
            pOS = new XEmuDOS(&m_memoryManager, m_pArch, this);
        } else {
            pOS = new XEmuLinux(&m_memoryManager, m_pArch, this);  // ELF / default
        }
    }

    connect(pOS, &XEmuOperatingSystem::infoMessage, this, &XEmuEmulator::infoMessage);
    connect(pOS, &XEmuOperatingSystem::errorMessage, this, &XEmuEmulator::errorMessage);
    m_pOS = pOS;

    // Hand the OS the raw file bytes so a packer stub that re-opens itself can read
    // its compressed payload.
    {
        QFile selfFile(sFileName);
        if (selfFile.open(QIODevice::ReadOnly)) {
            m_pOS->setImageFileBytes(selfFile.readAll());
            selfFile.close();
        }
    }

    emit infoMessage(tr("Selected %1 / %2 for %3").arg(m_pOS->getOSName(), QString::fromLatin1(xemuArchTypeName(archType)), QFileInfo(sFileName).fileName()));

    // --- 4. Build the process ----------------------------------------------------
    XEmuOperatingSystem::OPTIONS osOptions;
    osOptions.sSystemRoot = options.sSystemRoot;
    osOptions.nStackSize = options.nStackSize;
    osOptions.bLoadDependencies = options.bLoadDependencies;
    osOptions.sCommandLine = options.sCommandLine;
    osOptions.sWorkingDirectory = options.sWorkingDirectory;
    osOptions.nImageBaseOverride = options.nImageBaseOverride;
    osOptions.sProgramName = QFileInfo(sFileName).fileName();

    if (!m_pOS->setupProcess(m_pFormat, &m_registers, osOptions)) {
        return false;
    }

    m_bReady = true;
    return true;
}

bool XEmuEmulator::isReady() const
{
    return m_bReady;
}

XEmuArch::STEP_INFO XEmuEmulator::step()
{
    XEmuArch::STEP_INFO info;

    if (!m_bReady || !m_pArch) {
        info.result = XEmuArch::STEP_FAULT;
        info.sComment = tr("Emulator is not ready");
        return info;
    }

    // Give the OS personality a chance to service an emulated-API trampoline before
    // the CPU tries to execute it. When handled, the call has already been modelled
    // (return value set, PC advanced past the call), so no instruction is decoded.
    if (m_pOS) {
        XADDR nPC = m_pArch->getPC(&m_registers);

        if (m_pOS->handleApiCall(&m_registers, nPC)) {
            info.nAddress = nPC;
            info.nLength = 0;
            if (m_pOS->processExited()) {
                // The trampoline modelled ExitProcess/TerminateProcess: stop cleanly
                // instead of executing the stub filler and running off into 0.
                info.result = XEmuArch::STEP_HALT;
                info.sText = QStringLiteral("process-exit");
            } else {
                info.result = XEmuArch::STEP_OK;
                info.sText = QStringLiteral("emulated-api");
            }
            return info;
        }
    }

    XEmuArch::STEP_INFO stepInfo = m_pArch->step(&m_registers);

    // The CPU raised a syscall / int 0x80: let the OS personality service it. The
    // instruction pointer has already been advanced past the instruction.
    if (stepInfo.result == XEmuArch::STEP_SYSCALL) {
        // int 0x80 and the bare 0F05 syscall go to the syscall path; every other software
        // interrupt (DOS/BIOS: 0x20, 0x21, 0x10, 0x16, ...) goes to the interrupt path.
        bool bHandled = false;
        if (m_pOS) {
            if ((stepInfo.nVector < 0) || (stepInfo.nVector == 0x80)) {
                bHandled = m_pOS->handleSyscall(&m_registers);
            } else {
                bHandled = m_pOS->handleInterrupt(stepInfo.nVector, &m_registers);
            }
        }
        stepInfo.result = bHandled ? XEmuArch::STEP_OK : XEmuArch::STEP_HALT;  // unhandled, or the process exited
    }

    // The CPU raised a hardware exception (memory access violation). Give the OS
    // personality a chance to dispatch it to a guest handler (Win32 SEH). The arch
    // left the PC at the faulting instruction; if the OS redirects execution to a
    // handler, resume rather than reporting the fault.
    if ((stepInfo.result == XEmuArch::STEP_FAULT) && m_pOS) {
        XADDR nFaultingPC = m_pArch->getPC(&m_registers);
        XADDR nFaultAddress = m_pArch->getFaultAddress();

        if (m_pOS->handleException(&m_registers, nFaultingPC, nFaultAddress)) {
            stepInfo.result = XEmuArch::STEP_OK;
        }
    }

    return stepInfo;
}

qint64 XEmuEmulator::run(qint64 nMaxSteps)
{
    if (!m_bReady || !m_pArch) {
        return 0;
    }

    // Drive the translation-block engine: it translates/caches blocks of micro-ops
    // and interprets them, only returning when it halts, faults, hits an
    // unimplemented opcode or reaches the instruction budget.
    XEmuArch::STEP_INFO info;
    qint64 nExecuted = m_pArch->run(&m_registers, nMaxSteps, &info);

    if (info.result != XEmuArch::STEP_OK) {
        QString sReason;

        switch (info.result) {
            case XEmuArch::STEP_HALT: sReason = tr("halted (%1)").arg(info.sText); break;
            case XEmuArch::STEP_FAULT: sReason = tr("fault at %1 (%2)").arg(info.nAddress, 0, 16).arg(info.sComment); break;
            case XEmuArch::STEP_UNIMPLEMENTED: sReason = tr("unimplemented opcode at %1 (%2)").arg(info.nAddress, 0, 16).arg(info.sText); break;
            default: break;
        }

        emit infoMessage(tr("Execution stopped after %1 instruction(s): %2").arg(nExecuted).arg(sReason));
    } else {
        emit infoMessage(tr("Executed %1 instruction(s); %2 translation block(s) cached").arg(nExecuted).arg(m_pArch->getBlockCacheCount()));
    }

    return nExecuted;
}

XEmuMemoryManager *XEmuEmulator::getMemoryManager()
{
    return &m_memoryManager;
}

XEmuArch *XEmuEmulator::getArch()
{
    return m_pArch;
}

bool XEmuEmulator::fireTimerInterrupt()
{
    return m_pOS ? m_pOS->timerTick(&m_registers) : false;
}

XEmuRegisters *XEmuEmulator::getRegisters()
{
    return &m_registers;
}

QList<XEmuFileFormat::MODULE> XEmuEmulator::getModules() const
{
    if (m_pOS) {
        return m_pOS->getModules();
    }

    return QList<XEmuFileFormat::MODULE>();
}

bool XEmuEmulator::getReplacementImage(QByteArray *pbaImage) const
{
    return m_pOS && m_pOS->getReplacementImage(pbaImage);
}

quint64 XEmuEmulator::getApiStubBase() const
{
    return m_pOS ? m_pOS->apiStubBase() : 0;
}

quint64 XEmuEmulator::getApiStubLimit() const
{
    return m_pOS ? m_pOS->apiStubLimit() : 0;
}

bool XEmuEmulator::resolveImportStub(quint64 nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const
{
    return m_pOS && m_pOS->resolveImportStub(nStub, pLibrary, pFunction, pOrdinal);
}

QString XEmuEmulator::getOSName() const
{
    return m_pOS ? m_pOS->getOSName() : QString();
}

bool XEmuEmulator::getTextScreen(QByteArray *pbaVram, int *pnCols, int *pnRows, int *pnCursorRow, int *pnCursorCol) const
{
    XEmuDOS *pDos = dynamic_cast<XEmuDOS *>(m_pOS);
    if (!pDos) {
        return false;
    }

    const int nCols = XEmuDOS::N_VGA_COLS;
    const int nRows = XEmuDOS::N_VGA_ROWS;
    if (pbaVram) {
        *pbaVram = m_memoryManager.read(XEmuDOS::N_VGA_TEXT_BASE, (quint64)nCols * nRows * 2);
    }
    if (pnCols) {
        *pnCols = nCols;
    }
    if (pnRows) {
        *pnRows = nRows;
    }
    pDos->getCursor(pnCursorRow, pnCursorCol);
    return true;
}

QString XEmuEmulator::getArchName() const
{
    return m_pArch ? m_pArch->getArchName() : QString();
}

QString XEmuEmulator::getRegistersText() const
{
    return m_pArch ? m_pArch->getRegistersText(&m_registers) : QString();
}

QString XEmuEmulator::getMemoryMapText() const
{
    QString sResult;
    QList<XEmuMemoryManager::REGION> listRegions = m_memoryManager.getRegions();

    for (int i = 0; i < listRegions.count(); i++) {
        const XEmuMemoryManager::REGION &region = listRegions.at(i);

        QString sState = (region.state == XEmuMemoryManager::STATE_COMMIT) ? QStringLiteral("COMMIT") : QStringLiteral("RESERVE");
        QString sProtection;
        sProtection += region.flags.bRead ? QLatin1Char('r') : QLatin1Char('-');
        sProtection += region.flags.bWrite ? QLatin1Char('w') : QLatin1Char('-');
        sProtection += region.flags.bExec ? QLatin1Char('x') : QLatin1Char('-');

        sResult += QString("%1 - %2  %3  %4  %5\n")
                       .arg(region.nAddress, 16, 16, QChar('0'))
                       .arg(region.nAddress + region.nSize, 16, 16, QChar('0'))
                       .arg(sState, -7)
                       .arg(sProtection)
                       .arg(region.sName);
    }

    return sResult;
}
