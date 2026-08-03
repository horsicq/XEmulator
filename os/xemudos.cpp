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
#include "xemudos.h"

#include "xemumemorymanager.h"
#include "xemuregisters.h"
#include "xemucom.h"
#include "xemubiosint.h"
#include "xemumsdosint.h"
#include "dos_lowmem.inc"   // g_dosLowMem: DOSBox IVT + BIOS data area snapshot

XEmuDOS::XEmuDOS(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent)
    : XEmuOperatingSystem(pMemoryManager, pArch, pParent), m_pBiosInt(new XEmuBiosInt(pMemoryManager)), m_pMsdosInt(new XEmuMsdosInt(pMemoryManager)),
      m_nCurRow(0), m_nCurCol(0)
{
    // Route both service objects' console output through this personality's line buffer,
    // and DOS diagnostics through infoMessage().
    m_pBiosInt->setOutputSink([this](char c) { _putChar(c); });
    m_pMsdosInt->setOutputSink([this](char c) { _putChar(c); });
    m_pMsdosInt->setLogSink([this](const QString &sText) { emit infoMessage(sText); });
}

XEmuDOS::~XEmuDOS()
{
    delete m_pBiosInt;
    delete m_pMsdosInt;
}

QString XEmuDOS::getOSName() const
{
    return QStringLiteral("MS-DOS");
}

void XEmuDOS::_putChar(char c)
{
    _screenPutChar(c);  // render to the VGA text buffer

    // Keep the line-buffered [stdout] log (useful for headless runs / diagnostics).
    if (c == '\n') {
        _flushOutput();
    } else if (c != '\r') {
        m_baLine.append(c);
        if (m_baLine.size() >= 512) {
            _flushOutput();
        }
    }
}

void XEmuDOS::_flushOutput()
{
    if (!m_baLine.isEmpty()) {
        emit infoMessage(QStringLiteral("[stdout] %1").arg(QString::fromLatin1(m_baLine)));
        m_baLine.clear();
    }
}

// Load and run a child program (INT 21h AH=4Bh AL=00h). The child is placed in a block taken from
// the MCB arena so the PARENT'S IMAGE SURVIVES -- it regains control afterwards and typically has
// cleanup to do (EPACK deletes the TEMP.EXE it just ran). Returns false if the child could not be
// loaded, in which case the caller sets CF and a DOS error.
bool XEmuDOS::_execChild(const QString &sPath, XEmuRegisters *pRegisters)
{
    QFile file(sPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    const QByteArray baFile = file.readAll();
    file.close();
    if (baFile.isEmpty()) {
        return false;
    }

    auto rd16 = [&](int nOff) -> quint16 {
        return (nOff + 1 < baFile.size()) ? (quint16)((quint8)baFile.at(nOff) | ((quint8)baFile.at(nOff + 1) << 8)) : 0;
    };
    const quint8 nM0 = (quint8)baFile.at(0), nM1 = (baFile.size() > 1) ? (quint8)baFile.at(1) : 0;
    const bool bMz = ((nM0 == 'M') && (nM1 == 'Z')) || ((nM0 == 'Z') && (nM1 == 'M'));

    // Work out how much memory the child needs, then take it from the arena.
    QByteArray baLoad;
    quint16 e_ss = 0, e_sp = 0, e_ip = 0, e_cs = 0, e_crlc = 0, e_lfarlc = 0, e_minalloc = 0;
    if (bMz) {
        const quint16 e_cblp = rd16(0x02), e_cp = rd16(0x04), e_cparhdr = rd16(0x08);
        e_crlc = rd16(0x06);
        e_minalloc = rd16(0x0A);
        e_ss = rd16(0x0E); e_sp = rd16(0x10); e_ip = rd16(0x14); e_cs = rd16(0x16); e_lfarlc = rd16(0x18);
        const int nHeaderBytes = (int)e_cparhdr * 16;
        int nTotal = (int)e_cp * 512 - ((e_cblp != 0) ? (512 - e_cblp) : 0);
        if ((nTotal <= 0) || (nTotal > baFile.size())) {
            nTotal = baFile.size();
        }
        baLoad = baFile.mid(nHeaderBytes, qMax(0, nTotal - nHeaderBytes));
    } else {
        baLoad = baFile;  // .COM image: loaded at PSP:0100 with SP at the top of the segment
    }

    const quint16 nImagePara = (quint16)((baLoad.size() + 15) / 16);
    // 0x10 for the PSP, the image, plus whatever the child asked for (a .COM gets a full segment).
    const quint32 nWant = 0x10u + nImagePara + (bMz ? e_minalloc : (quint32)0x1000u);
    quint16 nChildPsp = 0;
    if (!m_pMsdosInt->allocParas((quint16)qMin<quint32>(nWant, 0xFFFF), &nChildPsp) || (nChildPsp == 0)) {
        return false;
    }

    const XADDR nPspLinear = (XADDR)nChildPsp << 4;
    const quint16 nLoadSeg = (quint16)(nChildPsp + 0x10);
    const XADDR nLoadLinear = (XADDR)nLoadSeg << 4;

    // Child PSP. PSP:16h is the PARENT here -- that is the whole point of the field, and it is what
    // a child walks to decide it is not top-level.
    m_pMemoryManager->writeByte(nPspLinear + 0, 0xCD);
    m_pMemoryManager->writeByte(nPspLinear + 1, 0x20);
    _writePspStubs(nPspLinear);
    m_pMemoryManager->writeWord(nPspLinear + 0x02, 0x9FFF);
    m_pMemoryManager->writeWord(nPspLinear + 0x16, m_nPspSeg);
    m_pMemoryManager->writeByte(nPspLinear + 0x80, 0);      // no command tail
    m_pMemoryManager->writeByte(nPspLinear + 0x81, 0x0D);
    _populatePspFcbs(nPspLinear, QString());
    _setupEnvironment(nPspLinear, sPath);

    m_pMemoryManager->write(nLoadLinear, baLoad);
    if (bMz) {
        for (int i = 0; i < (int)e_crlc; i++) {
            const int nRec = (int)e_lfarlc + i * 4;
            if (nRec + 3 >= baFile.size()) {
                break;
            }
            const XADDR nTarget = nLoadLinear + ((XADDR)rd16(nRec + 2) << 4) + rd16(nRec);
            m_pMemoryManager->writeWord(nTarget, (quint16)(m_pMemoryManager->readWord(nTarget) + nLoadSeg));
        }
    }

    // Stack the parent BEFORE touching the registers. RIP already points past the INT, so restoring
    // this state resumes the parent on its next instruction.
    PARENTCTX ctx;
    ctx.regs = *pRegisters;
    ctx.nPspSeg = m_nPspSeg;
    ctx.nChildSeg = nChildPsp;
    m_parents.append(ctx);

    pRegisters->nDS = nChildPsp;
    pRegisters->nES = nChildPsp;
    if (bMz) {
        pRegisters->nCS = (quint16)(nLoadSeg + e_cs);
        pRegisters->nSS = (quint16)(nLoadSeg + e_ss);
        pRegisters->setGPR(XEmuRegisters::GPR_RSP, 2, e_sp);
        pRegisters->nRIP = ((quint64)(nLoadSeg + e_cs) << 4) + e_ip;
    } else {
        pRegisters->nCS = nChildPsp;
        pRegisters->nSS = nChildPsp;
        pRegisters->setGPR(XEmuRegisters::GPR_RSP, 2, 0xFFFE);
        pRegisters->nRIP = nPspLinear + 0x100;
    }
    pRegisters->nRFLAGS = 0x7202;
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0);
    m_nPspSeg = nChildPsp;
    m_pMsdosInt->setPspSegment(nChildPsp);
    emit infoMessage(tr("INT 21h.4B exec '%1' -> PSP %2").arg(sPath).arg(nChildPsp, 4, 16, QChar('0')));
    return true;
}

// The running child called AH=4Ch / INT 20h. Put the parent back exactly as it was and let it carry
// on -- returning false here would end the whole run, which is what used to happen.
bool XEmuDOS::_returnToParent(XEmuRegisters *pRegisters, quint8 nExitCode)
{
    if (m_parents.isEmpty()) {
        return false;
    }
    const PARENTCTX ctx = m_parents.takeLast();
    m_pMsdosInt->freeSeg(ctx.nChildSeg);
    *pRegisters = ctx.regs;
    m_nPspSeg = ctx.nPspSeg;
    m_pMsdosInt->setPspSegment(ctx.nPspSeg);
    m_nLastChildExit = nExitCode;
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
    emit infoMessage(tr("INT 21h.4B child exited (code %1); resumed parent PSP %2").arg(nExitCode).arg(ctx.nPspSeg, 4, 16, QChar('0')));
    return true;
}

// PSP offsets 05h and 50h hold executable stubs in real DOS, and both were left as zeros here.
// 05h is the CP/M-compatibility far entry (a 5-byte far call/jump into the DOS dispatcher) and 50h
// is "INT 21h / RETF", the documented far-call entry a program uses instead of INT 21h. A program
// that far-calls either one previously executed zeros. DOSBox has EAh at 05h and CD 21 CB at 50h.
void XEmuDOS::_writePspStubs(XADDR nPspLinear)
{
    m_pMemoryManager->writeByte(nPspLinear + 0x05, 0xEA);  // CP/M far transfer (target unmodelled)
    m_pMemoryManager->writeByte(nPspLinear + 0x50, 0xCD);  // int 21h
    m_pMemoryManager->writeByte(nPspLinear + 0x51, 0x21);
    m_pMemoryManager->writeByte(nPspLinear + 0x52, 0xCB);  // retf
}

void XEmuDOS::_populateLowMem()
{
    // Seed the IVT (0000:0000..0000:03FF) and BIOS data area (0000:0400..0000:05FF) with a real
    // DOSBox snapshot, so anti-tamper packers that read interrupt vectors (INT 21h AH=35h) or
    // BIOS-data fields (equipment word, memory size, ...) see plausible values instead of zeros.
    // XEMU_LOWMEM=<file> substitutes a snapshot taken from the emulator being trace-diffed against
    // (dump it there with tests' lowdump.asm). The built-in snapshot is what the byte-identical
    // packer corpus is calibrated against, so it stays the default -- vectors differ between DOSBox
    // builds (e.g. IVT[2Fh] = F000:15C0 vs F000:15A0), which shows up as a false divergence in a diff.
    QByteArray baLow(reinterpret_cast<const char *>(g_dosLowMem), (int)sizeof(g_dosLowMem));
    if (!qEnvironmentVariableIsEmpty("XEMU_LOWMEM")) {
        QFile fileLow(qEnvironmentVariable("XEMU_LOWMEM"));
        if (fileLow.open(QIODevice::ReadOnly)) {
            const QByteArray baRead = fileLow.read(sizeof(g_dosLowMem));
            if (baRead.size() == (int)sizeof(g_dosLowMem)) {
                baLow = baRead;
                emit infoMessage(QStringLiteral("low memory loaded from %1").arg(fileLow.fileName()));
            }
        }
    }
    for (int i = 0; i < baLow.size(); i++) {
        m_pMemoryManager->writeByte((XADDR)i, (quint8)baLow.at(i));
    }
    // The BIOS handler addresses the vectors point at are not backed by real code here. Fill the whole
    // F000 ROM segment with IRET so that ANY entry into the BIOS -- an IVT vector we don't model, or a
    // program jumping there deliberately -- returns immediately. Previously only two addresses were
    // stubbed and the rest was zeros, so a stray entry executed 0x0000 ("add [bx+si],al") forever:
    // MASK burned 1.74M instructions inside F000 where DOSBox spends 29.
    // The F000 BIOS ROM segment has to be right in TWO ways at once, and they pull in opposite
    // directions.
    //   As CODE: a stray entry into unmodelled BIOS must return immediately. 0xCF (IRET) at every
    //     address does that -- MASK once burned 1.74M instructions in here where DOSBox spends 29.
    //   As DATA: protections fingerprint the ROM to identify the machine. EXELOCK 1.0 records the
    //     240 bytes at F000:0000 when it packs and refuses to run if they differ; DOSBox has zeros
    //     there, so an IRET fill made every EXELOCK-protected file print "Protection error."
    // So: IRET everywhere, then DOSBox's real values in the regions that are actually read as data.
    //
    // Installing DOSBox's whole 64 KiB ROM image instead was tried and rejected on measurement, not
    // taste. Its callback stubs are `FE 38 <n>`, and FE /7 is an INVALID x86 opcode -- this decoder
    // reads it as `dec byte [bx+si]` (a stray write into guest memory) and then decodes the callback
    // number as an instruction. And an image captured from a different DOSBox build than the IVT
    // snapshot in dos_lowmem.inc puts every F000 vector one callback slot out of phase, which lands
    // eight of them on padding and INT 20h on a RETF where an interrupt entry needs IRET.
    for (XADDR a = 0xF0000; a < 0x100000; a++) {
        m_pMemoryManager->writeByte(a, 0xCF);  // IRET: any stray entry returns at once
    }
    // DOSBox's F000 is all zero below 0x1020, and the lowest address any boot vector points at is
    // 0x1100, so zeroing the first 4 KiB is safe for the execute path and matches the reference for
    // every fingerprinting protection that reads the start of the ROM.
    for (XADDR a = 0xF0000; a < 0xF1000; a++) {
        m_pMemoryManager->writeByte(a, 0x00);
    }
    // The two most-read ROM identity fields: the release date at F000:FFF5 and the machine model
    // byte at F000:FFFE (FCh = AT). Both are classic machine-type checks.
    {
        static const char s_szBiosDate[] = "01/01/92";
        for (int i = 0; i < 8; i++) {
            m_pMemoryManager->writeByte(0xFFFF5 + i, (quint8)s_szBiosDate[i]);
        }
        m_pMemoryManager->writeByte(0xFFFFE, 0xFC);
    }
    m_pMemoryManager->writeByte(0x00708, 0xCF);  // 0070:0008 (DOS default) -> IRET
    // The DOS entry point the IVT's INT 21h vector points at (F000:14A0 in the snapshot). A program that
    // HOOKS INT 21h chains to whatever it saved from that vector, so that address must actually service
    // DOS. Put "int 21h; iret" there: re-entering INT 21h with CS=F000 is serviced natively (see
    // handleInterrupt) instead of being re-dispatched to the hook, which breaks the recursion, and the
    // IRET then unwinds the frame pushed when we dispatched to the hook.
    m_pMemoryManager->writeByte(0xF14A0, 0xCD);
    m_pMemoryManager->writeByte(0xF14A1, 0x21);
    m_pMemoryManager->writeByte(0xF14A2, 0xCF);

    // Remember the vector table as booted, so _dispatchGuestInterrupt can tell "the guest hooked this"
    // from "still the default" without guessing address ranges.
    for (int v = 0; v < 256; v++) {
        m_nBootIvt[v] = ((quint32)m_pMemoryManager->readWord((XADDR)v * 4 + 2) << 16) | m_pMemoryManager->readWord((XADDR)v * 4);
    }
}

void XEmuDOS::_screenClear()
{
    for (int i = 0; i < N_VGA_COLS * N_VGA_ROWS; i++) {
        m_pMemoryManager->writeByte(N_VGA_TEXT_BASE + i * 2, (quint8)' ');
        m_pMemoryManager->writeByte(N_VGA_TEXT_BASE + i * 2 + 1, 0x07);  // light-grey on black
    }
    m_nCurRow = 0;
    m_nCurCol = 0;
}

void XEmuDOS::_screenScroll()
{
    for (int r = 1; r < N_VGA_ROWS; r++) {
        for (int col = 0; col < N_VGA_COLS; col++) {
            XADDR nFrom = N_VGA_TEXT_BASE + (r * N_VGA_COLS + col) * 2;
            XADDR nTo = N_VGA_TEXT_BASE + ((r - 1) * N_VGA_COLS + col) * 2;
            m_pMemoryManager->writeByte(nTo, m_pMemoryManager->readByte(nFrom));
            m_pMemoryManager->writeByte(nTo + 1, m_pMemoryManager->readByte(nFrom + 1));
        }
    }
    for (int col = 0; col < N_VGA_COLS; col++) {
        XADDR nCell = N_VGA_TEXT_BASE + ((N_VGA_ROWS - 1) * N_VGA_COLS + col) * 2;
        m_pMemoryManager->writeByte(nCell, (quint8)' ');
        m_pMemoryManager->writeByte(nCell + 1, 0x07);
    }
}

void XEmuDOS::_screenPutChar(char c)
{
    if (c == '\r') {
        m_nCurCol = 0;
    } else if (c == '\n') {
        m_nCurRow++;
    } else if (c == '\b') {
        if (m_nCurCol > 0) {
            m_nCurCol--;
        }
    } else if (c == '\t') {
        m_nCurCol = (m_nCurCol + 8) & ~7;
    } else if ((quint8)c == 7) {
        // BEL: no audible effect in the model
    } else {
        XADDR nCell = N_VGA_TEXT_BASE + (m_nCurRow * N_VGA_COLS + m_nCurCol) * 2;
        m_pMemoryManager->writeByte(nCell, (quint8)c);
        m_pMemoryManager->writeByte(nCell + 1, 0x07);
        m_nCurCol++;
    }
    if (m_nCurCol >= N_VGA_COLS) {
        m_nCurCol = 0;
        m_nCurRow++;
    }
    while (m_nCurRow >= N_VGA_ROWS) {
        _screenScroll();
        m_nCurRow = N_VGA_ROWS - 1;
    }
}

bool XEmuDOS::timerTick(XEmuRegisters *pRegisters)
{
    // IRQ0 only fires with interrupts enabled, and injecting it is pointless unless the guest
    // installed its own handler -- the BIOS default merely counts the tick, which the harness
    // already maintains at 0040:006C. EXELOCK 666 hooks the timer and spins until its handler runs.
    if (!pRegisters->getFlag(XEmuRegisters::FLAG_IF)) {
        return false;
    }
    return _dispatchGuestInterrupt(0x08, pRegisters);
}

bool XEmuDOS::handleInterrupt(int nVector, XEmuRegisters *pRegisters)
{
    switch (nVector) {
        case 0x20:  // terminate program
            if (_returnToParent(pRegisters, 0)) {  // a child exiting: hand control back to its parent
                return true;
            }
            _flushOutput();
            emit infoMessage(QStringLiteral("INT 20h: program terminated"));
            return false;

        case 0x21: {  // DOS services
            // If the program has hooked INT 21h, its handler must run first -- packers/protectors install
            // one to watch or fake DOS calls. Re-entry from our own F000 stub (the chain target) is
            // serviced natively, which terminates the chain.
            // Guard against recursion: a hook that itself issues `int 21h` (rather than chaining with a
            // far JMP) would otherwise be dispatched into itself forever. While a dispatched hook is on
            // the stack, service DOS natively.
            if (!m_bInInt21Hook && (pRegisters->nCS != 0xF000) && _dispatchGuestInterrupt(0x21, pRegisters)) {
                m_bInInt21Hook = true;
                return true;
            }
            m_bInInt21Hook = false;  // reached the real service: the chain has ended

            // AH=4Bh EXEC and AH=4Dh (child exit code) are process control, which needs the loader
            // and the parent stack -- they live here rather than in the INT 21h service object.
            const quint8 nAh = (quint8)((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2) >> 8) & 0xFF);
            if (nAh == 0x4B) {
                const quint8 nAl = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
                const QString sChild = m_pMsdosInt->resolveGuestPath(pRegisters->nDS, (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2));
                // AL=00 load-and-execute is the only form anything here uses; AL=01 (load, don't
                // run) and AL=03 (load overlay) hand back control differently and are not modelled,
                // so report them as unsupported rather than pretending.
                if ((nAl == 0x00) && _execChild(sChild, pRegisters)) {
                    return true;
                }
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, true);
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, (nAl == 0x00) ? 2 : 1);  // file not found / invalid function
                emit infoMessage(tr("INT 21h.4B exec failed (AL=%1) '%2'").arg(nAl).arg(sChild));
                return true;
            }
            if (nAh == 0x4D) {  // get child return code
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, m_nLastChildExit);
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
                return true;
            }

            bool bTerminate = false;
            m_pMsdosInt->int21(pRegisters, &bTerminate);
            if (bTerminate) {
                // A child terminating resumes its parent instead of ending the run.
                const quint8 nExit = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
                if (_returnToParent(pRegisters, nExit)) {
                    return true;
                }
                _flushOutput();
                return false;
            }
            return true;
        }

        case 0x2F: {  // DOS multiplex interrupt
            quint16 nAx = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
            if ((nAx & 0xFF00) == 0x4300) {
                // XMS installation check: report NOT installed (AL != 0x80) so packers fall back to
                // conventional memory. The compressed output is the same wherever the buffers live.
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, 0x00);
            }
            return true;  // other multiplex calls: benign no-op
        }

        case 0x67:  // EMS / VCPI. Report NOT present: AH=DE00 (VCPI check) returns AH != 0 -> absent,
                    // so packers fall back to conventional memory (same compressed output).
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x8F00);  // AH=0x8F (not present), AL=0
            return true;

        case 0x33: {  // mouse driver services. Report NO mouse installed so callers skip mouse setup.
            quint16 nAx = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
            if (nAx == 0x0000) {                                        // reset / installation check
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0000);  // AX=0 -> driver not installed
                pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, 0x0000);  // BX = 0 buttons
            }
            return true;  // other subfunctions: benign no-op (no mouse to service)
        }

        case 0x15: {  // BIOS system services -- packers probe extended memory to size buffers
            quint16 nAx = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
            quint8 nAh = (quint8)(nAx >> 8);
            if (nAh == 0x88) {  // get extended memory size (KB) -> AX; report none (conventional only)
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0000);
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
            } else {  // E801/C7 (memory map), C0 (config table), 87 (block move), 24 (A20), ...: unsupported
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, true);
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, 0x86);  // AH=86h "unsupported function"
            }
            return true;
        }

        case 0x29:  // DOS fast console output: AL -> console
            _putChar((char)(quint8)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1));
            return true;

        default:
            if (m_pBiosInt->handle(nVector, pRegisters)) {  // BIOS video / keyboard
                return true;
            }
            if (_dispatchGuestInterrupt(nVector, pRegisters)) {  // program's own INT handler in RAM
                return true;
            }
            // A software INT to a vector nothing models: on a real DOS machine every IVT entry points
            // to at least an IRET stub, so `int N` for an unused/odd N (BIOS default, or a value a packer
            // computes at runtime -- e.g. PACK does `int <BIOS-tick-byte>` as an anti-debug flourish)
            // simply returns. Mirror that: log it but continue rather than halt. This can only turn a
            // former halt into progress, so it cannot regress a packer that already worked.
            emit infoMessage(QStringLiteral("unhandled INT 0x%1 (AX=0x%2) -> benign return")
                                 .arg(nVector, 2, 16, QChar('0'))
                                 .arg(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2), 4, 16, QChar('0')));
            return true;
    }
}

// Software INT to a handler the program installed for itself: when the guest IVT entry
// for a vector points into conventional RAM (the program image or an allocated block, not
// the BIOS ROM at 0xF000 or the DOS/IVT low area), dispatch through it exactly like real
// hardware -- push FLAGS:CS:IP, clear IF/TF, and jump to seg:off. The handler's IRET returns
// to the instruction after the INT. This models packers that call their own interrupt
// routines or reassign a vector as an anti-debug indirection (PACK via int3 -> IVT[3],
// Pksmart via int 37h -> IVT[37h]) instead of the emulator halting on the vector. Vectors
// serviced by the built-in DOS/BIOS layer never reach here, so this cannot shadow them.
quint16 XEmuDOS::_setupEnvironment(quint64 nPspBase, const QString &sProgName)
{
    // DOS gives every program an environment block and stores its segment at PSP:2Ch. Programs
    // (and PKZIP, which PGMPAK bundles) read it -- a missing block (segment 0) makes them take a
    // different code path. Match DOSBox 0.74's default master environment plus the ASCIIZ program
    // path that DOS appends after the double-NUL. Placed directly below the PSP (env MCB + 0x49-para
    // block == 0x4A paragraphs), matching DOSBox: PSP 0814 -> env 07CA.
    const quint16 nEnvSeg = (quint16)((nPspBase >> 4) - 0x4A);
    const XADDR nEnvBase = (XADDR)nEnvSeg << 4;
    QByteArray baEnv;
    baEnv += QByteArrayLiteral("PATH=Z:\\") + '\0';
    baEnv += QByteArrayLiteral("COMSPEC=Z:\\COMMAND.COM") + '\0';
    baEnv += QByteArrayLiteral("BLASTER=A220 I7 D1 H5 T6") + '\0';
    baEnv += '\0';                                        // double-NUL terminates the variables
    baEnv += QByteArray::fromRawData("\x01\x00", 2);      // one following string
    baEnv += (QByteArrayLiteral("C:\\") + sProgName.toUpper().toLatin1()) + '\0';  // program path
    m_pMemoryManager->write(nEnvBase, baEnv);
    m_pMemoryManager->writeWord(nPspBase + 0x2C, nEnvSeg);
    return nEnvSeg;
}

void XEmuDOS::_populatePspFcbs(quint64 nPspBase, const QString &sCmdLine)
{
    // COMMAND.COM parses the first two command-line arguments into the two default FCBs at
    // PSP:5C and PSP:6C (drive byte + 8-char name + 3-char extension, blank-padded, upper-cased).
    // Old tools (e.g. PGMPAK) read the input filename from FCB1 rather than the command tail, so
    // an all-zero FCB makes them see no file and bail.
    // The switch character ends the FCB parse. DOS scans the tail for filenames and STOPS at the
    // first argument beginning with '/', leaving that FCB and any after it blank -- it does not skip
    // the switch and carry on. Measured against DOSBox: `DOSCONF /N` leaves FCB1 blank, and
    // `DOSCONF large.exe /N -x` puts LARGE.EXE in FCB1 and leaves FCB2 blank even though `-x`
    // follows. A leading '-' is NOT a switch, and both emulators parse `-N` into an FCB normally.
    // Getting this wrong makes a program see a phantom input file named after a switch.
    const quint64 nFcb[2] = {nPspBase + 0x5C, nPspBase + 0x6C};
    QStringList tokens = sCmdLine.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    for (int i = 0; i < tokens.size(); i++) {
        if (tokens.at(i).startsWith(QLatin1Char('/'))) {
            while (tokens.size() > i) {  // the switch STOPS the parse; it does not merely get skipped
                tokens.removeLast();
            }
            break;
        }
    }
    for (int i = 0; i < 2; i++) {
        m_pMemoryManager->writeByte(nFcb[i], 0x00);  // drive 0 = default
        for (int j = 0; j < 11; j++) {
            m_pMemoryManager->writeByte(nFcb[i] + 1 + j, 0x20);  // name+ext blank-padded
        }
        if (i >= tokens.size()) {
            continue;
        }
        QString tok = tokens.at(i).toUpper();
        if ((tok.size() >= 2) && (tok.at(1) == QLatin1Char(':'))) {  // optional "X:" drive prefix
            m_pMemoryManager->writeByte(nFcb[i], (quint8)(tok.at(0).toLatin1() - 'A' + 1));
            tok = tok.mid(2);
        }
        const QString sName = tok.section(QLatin1Char('.'), 0, 0);
        const QString sExt = tok.section(QLatin1Char('.'), 1, 1);
        for (int j = 0; (j < 8) && (j < sName.size()); j++) {
            m_pMemoryManager->writeByte(nFcb[i] + 1 + j, (quint8)sName.at(j).toLatin1());
        }
        for (int j = 0; (j < 3) && (j < sExt.size()); j++) {
            m_pMemoryManager->writeByte(nFcb[i] + 9 + j, (quint8)sExt.at(j).toLatin1());
        }
    }
}

bool XEmuDOS::_dispatchGuestInterrupt(int nVector, XEmuRegisters *pRegisters)
{
    const XADDR nEntry = (XADDR)(nVector & 0xFF) * 4;
    const quint16 nHOff = m_pMemoryManager->readWord(nEntry);
    const quint16 nHSeg = m_pMemoryManager->readWord(nEntry + 2);
    // Only a handler in the guest's own conventional memory. 0x0800 clears the IVT / BIOS
    // data / DOS-kernel low area (COM programs load at PSP 0x0814, EXEs at 0x1000); 0xA000
    // excludes video RAM and the BIOS ROM. A null vector (0000:0000) is never a real handler.
    // Dispatch only to a handler the GUEST installed. Address-range guesses do not work here: a
    // program may relocate itself anywhere, even below its own PSP (EXEGUARD runs at 03A9 with its
    // PSP at 0435), so any fixed or PSP-derived floor both misses real handlers and risks calling
    // DOS/BIOS internals. Instead compare against the vector table as it was at boot: if the entry
    // still holds the default we installed, nothing hooked it -- service it natively.
    const quint32 nNow = ((quint32)nHSeg << 16) | nHOff;
    if ((nVector >= 0) && (nVector < 256) && (nNow == m_nBootIvt[nVector])) {
        return false;
    }
    if (nHSeg >= 0xA000) {  // video RAM / BIOS ROM is never a guest handler
        return false;
    }

    quint16 nSP = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 2);
    const XADDR nSSBase = (XADDR)pRegisters->nSS << 4;
    const quint16 nFlags = (quint16)(pRegisters->nRFLAGS & 0xFFFF);
    const quint16 nRetIP = (quint16)(pRegisters->nRIP - ((XADDR)pRegisters->nCS << 4));  // RIP is post-INT

    nSP -= 2;
    m_pMemoryManager->writeWord(nSSBase + nSP, nFlags);
    nSP -= 2;
    m_pMemoryManager->writeWord(nSSBase + nSP, pRegisters->nCS);
    nSP -= 2;
    m_pMemoryManager->writeWord(nSSBase + nSP, nRetIP);
    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 2, nSP);

    pRegisters->setFlag(XEmuRegisters::FLAG_IF, false);
    pRegisters->setFlag(XEmuRegisters::FLAG_TF, false);
    pRegisters->nCS = nHSeg;
    pRegisters->nRIP = ((XADDR)nHSeg << 4) + nHOff;
    return true;
}

bool XEmuDOS::setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options)
{
    m_listModules.clear();

    // Root INT 21h file I/O at the requested working directory (falls back to the process CWD).
    m_pMsdosInt->setWorkingDirectory(options.sWorkingDirectory);

    if (!pMainFormat || !pMainFormat->isValid()) {
        emit errorMessage(tr("Invalid main module"));
        return false;
    }

    m_pMemoryManager->clear();
    m_pMemoryManager->setBits(32);  // flat linear backing store
    m_pArch->setBits(16);           // 16-bit real mode

    // --- COM: flat image loaded at offset 0x100 in the program's segment ---
    if (pMainFormat->isDosCom()) {
        XEmuCOM *pCom = dynamic_cast<XEmuCOM *>(pMainFormat);
        QByteArray baData = pCom ? pCom->getData() : QByteArray();

        // Back the whole real-mode address space as one flat RWX region, from a low segment up
        // through ~1 MiB -- not just the program's own 64 KiB. Real-mode code (especially crypters
        // and self-relocating packers) forms far pointers into other segments: video, high
        // conventional memory, or a computed low scratch segment. Mapping from a low base means
        // those segment:offset addresses all resolve into real RAM. INT vectors are still modelled
        // via handleInterrupt, not a resident IVT, so the very bottom (segment 0) is left unmapped.
        const quint64 nRealModeTop = 0x120000;  // segment 0xFFFF + 64 KiB, plus A20 headroom
        if (!m_pMemoryManager->mapFixed(0, nRealModeTop, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("MS-DOS_memory"))) {
            emit errorMessage(tr("Cannot allocate the DOS memory"));
            return false;
        }
        _populateLowMem();
        // .COM program segment = 0x0814 (linear 0x8140), matching the DOS/DOSBox PSP for a program
        // run from COMMAND.COM. Anti-tamper packers (e.g. $PIRIT) index their own code by the PSP
        // segment value (mov cl,[bx] with bx=PSP from INT 21h AH=62), so it must match the reference.
        const XADDR nSegBase = 0x8140;

        m_pMemoryManager->writeByte(nSegBase + 0, 0xCD);  // PSP: INT 20h
        m_pMemoryManager->writeByte(nSegBase + 1, 0x20);
        _writePspStubs(nSegBase);
        m_pMemoryManager->writeWord(nSegBase + 0x02, 0x9FFF);  // segment past program memory
                                                          // (DOSBox 0.74 reports 9FFF, not A000: the last
                                                          // paragraph below video RAM is not handed out.
                                                          // Verified with tests/tracediff/memprobe.asm.)
        // PSP:16h = parent PSP. There is no shell here, so point it at ourselves -- the same
        // approximation the EXE loader makes, and what a program's "am I top-level?" self-check
        // (cmp ax,es:[0016]) expects. Leaving it 0 made that check take a dead branch.
        m_pMemoryManager->writeWord(nSegBase + 0x16, (quint16)(nSegBase >> 4));
        m_pMemoryManager->write(nSegBase + 0x100, baData);  // program image at CS:0100

        // PSP command tail at offset 0x80: a length byte, then a leading space, the
        // argument string, and a terminating CR. Programs read their arguments from here.
        {
            // DOS writes a LEADING SPACE before the arguments, but only when there ARE arguments: with an
            // empty command line the tail is just the terminating CR and PSP:80 (the length) is 0.
            // Emitting " " unconditionally made PSP:80 = 1, so the universal `mov cl,[80h] / jcxz
            // no_args` test saw an argument that DOS does not show. Verified against DOSBox both ways:
            // with an argument both emulators report length 2, without one DOSBox reports 0.
            QByteArray baTail = options.sCommandLine.isEmpty() ? QByteArray()
                                                               : (QByteArrayLiteral(" ") + options.sCommandLine.toLatin1());
            baTail.truncate(126);
            m_pMemoryManager->writeByte(nSegBase + 0x80, (quint8)baTail.size());
            m_pMemoryManager->write(nSegBase + 0x81, baTail);
            m_pMemoryManager->writeByte(nSegBase + 0x81 + baTail.size(), 0x0D);
        }
        _populatePspFcbs(nSegBase, options.sCommandLine);
        const quint16 nComEnvSeg = _setupEnvironment(nSegBase, options.sProgramName);  // env block -> PSP:2Ch
        m_pMsdosInt->setPspSegment((quint16)(nSegBase >> 4));  // PSP segment for AH=55/62 tracking
        // A .COM owns all of conventional memory from its PSP to the top. The EXE loader has always
        // built an MCB chain; the COM path never did, so m_nFirstMcb stayed 0 and anything that walks
        // the chain (AH=52h, "how much memory is free", TSR enumeration) had nothing to walk.
        m_pMsdosInt->mcbSetup(nComEnvSeg, 0x49, (quint16)(nSegBase >> 4), (quint16)(0x9FFF - (nSegBase >> 4)), 0x9FFF);

        _screenClear();  // blank the VGA text page (mapped inside the 1 MiB region at 0xB8000)

        XEmuFileFormat::MODULE module;
        module.sName = pCom ? pCom->getModuleName() : QStringLiteral("program.com");
        module.nBaseAddress = nSegBase + 0x100;
        module.nImageSize = (quint64)baData.size();
        module.nEntryPointAddress = nSegBase + 0x100;
        m_listModules.append(module);

        quint16 nSegment = (quint16)((nSegBase >> 4) & 0xFFFF);
        pRegisters->reset();
        pRegisters->nRFLAGS = 0x7202;  // see the EXE path: DOS-provided FLAGS (IOPL=3/NT/IF)
        pRegisters->nRIP = nSegBase + 0x100;
        pRegisters->nCS = nSegment;
        pRegisters->nDS = nSegment;
        pRegisters->nES = nSegment;
        pRegisters->nSS = nSegment;
        m_pArch->setStackPointer(pRegisters, 0xFFFE);
        // DOS leaves several GP registers non-zero at COM entry; anti-tamper packers (e.g. $PIRIT)
        // seed their decrypt counter from CX. Match the reference loader (DOSBox): SI=IP(0x100),
        // DI=SP(0xFFFE), DX=PSP, plus COMMAND.COM's constant EXEC leftovers CX=0x00FF, BP=0x091C
        // (identical leftovers observed at EPACK's .EXE entry).
        pRegisters->setGPR(XEmuRegisters::GPR_RSI, 2, 0x0100);
        pRegisters->setGPR(XEmuRegisters::GPR_RDI, 2, 0xFFFE);
        pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, nSegment);
        pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 0x00FF);
        pRegisters->setGPR(XEmuRegisters::GPR_RBP, 2, 0x091C);

        emit infoMessage(tr("MS-DOS .COM loaded: segment %1, entry CS:0100 (linear %2)").arg(nSegment, 4, 16, QChar('0')).arg(nSegBase + 0x100, 0, 16));
        return true;
    }

    // --- MZ / EXE: load into a full real-mode conventional-memory region and relocate ---
    //
    // Back the whole real-mode address space (segments 0x0100..0xFFFF) as one flat RWX region,
    // not just the file image. Self-extracting / self-relocating EXE stubs move their image or
    // stack to other segments (top of conventional memory, a computed low segment, ...); with
    // only the ~image-sized window mapped any such access faults. One shared region lets those
    // segment:offset addresses resolve into real RAM, exactly like the COM path above.
    const quint64 nRealModeTop = 0x120000;  // segment 0xFFFF + 64 KiB offset, plus A20 headroom
    if (!m_pMemoryManager->mapFixed(0, nRealModeTop, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("MS-DOS_memory"))) {
        emit errorMessage(tr("Cannot allocate the DOS memory"));
        return false;
    }
    _populateLowMem();

    const QByteArray &baFile = m_baImageFile;
    // Accept both signatures: "MZ" (0x4D 0x5A, the usual) and "ZM" (0x5A 0x4D, an equally valid
    // alternate DOS emitted by some linkers -- e.g. MEGALITE.EXE). DOS itself accepts either order.
    const quint8 nMagic0 = baFile.size() >= 2 ? (quint8)baFile.at(0) : 0;
    const quint8 nMagic1 = baFile.size() >= 2 ? (quint8)baFile.at(1) : 0;
    const bool bMz = ((nMagic0 == 'M') && (nMagic1 == 'Z')) || ((nMagic0 == 'Z') && (nMagic1 == 'M'));
    if ((baFile.size() < 0x20) || !bMz) {
        emit errorMessage(tr("Invalid MZ header"));
        return false;
    }
    auto rd16 = [&](int nOff) -> quint16 { return (nOff + 1 < baFile.size()) ? (quint16)((quint8)baFile.at(nOff) | ((quint8)baFile.at(nOff + 1) << 8)) : 0; };

    quint16 e_cblp = rd16(0x02), e_cp = rd16(0x04), e_crlc = rd16(0x06), e_cparhdr = rd16(0x08);
    quint16 e_minalloc = rd16(0x0A), e_maxalloc = rd16(0x0C);
    quint16 e_ss = rd16(0x0E), e_sp = rd16(0x10), e_ip = rd16(0x14), e_cs = rd16(0x16), e_lfarlc = rd16(0x18);

    int nHeaderBytes = (int)e_cparhdr * 16;
    int nTotalBytes = (int)e_cp * 512 - ((e_cblp != 0) ? (512 - e_cblp) : 0);
    if ((nTotalBytes <= 0) || (nTotalBytes > baFile.size())) {
        nTotalBytes = baFile.size();
    }
    int nLoadBytes = qMax(0, nTotalBytes - nHeaderBytes);
    QByteArray baLoad = baFile.mid(nHeaderBytes, nLoadBytes);

    // DOS layout: PSP at segment 0x0814 (matching DOSBox, so the MCB chain hands out the same segments
    // /sizes that programs which manage memory -- e.g. PGMPAK's bundled PKZIP -- depend on). Normally the
    // load module starts one PSP (0x10 paragraphs) above it (low load). BUT when e_maxalloc == 0 the
    // program is a "load-high" image: DOS allocates the largest free block, keeps the PSP low, and places
    // the image at the TOP of the block. Such programs run with a high CS and check their low buffers fit
    // below the code -- loading them low makes that check fail.
    // PSP at linear 0x8140 (DOSBox-compatible). XEMU_PSP_SEG (hex) overrides it: when trace-diffing
    // against a reference emulator whose low-memory layout differs, matching its PSP makes every
    // segment value identical, so the diff shows only genuine divergences instead of drowning in
    // benign load-address differences that propagate through far-pointer arithmetic.
    quint16 nPspSeg = 0x0814;
    if (!qEnvironmentVariableIsEmpty("XEMU_PSP_SEG")) {
        const quint16 nOverride = qEnvironmentVariable("XEMU_PSP_SEG").toUShort(nullptr, 16);
        if (nOverride >= 0x0100) {
            nPspSeg = nOverride;
        }
    }
    // Top of the MCB arena. A normal (low-load) program owns conventional RAM up to the true
    // 640 KiB ceiling (0xA000, matching PSP:02h) so an AH=4Ah "grow to my memtop" request (e.g.
    // PACK's 0x97EC = 0xA000-PSP) succeeds. A load-high (maxalloc==0) image sits at the top, so
    // the allocatable region ends one paragraph lower at 0x9FFF (this is what PGMPAK's bundled
    // PKZIP sees, and it matches DOSBox's block sizes for it byte-for-byte).
    const quint16 nMemTop = (e_maxalloc == 0) ? 0x9FFF : 0xA000;
    const quint16 nImagePara = (quint16)((nLoadBytes + 15) / 16);
    quint16 nLoadSeg;
    if (e_maxalloc == 0) {
        nLoadSeg = (quint16)(0xA000 - nImagePara - e_minalloc);  // image just under the 640 KiB ceiling
    } else {
        nLoadSeg = nPspSeg + 0x10;  // low load, immediately above the PSP
    }
    const XADDR nPspLinear = (XADDR)nPspSeg << 4;
    const XADDR nLoadLinear = (XADDR)nLoadSeg << 4;

    m_pMemoryManager->writeByte(nPspLinear + 0, 0xCD);  // PSP: INT 20h
    m_pMemoryManager->writeByte(nPspLinear + 1, 0x20);
    _writePspStubs(nPspLinear);
    m_pMemoryManager->writeWord(nPspLinear + 0x02, 0x9FFF);  // segment past program memory (see the COM path above)
    // PSP:16h = parent process's PSP. There is no shell here, so point it at ourselves: DOS gives
    // COMMAND.COM's PSP a self-referencing parent, and programs walk the chain looking for exactly
    // that self-reference to decide "I am a top-level process". Leaving it 0 made EXEGUARD's
    // `mov ax,[0016] / mov es,ax / cmp ax,es:[0016] / je` test fail and take a dead branch.
    m_pMemoryManager->writeWord(nPspLinear + 0x16, nPspSeg);
    {
        // See the COM path above: the leading space is only present when there are arguments.
        QByteArray baTail = options.sCommandLine.isEmpty() ? QByteArray()
                                                           : (QByteArrayLiteral(" ") + options.sCommandLine.toLatin1());
        baTail.truncate(126);
        m_pMemoryManager->writeByte(nPspLinear + 0x80, (quint8)baTail.size());
        m_pMemoryManager->write(nPspLinear + 0x81, baTail);
        m_pMemoryManager->writeByte(nPspLinear + 0x81 + baTail.size(), 0x0D);
    }
    _populatePspFcbs(nPspLinear, options.sCommandLine);
    quint16 nEnvSeg = _setupEnvironment(nPspLinear, options.sProgramName);  // env block -> PSP:2Ch
    m_pMsdosInt->setPspSegment(nPspSeg);  // PSP segment for AH=55/62 tracking
    m_nPspSeg = nPspSeg;                 // lower bound for dispatching INTs to guest handlers
    // MCB chain: env block (0x49 paras) then the program block owning to the memory top. A maxalloc==0
    // load-high program owns everything and shrinks/splits it via AH=4A to make room for its children;
    // a normal program is sized to its image + maxalloc with the remainder free.
    {
        quint16 nOwnParas = (e_maxalloc == 0) ? (quint16)(nMemTop - nPspSeg)
                                              : (quint16)qMin((int)(nMemTop - nPspSeg),
                                                              (int)(0x10 + nImagePara + e_minalloc + e_maxalloc));
        m_pMsdosInt->mcbSetup(nEnvSeg, 0x49, nPspSeg, nOwnParas, nMemTop);
    }

    m_pMemoryManager->write(nLoadLinear, baLoad);  // program image

    // Apply MZ relocations: each (segment, offset) points at a word holding a paragraph value
    // that must be biased by the actual load paragraph.
    for (int i = 0; i < (int)e_crlc; i++) {
        int nRec = (int)e_lfarlc + i * 4;
        if (nRec + 3 >= baFile.size()) {
            break;
        }
        quint16 nRelOff = rd16(nRec), nRelSeg = rd16(nRec + 2);
        XADDR nTarget = nLoadLinear + ((XADDR)nRelSeg << 4) + nRelOff;
        quint16 nVal = m_pMemoryManager->readWord(nTarget);
        m_pMemoryManager->writeWord(nTarget, (quint16)(nVal + nLoadSeg));
    }

    _screenClear();  // blank the VGA text page (0xB8000 is inside the mapped region)

    XEmuFileFormat::MODULE mainModule;
    mainModule.sName = QStringLiteral("program.exe");
    mainModule.nBaseAddress = nLoadLinear;
    mainModule.nImageSize = (quint64)baLoad.size();
    pRegisters->reset();
    // DOS hands a program FLAGS with IOPL=3 / NT set (DOSBox: 0x7202 at the program's first
    // instruction, versus 0x0002 in the shell). Programs identify the CPU by pushf-ing and testing
    // exactly those bits -- EXEGUARD does `pushf / pop cx / or ch,01 / push cx / popf` -- so starting
    // at 0x0202 makes them see a different machine and take a different path.
    pRegisters->nRFLAGS = 0x7202;
    pRegisters->nCS = (quint16)(nLoadSeg + e_cs);
    pRegisters->nRIP = ((XADDR)pRegisters->nCS << 4) + e_ip;
    pRegisters->nSS = (quint16)(nLoadSeg + e_ss);
    m_pArch->setStackPointer(pRegisters, e_sp);
    pRegisters->nDS = nPspSeg;
    pRegisters->nES = nPspSeg;
    // DOS leaves several GP registers with load-derived values (not zero) at EXE entry.
    // Self-relocating/anti-tamper packers (e.g. EPACK) read SI before writing it, so a
    // zeroed SI corrupts their pointer math. Match the reference loader (DOSBox): SI = entry
    // IP, DI = initial SP, DX = PSP segment. (BP/CX leftovers aren't header-derivable; the
    // packers that matter overwrite them before use.)
    pRegisters->setGPR(XEmuRegisters::GPR_RSI, 2, e_ip);
    pRegisters->setGPR(XEmuRegisters::GPR_RDI, 2, e_sp);
    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, nPspSeg);
    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 0x00FF);  // COMMAND.COM EXEC leftovers (as at COM entry)
    pRegisters->setGPR(XEmuRegisters::GPR_RBP, 2, 0x091C);
    mainModule.nEntryPointAddress = pRegisters->nRIP;
    m_listModules.append(mainModule);

    emit infoMessage(tr("MS-DOS program loaded: CS=%1:%2 SS=%3:%4 (%5 bytes, %6 relocs)")
                         .arg(pRegisters->nCS, 4, 16, QChar('0'))
                         .arg(e_ip, 4, 16, QChar('0'))
                         .arg(pRegisters->nSS, 4, 16, QChar('0'))
                         .arg(e_sp, 4, 16, QChar('0'))
                         .arg(baLoad.size())
                         .arg(e_crlc));
    return true;
}
