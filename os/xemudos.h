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
#ifndef XEMUDOS_H
#define XEMUDOS_H

#include <QByteArray>

#include <QVector>

#include "xemuoperatingsystem.h"

class XEmuBiosInt;
class XEmuMsdosInt;

// MS-DOS personality for MZ / COM executables (16-bit x86 real mode). Maps the load
// module, builds a PSP and sets the real-mode segment registers (CS:IP, SS:SP,
// DS=ES=PSP). Real-mode execution is experimental: MZ segment relocations and full
// segment:offset translation for far pointers are not modelled.
//
// Software interrupts are dispatched by handleInterrupt() to the DOS (os/msdos_int) and
// BIOS (os/bios_int) service objects: INT 20h/21h terminate and DOS functions, INT 10h
// video, INT 16h keyboard. Program output is buffered here and surfaced through
// infoMessage() as "[stdout] ..." lines.
class XEmuDOS : public XEmuOperatingSystem {
    Q_OBJECT

public:
    explicit XEmuDOS(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent = nullptr);
    ~XEmuDOS() override;
    QString getOSName() const override;

    bool setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options) override;
    bool handleInterrupt(int nVector, XEmuRegisters *pRegisters) override;
    bool timerTick(XEmuRegisters *pRegisters) override;

    // VGA text mode. Character output (INT 21h/INT 10h) is rendered into the standard
    // colour-text video buffer at 0xB8000 (80x25, char + attribute per cell) so a display
    // widget can render exactly what a real screen would show. The cursor is exposed for
    // the same reason.
    static const XADDR N_VGA_TEXT_BASE = 0xB8000;
    static const int N_VGA_COLS = 80;
    static const int N_VGA_ROWS = 25;
    void getCursor(int *pnRow, int *pnCol) const
    {
        if (pnRow) {
            *pnRow = m_nCurRow;
        }
        if (pnCol) {
            *pnCol = m_nCurCol;
        }
    }

private:
    void _writePspStubs(XADDR nPspLinear);  // PSP:05h CP/M entry + PSP:50h "int 21h / retf"

    // INT 21h AH=4Bh EXEC: run a child program and come back. The parent's whole register state and
    // the block allocated for the child are stacked, so the child's AH=4Ch resumes the parent right
    // after its INT rather than ending the run. Self-extractors do this constantly -- EPACK writes
    // TEMP.EXE and EXECs it -- and without it they simply stop.
    struct PARENTCTX {
        XEmuRegisters regs;
        quint16 nPspSeg;    // the parent's PSP, to restore for AH=51h/62h
        quint16 nChildSeg;  // block to release when the child exits
    };
    QVector<PARENTCTX> m_parents;
    bool _execChild(const QString &sPath, XEmuRegisters *pRegisters);
    bool _returnToParent(XEmuRegisters *pRegisters, quint8 nExitCode);
    quint8 m_nLastChildExit = 0;  // reported by AH=4Dh
    void _populateLowMem();       // seed the IVT + BIOS data area with a DOSBox low-memory snapshot
    void _populatePspFcbs(quint64 nPspBase, const QString &sCmdLine);  // parse args into PSP default FCBs
    quint16 _setupEnvironment(quint64 nPspBase, const QString &sProgName);  // DOS env block -> PSP:2Ch
    bool _dispatchGuestInterrupt(int nVector, XEmuRegisters *pRegisters);  // INT -> guest handler in RAM
    void _putChar(char c);        // console byte: to the VGA buffer + the [stdout] line log
    quint16 m_nPspSeg = 0;        // loaded program's PSP segment (0 = not loaded yet)
    quint32 m_nBootIvt[256] = {};  // IVT as booted: a differing entry means the guest hooked that vector
    bool m_bInInt21Hook = false;  // a guest INT 21h hook is currently on the stack (recursion guard)
    void _flushOutput();          // emit the pending [stdout] line
    void _screenPutChar(char c);  // write one byte to the VGA text buffer, advancing the cursor
    void _screenClear();          // blank the VGA text page and home the cursor
    void _screenScroll();         // scroll the text page up one row

    XEmuBiosInt *m_pBiosInt;
    XEmuMsdosInt *m_pMsdosInt;
    QByteArray m_baLine;  // pending output not yet ended by a newline
    int m_nCurRow;
    int m_nCurCol;
};

#endif  // XEMUDOS_H
