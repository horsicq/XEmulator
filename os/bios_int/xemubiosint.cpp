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
#include "xemubiosint.h"

#include <QTime>

#include "xemumemorymanager.h"
#include "xemuregisters.h"

namespace {
quint8 ah(XEmuRegisters *pRegisters)
{
    return (quint8)((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2) >> 8) & 0xFF);
}
quint8 al(XEmuRegisters *pRegisters)
{
    return (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1) & 0xFF);
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
}  // namespace

XEmuBiosInt::XEmuBiosInt(XEmuMemoryManager *pMemoryManager) : m_pMemoryManager(pMemoryManager)
{
}

bool XEmuBiosInt::handle(int nVector, XEmuRegisters *pRegisters)
{
    switch (nVector) {
        case 0x10: _video(pRegisters); return true;
        case 0x11:  // equipment list -> AX (1 floppy, 80x25 colour, no coprocessor)
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x0021);
            return true;
        case 0x12:  // conventional memory size in KB -> AX
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 640);
            return true;
        case 0x16: _keyboard(pRegisters); return true;
        case 0x1A: _timer(pRegisters); return true;
        default: return false;
    }
}

void XEmuBiosInt::_video(XEmuRegisters *pRegisters)
{
    switch (ah(pRegisters)) {
        case 0x0E:  // teletype output (AL)
        case 0x0A:  // write character at cursor
        case 0x09:  // write character + attribute
            _out((char)al(pRegisters));
            break;
        case 0x0F: {  // get video mode -> AL = mode, AH = columns, BH = active display page
            setAL(pRegisters, 0x03);  // 80x25 colour text
            setAH(pRegisters, 0x50);  // 80 columns
            // BH must be written too: callers pass the returned page straight back into other INT 10h
            // calls (TINYPROG does `int 10h AH=0Fh` then `mov bl,..` and calls AH=12h with BX), so
            // leaving BH holding whatever the caller had corrupts that parameter. Page 0 is active.
            quint16 nBX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2);
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, (quint16)(nBX & 0x00FF));
            break;
        }
        case 0x03:  // get cursor position/size
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 0x0607);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, 0x0000);
            break;

        case 0x12: {  // EGA/VGA alternate select
            quint8 nBL = (quint8)(pRegisters->getGPR(XEmuRegisters::GPR_RBX, 2) & 0xFF);
            if (nBL == 0x10) {
                // Get EGA/VGA configuration information. Report the same machine DOSBox does, since
                // callers branch on it: BH = 0 (colour display), BL = 3 (256 KB video memory),
                // CH = 0 (feature bits), CL = 9 (switch settings). TINYPROG computes AL = BL + F0h
                // and treats a zero result as "no EGA/VGA", so a stale BL sends it down a dead path.
                pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, 0x0003);
                pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, 0x0009);
            }
            break;  // other subfunctions (screen refresh, palette loading, ...): benign no-op
        }
        default:
            break;  // set-mode / cursor move / scroll / palette: no-op
    }
}

void XEmuBiosInt::_keyboard(XEmuRegisters *pRegisters)
{
    // The BIOS keyboard buffer lives in the BIOS data area at segment 0040: a 16-word ring at
    // 0040:001E..003D with head at 0040:001A and tail at 0040:001C (empty when head==tail).
    // Anti-tamper packers (e.g. $PIRIT) stuff computed words into the ring then read them back
    // via INT 16h, so we MUST go through the real buffer rather than fake a fixed key.
    const XADDR kBda = 0x400;  // segment 0040 << 4
    switch (ah(pRegisters)) {
        case 0x00:  // read key (blocking)
        case 0x10: {
            quint16 nHead = m_pMemoryManager->readWord(kBda + 0x1A);
            quint16 nTail = m_pMemoryManager->readWord(kBda + 0x1C);
            if (nHead == nTail || nHead < 0x1E || nHead >= 0x3E) {
                // Empty (or uninitialised): the real BIOS blocks. Return Enter so plain
                // "press any key" prompts proceed; buffer-stuffing code never reaches here.
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0x1C0D);
            } else {
                quint16 nKey = m_pMemoryManager->readWord(kBda + nHead);
                nHead += 2;
                if (nHead >= 0x3E) {
                    nHead = 0x1E;  // wrap the ring
                }
                m_pMemoryManager->writeWord(kBda + 0x1A, nHead);
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nKey);
            }
            break;
        }
        case 0x01:  // check for keystroke (peek, don't consume)
        case 0x11: {
            quint16 nHead = m_pMemoryManager->readWord(kBda + 0x1A);
            quint16 nTail = m_pMemoryManager->readWord(kBda + 0x1C);
            if (nHead == nTail) {
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, true);  // no key waiting
            } else {
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, false);
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, m_pMemoryManager->readWord(kBda + nHead));
            }
            break;
        }
        case 0x02:  // shift-key status
            setAL(pRegisters, 0x00);
            break;
        case 0x05:  // store keystroke in buffer (CX) -> append to the ring
            setAL(pRegisters, 0x00);  // success (buffer not full)
            pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
            break;
        default:
            break;
    }
}

void XEmuBiosInt::_timer(XEmuRegisters *pRegisters)
{
    switch (ah(pRegisters)) {
        case 0x00: {  // read system clock tick counter -> CX:DX = ticks since midnight, AL = midnight flag
            quint64 nMs = (quint64)QTime::currentTime().msecsSinceStartOfDay();
            quint32 nTicks = (quint32)(nMs * 0x1800B0ULL / 86400000ULL);  // 0x1800B0 ticks per day (~18.2/s)
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, (nTicks >> 16) & 0xFFFF);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, nTicks & 0xFFFF);
            setAL(pRegisters, 0x00);  // no midnight rollover since last read
            break;
        }
        case 0x02: {  // read real-time clock -> CH=hour CL=min DH=sec (BCD), CF=0
            QTime t = QTime::currentTime();
            auto bcd = [](int v) { return (quint8)(((v / 10) << 4) | (v % 10)); };
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, ((quint16)bcd(t.hour()) << 8) | bcd(t.minute()));
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, (quint16)bcd(t.second()) << 8);
            pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
            break;
        }
        default:
            break;  // set-time / RTC-alarm etc.: no-op
    }
}
