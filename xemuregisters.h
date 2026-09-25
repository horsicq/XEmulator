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
#ifndef XEMUREGISTERS_H
#define XEMUREGISTERS_H

#include <QtGlobal>

// The register file of an x86 / x86-64 thread. General-purpose registers are
// always stored as 64-bit values; 32-bit mode simply ignores the upper halves.
// The segment registers keep both the selector and the hidden base address the
// emulator actually uses (FS base == TEB on x86, GS base == TEB on x86-64).
class XEmuRegisters {
public:
    enum GPR {
        GPR_RAX = 0,
        GPR_RCX = 1,
        GPR_RDX = 2,
        GPR_RBX = 3,
        GPR_RSP = 4,
        GPR_RBP = 5,
        GPR_RSI = 6,
        GPR_RDI = 7,
        GPR_R8 = 8,
        GPR_R9 = 9,
        GPR_R10 = 10,
        GPR_R11 = 11,
        GPR_R12 = 12,
        GPR_R13 = 13,
        GPR_R14 = 14,
        GPR_R15 = 15
    };

    enum FLAG {
        FLAG_CF = (1u << 0),
        FLAG_PF = (1u << 2),
        FLAG_AF = (1u << 4),
        FLAG_ZF = (1u << 6),
        FLAG_SF = (1u << 7),
        FLAG_TF = (1u << 8),
        FLAG_IF = (1u << 9),
        FLAG_DF = (1u << 10),
        FLAG_OF = (1u << 11)
    };

    XEmuRegisters();

    void reset();

    quint64 getGPR(qint32 nIndex, qint32 nSize) const;         // nSize in bytes: 1, 2, 4 or 8
    void setGPR(qint32 nIndex, qint32 nSize, quint64 nValue);  // 4-byte writes zero-extend (x86-64 semantics)

    bool getFlag(FLAG flag) const;
    void setFlag(FLAG flag, bool bValue);

    static const char *getGPRName(qint32 nIndex, qint32 nSize);

    // General-purpose registers. x86/x86-64 use [0..15]; AArch32 uses [0..15]
    // (r13=SP, r14=LR, r15=PC via nRIP); AArch64 uses [0..30] for x0..x30 with the
    // stack pointer kept in nSP.
    quint64 nGPR[32];
    quint64 nSP;   // dedicated stack pointer (AArch64 SP; unused by x86)
    quint64 nRIP;  // program counter (RIP / EIP / PC)
    quint64 nRFLAGS;  // RFLAGS on x86, PSTATE/CPSR on ARM (NZCV in the top nibble)

    quint16 nCS;
    quint16 nDS;
    quint16 nES;
    quint16 nFS;
    quint16 nGS;
    quint16 nSS;

    quint64 nFSBase;
    quint64 nGSBase;
    quint64 nTPIDR;  // ARM thread pointer (TPIDR_EL0 / TPIDRURW) for TLS

    quint64 nCR0;
    quint64 nCR3;
    quint64 nCR4;

    quint64 nMMX[8];  // MMX registers MM0-MM7 (64-bit; aliased to the x87 mantissas on real HW)
    quint64 nXMM[16][2];  // XMM0-XMM15, low and high 64-bit lanes
};

#endif  // XEMUREGISTERS_H
