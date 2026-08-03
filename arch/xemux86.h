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
#ifndef XEMUX86_H
#define XEMUX86_H

#include "xemuarch.h"
#include <QSet>

#include "xemutb.h"

// x86 / x86-64 dynamic-translation core.
//
// The engine follows QEMU's model: a *translator* decodes guest instructions into
// architecture-neutral micro-ops (XEmuMicroOp), a straight-line run of them forms a
// Translation Block (XEmuTB) that is cached by guest address, and an *interpreter*
// backend executes the cached micro-ops. Guest code is decoded once and re-executed
// from the cache -- no dependency on Unicorn or any external CPU library.
class XEmuX86 : public XEmuArch {
public:
    explicit XEmuX86(XEmuMemoryManager *pMemoryManager, quint8 nBits = 64);

    QString getArchName() const override;
    XEmuArchType getArchType() const override;
    quint8 getBits() const override;
    void setBits(quint8 nBits) override;

    STEP_INFO step(XEmuRegisters *pRegisters) override;
    XADDR getFaultAddress() const override { return m_nFaultAddr; }
    qint64 run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo) override;
    int getBlockCacheCount() const override;
    void resetCache() override;

    QString getRegistersText(const XEmuRegisters *pRegisters) const override;

    // Diagnostic: read the x87 FPU register stack. ST(i) as the modelled double, and its
    // int64 round-trip (what fistp would store) so a caller can spot precision loss on
    // 64-bit-integer accumulators (double mantissa is 52 bits; real x87 has 64).
    double diagFpuST(int i) const { return _fpuGet(i); }
    qint64 diagFpuSTasInt(int i) const { return (qint64)_fpuGet(i); }
    bool diagFpuEmpty(int i) const { return _fpuEmpty(i); }
    int diagFpuTop() const { return m_fpuTop; }
    quint16 diagFpuControl() const { return m_fpuControl; }

private:
    static const int N_MAX_BLOCK_INSNS = 256;

    // Decoder state for one instruction.
    struct DEC {
        XADDR nStart;
        XADDR nFetch;
        bool bRexW;
        bool bRexR;
        bool bRexX;
        bool bRexB;
        bool bHasRex;
        bool bOpSize16;
        int nSegSource;  // 0 none, 1 FS, 2 GS
        int nOpSize;
        int nAddrSize;
        int nRep;  // 0 none, 1 rep/repe (F3), 2 repne (F2)
        bool bFault;

        DEC() : nStart(0), nFetch(0), bRexW(false), bRexR(false), bRexX(false), bRexB(false), bHasRex(false), bOpSize16(false), nSegSource(0), nOpSize(4),
                nAddrSize(8), nRep(0), bFault(false)
        {
        }
    };

    // --- Translator (guest bytes -> micro-ops) ---------------------------------
    quint8 _fetch8(DEC &dec);
    quint16 _fetch16(DEC &dec);
    quint32 _fetch32(DEC &dec);
    quint64 _fetch64(DEC &dec);
    void _decodeModRM(DEC &dec, int &nRegField, XEmuOperand &rm);
    bool _decodeInsn(XADDR nAddress, XEmuMicroOp &op);  // false on code-fetch fault
    void _decodeTwoByte(DEC &dec, XEmuMicroOp &op);
    void _decodeFpu(DEC &dec, XEmuMicroOp &op, quint8 nOpcode);  // x87 ESC opcodes 0xD8..0xDF
    bool _decodeMMX(DEC &dec, XEmuMicroOp &op, quint8 nOpcode);  // MMX 0F opcodes; returns true if handled
    XEmuTB *_translateBlock(XADDR nAddress);
    int _stackSize(const DEC &dec) const;

    // --- x87 FPU (modelled with double precision; 80-bit extended is approximated) ---
    void _fpuInit();                          // FINIT/FNINIT
    void _execFpu(const XEmuMicroOp &op);     // run a decoded MOP_FPU
    double _fpuGet(int i) const;              // read ST(i)
    void _fpuSet(int i, double v);            // write ST(i)
    void _fpuPush(double v);                  // decrement TOP, ST(0) = v
    void _fpuPushInt(qint64 v);               // FILD: decrement TOP, ST(0) = exact integer v
    void _fpuPop();                           // mark ST(0) empty, increment TOP
    bool _fpuEmpty(int i) const;              // is ST(i) tagged empty?
    void _fpuCompare(double a, double b, bool bUnordered);  // set C3/C2/C0 from a?b
    quint16 _fpuStatusWord() const;           // status word with TOP + condition codes inserted

    // --- Interpreter backend (micro-ops -> effects) ----------------------------
    void _execOp(const XEmuMicroOp &op, XEmuRegisters *pRegisters, STEP_INFO &info);
    XADDR _resolveAddr(const XEmuMicroOp &op, const XEmuOperand &opnd, bool bOffsetOnly = false);
    quint64 _readOpnd(const XEmuMicroOp &op, const XEmuOperand &opnd, int nSize);
    void _writeOpnd(const XEmuMicroOp &op, const XEmuOperand &opnd, int nSize, quint64 nValue);

    // MMX helpers: read/write a 64-bit MMX operand (register or m64), a packed binary op,
    // and a packed shift.
    quint64 _readMMX(const XEmuMicroOp &op, const XEmuOperand &opnd);
    void _writeMMX(const XEmuMicroOp &op, const XEmuOperand &opnd, quint64 nValue);
    quint64 _mmxALU(int nOp, quint64 a, quint64 b);
    quint64 _mmxShift(int nOp, quint64 a, quint64 nCount);
    void _push(quint64 nValue, int nSize);
    quint64 _pop(int nSize);
    // Real-mode address wrap (the A20 line). With A20 disabled -- the state DOS runs in unless a
    // driver like HIMEM enables it, and what DOSBox emulates -- address line 20 is forced low, so
    // seg:off arithmetic that overflows 1 MiB aliases back to low memory. Packers exploit this to
    // reach memory *below* their segment by subtracting from the segment (e.g. AVPack copies with
    // DS=F5BA/SI=FFFE, i.e. linear 0x105B9E -> 0x005B9E). Without the wrap those accesses land in
    // the >1 MiB region and the program silently reads/writes the wrong memory.
    XADDR _wrapA20(XADDR nAddress) const { return (m_nBits == 16) ? (nAddress & 0xFFFFF) : nAddress; }
    quint64 _memReadSized(XADDR nAddress, int nSize);              // sets m_bExecFault on fault
    void _memWriteSized(XADDR nAddress, quint64 nValue, int nSize);  // sets m_bExecFault on fault
    quint64 _aluCompute(int nAluOp, quint64 a, quint64 b, int nSize, bool &bWriteBack);
    quint64 _doShift(int nShiftOp, quint64 nValue, int nSize, quint8 nCount);  // sets flags

    void _setFlagsAdd(quint64 a, quint64 b, quint64 res, int nSize);
    void _setFlagsSub(quint64 a, quint64 b, quint64 res, int nSize);
    void _setFlagsAdc(quint64 a, quint64 b, quint64 carry, quint64 res, int nSize);
    void _setFlagsSbb(quint64 a, quint64 b, quint64 borrow, quint64 res, int nSize);
    void _setFlagsLogic(quint64 res, int nSize);
    void _setFlagsIncDec(quint64 a, quint64 res, int nSize, bool bInc);
    bool _evalCond(quint8 nCond);

    static bool _parity(quint8 nValue);
    static quint64 _mask(int nSize);
    static quint64 _signBit(int nSize);
    static qint64 _signExtend(quint64 nValue, int nSize);

    quint8 m_nBits;
    quint64 m_nTsc;
    quint8 m_ioPorts[0x400];  // stateful low-ISA I/O ports (PIC/PIT/keyboard) so anti-debug
                              // "read mask / modify / write it back" games stay self-consistent
    quint64 m_nInsnCount;      // instructions executed -- a physical time base for the video retrace
                              // timing (port 0x3DA), so its bits cycle at a realistic per-frame rate

    // Self-modifying code (16-bit real mode): a coarse map of which 64-byte spans of the real-mode
    // address space have been translated, so an ordinary write pays only two bit tests instead of a
    // full cache scan. Needed once code is modified at instruction granularity -- e.g. a protector
    // that decrypts the next instruction from its own INT 1 (single-step) handler.
    enum { N_SMC_LIMIT = 0x120000, N_SMC_GRAN = 64 };
    quint8 m_smcMap[N_SMC_LIMIT / N_SMC_GRAN / 8];

    // Which 4 KiB pages currently hold translated code. The 64-byte m_smcMap above only covers the
    // real-mode 1 MiB, so it cannot filter writes in 32/64-bit mode; this set covers the whole
    // address space and keeps a store on a non-code page down to a single hash lookup with no
    // allocation. Without it, invalidating on every store means walking the entire block hash and
    // heap-allocating a list per write, which would cost far more than the cache saves.
    QSet<quint64> m_codePages;
    enum { N_CODE_PAGE_SHIFT = 12 };
    void _noteWrite(XADDR nAddress, int nSize);   // guest memory changed: drop stale translations
    bool m_bPitHiByte;         // PIT lo/hi read toggle (ports 0x40-0x42)
    bool m_bTrapTaken;         // a single-step trap fired: run() must leave the current block
    // Loading SS (MOV SS,r/m -- POP SS -- LSS) inhibits the single-step trap and maskable interrupts
    // for exactly ONE following instruction, so that the SS:SP pair can be updated without an
    // interrupt seeing a half-changed stack. Not an obscure corner: ALEC 1.6 counts its own INT 1
    // traps over a block containing two `pop ss` and refuses to run unless the count is exactly 8.
    bool m_bSsBlock;

    // Debug registers DR0..DR7. Anti-debug stubs do not merely READ these looking for hardware
    // breakpoints -- they WRITE a value and read it back to see whether the CPU applies the
    // architectural reserved-bit masks. Returning a constant 0 makes two different written values
    // read back identical, which is exactly the "no real CPU here" answer such a check looks for:
    // ALEC 1.6 writes 0x0000000A then 0x0000FFFF to DR6, compares the read-backs, and refuses to run.
    quint32 m_dr[8];
    void _smcMark(XADDR nFrom, XADDR nTo);        // record that [nFrom,nTo) holds translated code
    bool _smcHit(XADDR nFrom, XADDR nTo) const;   // does [nFrom,nTo) overlap any translated code?
    XEmuTBCache m_tbCache;

    // x87 FPU register stack. m_fpuReg holds the eight physical registers; ST(i) is
    // m_fpuReg[(m_fpuTop + i) & 7]. m_fpuStatusCC caches condition codes C3 C2 C1 C0.
    double m_fpuReg[8];
    // Exact-integer shadow: when a register was loaded via FILD and not overwritten by a
    // non-integer op, m_fpuIsInt[phys] is true and m_fpuInt[phys] is the exact value, so a
    // FIST/FISTP round-trips a 64-bit integer losslessly. The host double has only a 52-bit
    // mantissa (real x87 has 64), so without this a >2^53 integer checksum is silently
    // corrupted -- a known packer anti-emulation probe (PeX 0.99).
    qint64 m_fpuInt[8];
    bool m_fpuIsInt[8];
    quint8 m_fpuTag[8];      // per physical register: 0 valid, 1 zero, 2 special, 3 empty
    int m_fpuTop;
    quint16 m_fpuControl;    // control word (rounding/precision/exception masks)
    quint16 m_fpuStatusCC;   // condition codes only (C3<<14 | C2<<10 | C1<<9 | C0<<8)
    bool m_bFpuInit;         // one-time reset guard

    // Transient execution state (valid only inside _execOp and its helpers).
    XEmuRegisters *m_pExecRegs;
    bool m_bExecFault;
    XADDR m_nFaultAddr;  // linear address of the access that raised m_bExecFault
};

#endif  // XEMUX86_H
