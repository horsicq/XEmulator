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
#ifndef XEMUARM64_H
#define XEMUARM64_H

#include "xemuarch.h"
#include "xemuopcache.h"

// AArch64 (ARM64) core. Fixed 32-bit instructions are decoded into a normalized op
// (cached per guest address -- the "translate once" idea) and interpreted. Covers a
// practical subset: move-wide, add/sub (imm & reg), logical, ADR/ADRP, load/store
// (unsigned offset) and load/store pair, and the branch family.
class XEmuArm64 : public XEmuArch {
public:
    explicit XEmuArm64(XEmuMemoryManager *pMemoryManager);

    QString getArchName() const override;
    XEmuArchType getArchType() const override;
    quint8 getBits() const override;
    void setBits(quint8 nBits) override;

    STEP_INFO step(XEmuRegisters *pRegisters) override;
    qint64 run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo) override;
    int getBlockCacheCount() const override;
    void resetCache() override;

    void setStackPointer(XEmuRegisters *pRegisters, XADDR nAddress) override;
    XADDR getStackPointer(const XEmuRegisters *pRegisters) const override;
    void setThreadPointer(XEmuRegisters *pRegisters, XADDR nAddress) override;

    QString getRegistersText(const XEmuRegisters *pRegisters) const override;

    struct OP {
        enum Kind {
            A64_NOP,
            A64_MOVWIDE,
            A64_ADDSUB_IMM,
            A64_ADDSUB_REG,
            A64_LOGIC_REG,
            A64_ADR,
            A64_LDST_IMM,
            A64_LDST_PAIR,
            A64_B,
            A64_BL,
            A64_BCOND,
            A64_CBZ,
            A64_BR,
            A64_BLR,
            A64_RET,
            A64_HALT,
            A64_UNIMPL
        };

        Kind kind;
        int nRd;
        int nRn;
        int nRm;
        int nRt2;
        qint64 nImm;
        int nSize;       // load/store access width in bytes
        int nShift;
        int nShiftType;  // 0 LSL, 1 LSR, 2 ASR
        int nOpc;        // sub-operation selector
        bool bSetFlags;
        bool b64;
        int nCond;
        int nIndexMode;  // 0 offset, 1 post, 2 pre
        bool bLoad;
        bool bCbnz;
        XADDR nPc;
        XADDR nTarget;
        QString sText;

        OP()
            : kind(A64_UNIMPL), nRd(0), nRn(0), nRm(0), nRt2(0), nImm(0), nSize(8), nShift(0), nShiftType(0), nOpc(0), bSetFlags(false), b64(true), nCond(0),
              nIndexMode(0), bLoad(false), bCbnz(false), nPc(0), nTarget(0)
        {
        }

        bool isTerminator() const
        {
            return (kind == A64_B) || (kind == A64_BL) || (kind == A64_BCOND) || (kind == A64_CBZ) || (kind == A64_BR) || (kind == A64_BLR) ||
                   (kind == A64_RET) || (kind == A64_HALT) || (kind == A64_UNIMPL);
        }
    };

private:
    OP _decode(XADDR nPc, quint32 nWord);
    void _exec(const OP &op, XEmuRegisters *pRegisters, STEP_INFO &info);

    quint64 _readReg(XEmuRegisters *pRegisters, int nIndex, bool bUseSP) const;
    void _writeReg(XEmuRegisters *pRegisters, int nIndex, quint64 nValue, bool bUseSP, bool b64) const;
    quint64 _shift(quint64 nValue, int nType, int nAmount, bool b64) const;
    void _addWithCarry(quint64 a, quint64 b, quint64 nCarryIn, bool b64, quint64 &nResult, bool &bN, bool &bZ, bool &bC, bool &bV) const;
    bool _evalCond(XEmuRegisters *pRegisters, int nCond) const;

    static const quint64 N_FLAG = (Q_UINT64_C(1) << 31);
    static const quint64 Z_FLAG = (Q_UINT64_C(1) << 30);
    static const quint64 C_FLAG = (Q_UINT64_C(1) << 29);
    static const quint64 V_FLAG = (Q_UINT64_C(1) << 28);

    XEmuOpCache<OP> m_cache;
    // See XEmuArm::_noteWrite -- a CPU store must drop any decode cached for that address, or
    // self-modifying code re-executes the stale one. Only run() populates m_cache, so the step()
    // path pays nothing.
    void _noteWrite(XADDR nAddress, int nSize)
    {
        if (m_cache.count()) {
            m_cache.invalidate(nAddress, nAddress + (XADDR)nSize);
        }
    }
    bool m_bExecFault;
};

#endif  // XEMUARM64_H
