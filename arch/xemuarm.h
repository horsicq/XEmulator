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
#ifndef XEMUARM_H
#define XEMUARM_H

#include "xemuarch.h"
#include "xemuopcache.h"

// AArch32 (ARM) core. Decodes fixed 32-bit ARM-mode instructions into a normalized
// op (cached per address) and interprets a practical subset: data processing
// (immediate & register), single load/store, branch/branch-with-link and BX.
class XEmuArm : public XEmuArch {
public:
    explicit XEmuArm(XEmuMemoryManager *pMemoryManager);

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
        enum Kind { ARM_DP, ARM_LDST, ARM_B, ARM_BX, ARM_HALT, ARM_UNIMPL };
        Kind kind;
        int nCond;
        int nOpcode;   // data-processing opcode
        int nRd;
        int nRn;
        int nRm;
        quint32 nImm;
        bool bImmOperand;
        bool bSetFlags;
        int nShiftType;
        int nShiftAmount;
        // load/store
        bool bLoad;
        bool bByte;
        bool bPre;
        bool bUp;
        bool bWriteBack;
        bool bLink;
        XADDR nPc;
        XADDR nTarget;
        QString sText;

        OP()
            : kind(ARM_UNIMPL), nCond(14), nOpcode(0), nRd(0), nRn(0), nRm(0), nImm(0), bImmOperand(false), bSetFlags(false), nShiftType(0), nShiftAmount(0),
              bLoad(false), bByte(false), bPre(true), bUp(true), bWriteBack(false), bLink(false), nPc(0), nTarget(0)
        {
        }

        bool isTerminator() const
        {
            return (kind == ARM_B) || (kind == ARM_BX) || (kind == ARM_HALT) || (kind == ARM_UNIMPL);
        }
    };

private:
    OP _decode(XADDR nPc, quint32 nWord);
    void _exec(const OP &op, XEmuRegisters *pRegisters, STEP_INFO &info);
    bool _evalCond(XEmuRegisters *pRegisters, int nCond) const;

    static const quint64 N_FLAG = (Q_UINT64_C(1) << 31);
    static const quint64 Z_FLAG = (Q_UINT64_C(1) << 30);
    static const quint64 C_FLAG = (Q_UINT64_C(1) << 29);
    static const quint64 V_FLAG = (Q_UINT64_C(1) << 28);

    XEmuOpCache<OP> m_cache;
    // Guest memory written by the CPU must drop any decoded instruction cached for that address, or
    // self-modifying code re-executes the pre-modification decode. m_cache is only populated by
    // run(); step() decodes fresh each time, so this costs nothing on the step path.
    void _noteWrite(XADDR nAddress, int nSize)
    {
        if (m_cache.count()) {
            m_cache.invalidate(nAddress, nAddress + (XADDR)nSize);
        }
    }
    bool m_bExecFault;
};

#endif  // XEMUARM_H
