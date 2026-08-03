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
#include "xemuarm64.h"

XEmuArm64::XEmuArm64(XEmuMemoryManager *pMemoryManager) : XEmuArch(pMemoryManager), m_bExecFault(false)
{
}

QString XEmuArm64::getArchName() const
{
    return QStringLiteral("AArch64");
}

XEmuArchType XEmuArm64::getArchType() const
{
    return XARCH_ARM64;
}

quint8 XEmuArm64::getBits() const
{
    return 64;
}

void XEmuArm64::setBits(quint8 nBits)
{
    Q_UNUSED(nBits)
}

int XEmuArm64::getBlockCacheCount() const
{
    return m_cache.count();
}

void XEmuArm64::resetCache()
{
    m_cache.clear();
}

void XEmuArm64::setStackPointer(XEmuRegisters *pRegisters, XADDR nAddress)
{
    pRegisters->nSP = nAddress;
}

XADDR XEmuArm64::getStackPointer(const XEmuRegisters *pRegisters) const
{
    return pRegisters->nSP;
}

void XEmuArm64::setThreadPointer(XEmuRegisters *pRegisters, XADDR nAddress)
{
    pRegisters->nTPIDR = nAddress;
}

quint64 XEmuArm64::_readReg(XEmuRegisters *pRegisters, int nIndex, bool bUseSP) const
{
    if (nIndex == 31) {
        return bUseSP ? pRegisters->nSP : 0;  // SP or XZR
    }
    return pRegisters->nGPR[nIndex];
}

void XEmuArm64::_writeReg(XEmuRegisters *pRegisters, int nIndex, quint64 nValue, bool bUseSP, bool b64) const
{
    if (!b64) {
        nValue &= 0xFFFFFFFF;
    }
    if (nIndex == 31) {
        if (bUseSP) {
            pRegisters->nSP = nValue;
        }
        return;  // XZR write ignored
    }
    pRegisters->nGPR[nIndex] = nValue;
}

quint64 XEmuArm64::_shift(quint64 nValue, int nType, int nAmount, bool b64) const
{
    if (nAmount == 0) {
        return nValue;
    }
    quint64 nMask = b64 ? ~Q_UINT64_C(0) : 0xFFFFFFFF;
    nValue &= nMask;
    switch (nType) {
        case 0: return (nValue << nAmount) & nMask;   // LSL
        case 1: return (nValue >> nAmount);           // LSR
        case 2:                                       // ASR
            if (b64) {
                return (quint64)((qint64)nValue >> nAmount);
            }
            return (quint64)(((qint32)(quint32)nValue >> nAmount)) & 0xFFFFFFFF;
        default: return nValue;
    }
}

void XEmuArm64::_addWithCarry(quint64 a, quint64 b, quint64 nCarryIn, bool b64, quint64 &nResult, bool &bN, bool &bZ, bool &bC, bool &bV) const
{
    if (b64) {
        quint64 r1 = a + b;
        bool c1 = r1 < a;
        quint64 r2 = r1 + nCarryIn;
        bool c2 = r2 < r1;
        nResult = r2;
        bC = c1 || c2;
        bV = ((~(a ^ b)) & (a ^ r2) & (Q_UINT64_C(1) << 63)) != 0;
        bN = (r2 >> 63) & 1;
        bZ = (r2 == 0);
    } else {
        quint64 A = a & 0xFFFFFFFF;
        quint64 B = b & 0xFFFFFFFF;
        quint64 full = A + B + nCarryIn;
        quint64 r = full & 0xFFFFFFFF;
        nResult = r;
        bC = (full >> 32) & 1;
        bV = ((~(A ^ B)) & (A ^ r) & 0x80000000) != 0;
        bN = (r >> 31) & 1;
        bZ = (r == 0);
    }
}

bool XEmuArm64::_evalCond(XEmuRegisters *pRegisters, int nCond) const
{
    bool bN = (pRegisters->nRFLAGS & N_FLAG) != 0;
    bool bZ = (pRegisters->nRFLAGS & Z_FLAG) != 0;
    bool bC = (pRegisters->nRFLAGS & C_FLAG) != 0;
    bool bV = (pRegisters->nRFLAGS & V_FLAG) != 0;

    bool bResult = false;
    switch (nCond >> 1) {
        case 0: bResult = bZ; break;             // EQ / NE
        case 1: bResult = bC; break;             // CS / CC
        case 2: bResult = bN; break;             // MI / PL
        case 3: bResult = bV; break;             // VS / VC
        case 4: bResult = bC && !bZ; break;      // HI / LS
        case 5: bResult = (bN == bV); break;     // GE / LT
        case 6: bResult = (bN == bV) && !bZ; break;  // GT / LE
        case 7: bResult = true; break;           // AL
    }
    return (nCond & 1) && (nCond != 0x0F) ? !bResult : bResult;
}

XEmuArm64::OP XEmuArm64::_decode(XADDR nPc, quint32 nWord)
{
    OP op;
    op.nPc = nPc;
    op.b64 = ((nWord >> 31) & 1) != 0;

    int nRd = nWord & 0x1F;
    int nRn = (nWord >> 5) & 0x1F;
    int nRm = (nWord >> 16) & 0x1F;

    if (nWord == 0xD503201F) {
        op.kind = OP::A64_NOP;
        op.sText = QStringLiteral("nop");
        return op;
    }

    // Move wide immediate: sf opc 100101 hw imm16 Rd
    if (((nWord >> 23) & 0x3F) == 0x25) {
        op.kind = OP::A64_MOVWIDE;
        op.nOpc = (nWord >> 29) & 3;  // 0 MOVN, 2 MOVZ, 3 MOVK
        op.nShift = ((nWord >> 21) & 3) * 16;
        op.nImm = (nWord >> 5) & 0xFFFF;
        op.nRd = nRd;
        op.sText = (op.nOpc == 3) ? QStringLiteral("movk") : ((op.nOpc == 0) ? QStringLiteral("movn") : QStringLiteral("movz"));
        return op;
    }

    // Add/subtract immediate: sf op S 100010 sh imm12 Rn Rd
    if (((nWord >> 23) & 0x3F) == 0x22) {
        op.kind = OP::A64_ADDSUB_IMM;
        op.nOpc = (nWord >> 30) & 1;  // 0 add, 1 sub
        op.bSetFlags = ((nWord >> 29) & 1) != 0;
        int nSh = (nWord >> 22) & 1;
        op.nImm = (nWord >> 10) & 0xFFF;
        if (nSh) {
            op.nImm <<= 12;
        }
        op.nRn = nRn;
        op.nRd = nRd;
        op.sText = op.nOpc ? QStringLiteral("sub") : QStringLiteral("add");
        return op;
    }

    // ADR / ADRP: op immlo 10000 immhi Rd
    if (((nWord >> 24) & 0x1F) == 0x10) {
        op.kind = OP::A64_ADR;
        int nImmLo = (nWord >> 29) & 3;
        qint32 nImmHi = (nWord >> 5) & 0x7FFFF;
        qint64 nImm = ((qint64)nImmHi << 2) | nImmLo;
        if (nImm & (Q_INT64_C(1) << 20)) {
            nImm |= ~((Q_INT64_C(1) << 21) - 1);  // sign-extend 21-bit
        }
        op.nOpc = (nWord >> 31) & 1;  // 1 = ADRP
        op.nImm = nImm;
        op.nRd = nRd;
        op.sText = op.nOpc ? QStringLiteral("adrp") : QStringLiteral("adr");
        return op;
    }

    // Add/subtract shifted register: sf op S 01011 shift 0 Rm imm6 Rn Rd
    if ((((nWord >> 24) & 0x1F) == 0x0B) && (((nWord >> 21) & 1) == 0)) {
        op.kind = OP::A64_ADDSUB_REG;
        op.nOpc = (nWord >> 30) & 1;
        op.bSetFlags = ((nWord >> 29) & 1) != 0;
        op.nShiftType = (nWord >> 22) & 3;
        op.nShift = (nWord >> 10) & 0x3F;
        op.nRm = nRm;
        op.nRn = nRn;
        op.nRd = nRd;
        op.sText = op.nOpc ? QStringLiteral("sub") : QStringLiteral("add");
        return op;
    }

    // Logical shifted register: sf opc 01010 shift N Rm imm6 Rn Rd
    if (((nWord >> 24) & 0x1F) == 0x0A) {
        op.kind = OP::A64_LOGIC_REG;
        op.nOpc = (nWord >> 29) & 3;  // 0 AND, 1 ORR, 2 EOR, 3 ANDS
        op.nShiftType = (nWord >> 22) & 3;
        op.nShift = (nWord >> 10) & 0x3F;
        op.bSetFlags = (op.nOpc == 3);
        op.nRm = nRm;
        op.nRn = nRn;
        op.nRd = nRd;
        static const char *const pszNames[4] = {"and", "orr", "eor", "ands"};
        op.sText = QString::fromLatin1(pszNames[op.nOpc]);
        return op;
    }

    // Load/store pair: opc 101 0 mode L imm7 Rt2 Rn Rt
    if ((((nWord >> 27) & 0x7) == 0x5) && (((nWord >> 26) & 1) == 0)) {
        int nMode = (nWord >> 23) & 0x7;  // 001 post, 010 offset, 011 pre
        if ((nMode == 1) || (nMode == 2) || (nMode == 3)) {
            op.kind = OP::A64_LDST_PAIR;
            op.bLoad = ((nWord >> 22) & 1) != 0;
            int nOpc = (nWord >> 30) & 3;   // 0 32-bit, 2 64-bit
            op.b64 = (nOpc == 2);
            op.nSize = op.b64 ? 8 : 4;
            qint64 nImm7 = (nWord >> 15) & 0x7F;
            if (nImm7 & 0x40) {
                nImm7 |= ~Q_INT64_C(0x7F);
            }
            op.nImm = nImm7 * op.nSize;
            op.nIndexMode = (nMode == 1) ? 1 : ((nMode == 3) ? 2 : 0);
            op.nRt2 = (nWord >> 10) & 0x1F;
            op.nRn = nRn;
            op.nRd = nRd;  // Rt
            op.sText = op.bLoad ? QStringLiteral("ldp") : QStringLiteral("stp");
            return op;
        }
    }

    // Load/store unsigned immediate: size 111 0 01 opc imm12 Rn Rt
    if ((((nWord >> 27) & 0x7) == 0x7) && (((nWord >> 26) & 1) == 0) && (((nWord >> 24) & 0x3) == 0x1)) {
        int nSize = (nWord >> 30) & 3;
        int nOpc = (nWord >> 22) & 3;  // 0 STR, 1 LDR
        if ((nOpc == 0) || (nOpc == 1)) {
            op.kind = OP::A64_LDST_IMM;
            op.bLoad = (nOpc == 1);
            op.nSize = 1 << nSize;
            op.b64 = (nSize == 3);
            op.nImm = (qint64)((nWord >> 10) & 0xFFF) * op.nSize;
            op.nIndexMode = 0;
            op.nRn = nRn;
            op.nRd = nRd;  // Rt
            op.sText = op.bLoad ? QStringLiteral("ldr") : QStringLiteral("str");
            return op;
        }
    }

    // Unconditional branch (immediate): op 00101 imm26
    if (((nWord >> 26) & 0x3F) == 0x05 || ((nWord >> 26) & 0x3F) == 0x25) {
        bool bLink = ((nWord >> 31) & 1) != 0;
        qint64 nImm = nWord & 0x3FFFFFF;
        if (nImm & (Q_INT64_C(1) << 25)) {
            nImm |= ~((Q_INT64_C(1) << 26) - 1);
        }
        op.kind = bLink ? OP::A64_BL : OP::A64_B;
        op.nTarget = nPc + (nImm << 2);
        op.sText = bLink ? QStringLiteral("bl") : QStringLiteral("b");
        return op;
    }

    // Conditional branch (immediate): 0101010 0 imm19 0 cond
    if (((nWord >> 24) & 0xFF) == 0x54) {
        op.kind = OP::A64_BCOND;
        qint64 nImm = (nWord >> 5) & 0x7FFFF;
        if (nImm & (Q_INT64_C(1) << 18)) {
            nImm |= ~((Q_INT64_C(1) << 19) - 1);
        }
        op.nTarget = nPc + (nImm << 2);
        op.nCond = nWord & 0xF;
        op.sText = QStringLiteral("b.cond");
        return op;
    }

    // Compare and branch: sf 011010 op imm19 Rt
    if (((nWord >> 25) & 0x3F) == 0x1A) {
        op.kind = OP::A64_CBZ;
        op.bCbnz = ((nWord >> 24) & 1) != 0;
        qint64 nImm = (nWord >> 5) & 0x7FFFF;
        if (nImm & (Q_INT64_C(1) << 18)) {
            nImm |= ~((Q_INT64_C(1) << 19) - 1);
        }
        op.nTarget = nPc + (nImm << 2);
        op.nRd = nWord & 0x1F;  // Rt
        op.sText = op.bCbnz ? QStringLiteral("cbnz") : QStringLiteral("cbz");
        return op;
    }

    // Unconditional branch (register): 1101011 opc ... Rn
    if (((nWord >> 25) & 0x7F) == 0x6B) {
        int nOpc = (nWord >> 21) & 0xF;
        op.nRn = nRn;
        if (nOpc == 0) {
            op.kind = OP::A64_BR;
            op.sText = QStringLiteral("br");
        } else if (nOpc == 1) {
            op.kind = OP::A64_BLR;
            op.sText = QStringLiteral("blr");
        } else if (nOpc == 2) {
            op.kind = OP::A64_RET;
            op.sText = QStringLiteral("ret");
        } else {
            op.kind = OP::A64_UNIMPL;
            op.sText = QStringLiteral("br?");
        }
        return op;
    }

    // SVC / BRK -> halt
    if (((nWord >> 24) & 0xFF) == 0xD4) {
        op.kind = OP::A64_HALT;
        op.sText = QStringLiteral("svc/brk");
        return op;
    }

    op.kind = OP::A64_UNIMPL;
    op.sText = QString("dcd %1").arg(nWord, 8, 16, QChar('0'));
    return op;
}

void XEmuArm64::_exec(const OP &op, XEmuRegisters *pRegisters, STEP_INFO &info)
{
    m_bExecFault = false;
    m_pMemoryManager->fireCodeHook(op.nPc, 4);  // code hook: once per instruction

    info.result = STEP_OK;
    info.nAddress = op.nPc;
    info.nLength = 4;
    info.sText = op.sText;

    XADDR nNext = op.nPc + 4;
    bool bBranch = false;

    switch (op.kind) {
        case OP::A64_NOP:
            break;
        case OP::A64_MOVWIDE: {
            quint64 nImm = (quint64)op.nImm << op.nShift;
            if (op.nOpc == 0) {  // MOVN
                _writeReg(pRegisters, op.nRd, ~nImm, false, op.b64);
            } else if (op.nOpc == 2) {  // MOVZ
                _writeReg(pRegisters, op.nRd, nImm, false, op.b64);
            } else {  // MOVK
                quint64 nOld = _readReg(pRegisters, op.nRd, false);
                quint64 nMask = ~(Q_UINT64_C(0xFFFF) << op.nShift);
                _writeReg(pRegisters, op.nRd, (nOld & nMask) | nImm, false, op.b64);
            }
            break;
        }
        case OP::A64_ADDSUB_IMM: {
            quint64 a = _readReg(pRegisters, op.nRn, true);  // Rn may be SP
            quint64 b = (quint64)op.nImm;
            quint64 nResult;
            bool bN, bZ, bC, bV;
            if (op.nOpc == 0) {
                _addWithCarry(a, b, 0, op.b64, nResult, bN, bZ, bC, bV);
            } else {
                _addWithCarry(a, ~b, 1, op.b64, nResult, bN, bZ, bC, bV);
            }
            if (op.bSetFlags) {
                pRegisters->nRFLAGS = (bN ? N_FLAG : 0) | (bZ ? Z_FLAG : 0) | (bC ? C_FLAG : 0) | (bV ? V_FLAG : 0);
                _writeReg(pRegisters, op.nRd, nResult, false, op.b64);  // Rd=XZR for CMP
            } else {
                _writeReg(pRegisters, op.nRd, nResult, true, op.b64);  // Rd may be SP
            }
            break;
        }
        case OP::A64_ADDSUB_REG: {
            quint64 a = _readReg(pRegisters, op.nRn, false);
            quint64 b = _shift(_readReg(pRegisters, op.nRm, false), op.nShiftType, op.nShift, op.b64);
            quint64 nResult;
            bool bN, bZ, bC, bV;
            if (op.nOpc == 0) {
                _addWithCarry(a, b, 0, op.b64, nResult, bN, bZ, bC, bV);
            } else {
                _addWithCarry(a, ~b, 1, op.b64, nResult, bN, bZ, bC, bV);
            }
            if (op.bSetFlags) {
                pRegisters->nRFLAGS = (bN ? N_FLAG : 0) | (bZ ? Z_FLAG : 0) | (bC ? C_FLAG : 0) | (bV ? V_FLAG : 0);
            }
            _writeReg(pRegisters, op.nRd, nResult, false, op.b64);
            break;
        }
        case OP::A64_LOGIC_REG: {
            quint64 a = _readReg(pRegisters, op.nRn, false);
            quint64 b = _shift(_readReg(pRegisters, op.nRm, false), op.nShiftType, op.nShift, op.b64);
            quint64 nResult = 0;
            switch (op.nOpc) {
                case 0: nResult = a & b; break;
                case 1: nResult = a | b; break;
                case 2: nResult = a ^ b; break;
                case 3: nResult = a & b; break;
            }
            if (op.bSetFlags) {
                if (!op.b64) {
                    nResult &= 0xFFFFFFFF;
                }
                bool bN = op.b64 ? ((nResult >> 63) & 1) : ((nResult >> 31) & 1);
                pRegisters->nRFLAGS = (bN ? N_FLAG : 0) | (nResult == 0 ? Z_FLAG : 0);
            }
            _writeReg(pRegisters, op.nRd, nResult, false, op.b64);
            break;
        }
        case OP::A64_ADR: {
            quint64 nBase = op.nPc;
            qint64 nImm = op.nImm;
            if (op.nOpc == 1) {  // ADRP
                nBase &= ~Q_UINT64_C(0xFFF);
                nImm <<= 12;
            }
            _writeReg(pRegisters, op.nRd, nBase + nImm, false, true);
            break;
        }
        case OP::A64_LDST_IMM: {
            XADDR nAddress = _readReg(pRegisters, op.nRn, true) + op.nImm;
            bool bOk = false;
            if (op.bLoad) {
                quint64 nValue = 0;
                switch (op.nSize) {
                    case 1: nValue = m_pMemoryManager->readByte(nAddress, &bOk); break;
                    case 2: nValue = m_pMemoryManager->readWord(nAddress, &bOk); break;
                    case 4: nValue = m_pMemoryManager->readDword(nAddress, &bOk); break;
                    default: nValue = m_pMemoryManager->readQword(nAddress, &bOk); break;
                }
                _writeReg(pRegisters, op.nRd, nValue, false, op.b64);
            } else {
                quint64 nValue = _readReg(pRegisters, op.nRd, false);
                _noteWrite(nAddress, op.nSize ? op.nSize : 8);
                switch (op.nSize) {
                    case 1: bOk = m_pMemoryManager->writeByte(nAddress, (quint8)nValue); break;
                    case 2: bOk = m_pMemoryManager->writeWord(nAddress, (quint16)nValue); break;
                    case 4: bOk = m_pMemoryManager->writeDword(nAddress, (quint32)nValue); break;
                    default: bOk = m_pMemoryManager->writeQword(nAddress, nValue); break;
                }
            }
            if (!bOk) {
                m_bExecFault = true;
            }
            break;
        }
        case OP::A64_LDST_PAIR: {
            quint64 nBase = _readReg(pRegisters, op.nRn, true);
            XADDR nAddress = (op.nIndexMode == 1) ? nBase : (nBase + op.nImm);  // post uses base, else base+imm
            bool bOk1 = false;
            bool bOk2 = false;
            if (op.bLoad) {
                quint64 v1 = 0;
                quint64 v2 = 0;
                if (op.b64) {
                    v1 = m_pMemoryManager->readQword(nAddress, &bOk1);
                    v2 = m_pMemoryManager->readQword(nAddress + 8, &bOk2);
                } else {
                    v1 = m_pMemoryManager->readDword(nAddress, &bOk1);
                    v2 = m_pMemoryManager->readDword(nAddress + 4, &bOk2);
                }
                _writeReg(pRegisters, op.nRd, v1, false, op.b64);
                _writeReg(pRegisters, op.nRt2, v2, false, op.b64);
            } else {
                quint64 v1 = _readReg(pRegisters, op.nRd, false);
                quint64 v2 = _readReg(pRegisters, op.nRt2, false);
                _noteWrite(nAddress, op.b64 ? 16 : 8);  // the pair is contiguous
                if (op.b64) {
                    bOk1 = m_pMemoryManager->writeQword(nAddress, v1);
                    bOk2 = m_pMemoryManager->writeQword(nAddress + 8, v2);
                } else {
                    bOk1 = m_pMemoryManager->writeDword(nAddress, (quint32)v1);
                    bOk2 = m_pMemoryManager->writeDword(nAddress + 4, (quint32)v2);
                }
            }
            if (!bOk1 || !bOk2) {
                m_bExecFault = true;
            }
            if (op.nIndexMode != 0) {  // pre/post index write-back
                _writeReg(pRegisters, op.nRn, nBase + op.nImm, true, true);
            }
            break;
        }
        case OP::A64_B:
            pRegisters->nRIP = op.nTarget;
            bBranch = true;
            break;
        case OP::A64_BL:
            pRegisters->nGPR[30] = nNext;  // X30 = LR
            pRegisters->nRIP = op.nTarget;
            bBranch = true;
            break;
        case OP::A64_BCOND:
            pRegisters->nRIP = _evalCond(pRegisters, op.nCond) ? op.nTarget : nNext;
            bBranch = true;
            break;
        case OP::A64_CBZ: {
            quint64 v = _readReg(pRegisters, op.nRd, false);
            bool bTake = op.bCbnz ? (v != 0) : (v == 0);
            pRegisters->nRIP = bTake ? op.nTarget : nNext;
            bBranch = true;
            break;
        }
        case OP::A64_BR:
            pRegisters->nRIP = _readReg(pRegisters, op.nRn, false);
            bBranch = true;
            break;
        case OP::A64_BLR:
            pRegisters->nRIP = _readReg(pRegisters, op.nRn, false);
            pRegisters->nGPR[30] = nNext;
            bBranch = true;
            break;
        case OP::A64_RET:
            pRegisters->nRIP = pRegisters->nGPR[(op.nRn == 0) ? 30 : op.nRn];
            bBranch = true;
            break;
        case OP::A64_HALT:
            info.result = STEP_HALT;
            pRegisters->nRIP = nNext;
            return;
        case OP::A64_UNIMPL:
            info.result = STEP_UNIMPLEMENTED;
            info.sComment = QStringLiteral("instruction not implemented");
            return;
    }

    if (m_bExecFault) {
        info.result = STEP_FAULT;
        info.sComment = QStringLiteral("memory access violation");
        return;
    }

    if (!bBranch) {
        pRegisters->nRIP = nNext;
    }
}

XEmuArch::STEP_INFO XEmuArm64::step(XEmuRegisters *pRegisters)
{
    STEP_INFO info;

    bool bOk = false;
    quint32 nWord = m_pMemoryManager->fetchDword(pRegisters->nRIP, &bOk);
    if (!bOk) {
        info.result = STEP_FAULT;
        info.nAddress = pRegisters->nRIP;
        info.sComment = QStringLiteral("cannot fetch instruction");
        return info;
    }

    OP op = _decode(pRegisters->nRIP, nWord);
    _exec(op, pRegisters, info);
    return info;
}

qint64 XEmuArm64::run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo)
{
    qint64 nCount = 0;
    STEP_INFO lastInfo;

    while ((nMaxInsns <= 0) || (nCount < nMaxInsns)) {
        XADDR nPc = pRegisters->nRIP;

        const OP *pOp = m_cache.find(nPc);
        if (!pOp) {
            bool bOk = false;
            quint32 nWord = m_pMemoryManager->fetchDword(nPc, &bOk);
            if (!bOk) {
                lastInfo.result = STEP_FAULT;
                lastInfo.nAddress = nPc;
                lastInfo.sComment = QStringLiteral("cannot fetch instruction");
                nCount++;
                break;
            }
            pOp = m_cache.insert(nPc, _decode(nPc, nWord));
        }

        STEP_INFO info;
        _exec(*pOp, pRegisters, info);
        nCount++;
        lastInfo = info;

        if (info.result != STEP_OK) {
            break;
        }
    }

    if (pStopInfo) {
        *pStopInfo = lastInfo;
    }
    return nCount;
}

QString XEmuArm64::getRegistersText(const XEmuRegisters *pRegisters) const
{
    QString sResult;
    for (int i = 0; i < 31; i++) {
        sResult += QString("x%1 = %2\n").arg(i, -2).arg(pRegisters->nGPR[i], 16, 16, QChar('0'));
    }
    sResult += QString("sp = %1\n").arg(pRegisters->nSP, 16, 16, QChar('0'));
    sResult += QString("pc = %1\n").arg(pRegisters->nRIP, 16, 16, QChar('0'));
    sResult += QString("nzcv = %1%2%3%4\n")
                   .arg((pRegisters->nRFLAGS & N_FLAG) ? 'N' : '-')
                   .arg((pRegisters->nRFLAGS & Z_FLAG) ? 'Z' : '-')
                   .arg((pRegisters->nRFLAGS & C_FLAG) ? 'C' : '-')
                   .arg((pRegisters->nRFLAGS & V_FLAG) ? 'V' : '-');
    sResult += QString("tpidr = %1\n").arg(pRegisters->nTPIDR, 16, 16, QChar('0'));
    return sResult;
}
