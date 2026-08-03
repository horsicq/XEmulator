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
#include "xemuarm.h"

XEmuArm::XEmuArm(XEmuMemoryManager *pMemoryManager) : XEmuArch(pMemoryManager), m_bExecFault(false)
{
}

QString XEmuArm::getArchName() const
{
    return QStringLiteral("ARM");
}

XEmuArchType XEmuArm::getArchType() const
{
    return XARCH_ARM;
}

quint8 XEmuArm::getBits() const
{
    return 32;
}

void XEmuArm::setBits(quint8 nBits)
{
    Q_UNUSED(nBits)
}

int XEmuArm::getBlockCacheCount() const
{
    return m_cache.count();
}

void XEmuArm::resetCache()
{
    m_cache.clear();
}

void XEmuArm::setStackPointer(XEmuRegisters *pRegisters, XADDR nAddress)
{
    pRegisters->nGPR[13] = nAddress;  // R13 = SP
}

XADDR XEmuArm::getStackPointer(const XEmuRegisters *pRegisters) const
{
    return pRegisters->nGPR[13];
}

void XEmuArm::setThreadPointer(XEmuRegisters *pRegisters, XADDR nAddress)
{
    pRegisters->nTPIDR = nAddress;
}

bool XEmuArm::_evalCond(XEmuRegisters *pRegisters, int nCond) const
{
    bool bN = (pRegisters->nRFLAGS & N_FLAG) != 0;
    bool bZ = (pRegisters->nRFLAGS & Z_FLAG) != 0;
    bool bC = (pRegisters->nRFLAGS & C_FLAG) != 0;
    bool bV = (pRegisters->nRFLAGS & V_FLAG) != 0;

    switch (nCond) {
        case 0x0: return bZ;
        case 0x1: return !bZ;
        case 0x2: return bC;
        case 0x3: return !bC;
        case 0x4: return bN;
        case 0x5: return !bN;
        case 0x6: return bV;
        case 0x7: return !bV;
        case 0x8: return bC && !bZ;
        case 0x9: return !bC || bZ;
        case 0xA: return bN == bV;
        case 0xB: return bN != bV;
        case 0xC: return !bZ && (bN == bV);
        case 0xD: return bZ || (bN != bV);
        default: return true;  // AL / NV
    }
}

XEmuArm::OP XEmuArm::_decode(XADDR nPc, quint32 nWord)
{
    OP op;
    op.nPc = nPc;
    op.nCond = (nWord >> 28) & 0xF;

    // BX Rn
    if ((nWord & 0x0FFFFFF0) == 0x012FFF10) {
        op.kind = OP::ARM_BX;
        op.nRm = nWord & 0xF;
        op.sText = QStringLiteral("bx");
        return op;
    }

    int nGroup = (nWord >> 26) & 0x3;

    if (nGroup == 0) {
        // Data processing.
        op.kind = OP::ARM_DP;
        op.bImmOperand = ((nWord >> 25) & 1) != 0;
        op.nOpcode = (nWord >> 21) & 0xF;
        op.bSetFlags = ((nWord >> 20) & 1) != 0;
        op.nRn = (nWord >> 16) & 0xF;
        op.nRd = (nWord >> 12) & 0xF;
        if (op.bImmOperand) {
            quint32 nImm8 = nWord & 0xFF;
            int nRot = ((nWord >> 8) & 0xF) * 2;
            op.nImm = (nImm8 >> nRot) | (nImm8 << (32 - nRot));
            if (nRot == 0) {
                op.nImm = nImm8;
            }
        } else {
            op.nRm = nWord & 0xF;
            op.nShiftType = (nWord >> 5) & 3;
            op.nShiftAmount = (nWord >> 7) & 0x1F;  // immediate shift only
        }
        static const char *const pszNames[16] = {"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
                                                 "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"};
        op.sText = QString::fromLatin1(pszNames[op.nOpcode]);
        return op;
    }

    if (nGroup == 1) {
        // Single data transfer (LDR/STR).
        op.kind = OP::ARM_LDST;
        op.bPre = ((nWord >> 24) & 1) != 0;
        op.bUp = ((nWord >> 23) & 1) != 0;
        op.bByte = ((nWord >> 22) & 1) != 0;
        op.bWriteBack = ((nWord >> 21) & 1) != 0;
        op.bLoad = ((nWord >> 20) & 1) != 0;
        op.nRn = (nWord >> 16) & 0xF;
        op.nRd = (nWord >> 12) & 0xF;
        op.bImmOperand = ((nWord >> 25) & 1) == 0;  // I bit inverted for LDST
        if (op.bImmOperand) {
            op.nImm = nWord & 0xFFF;
        } else {
            op.nRm = nWord & 0xF;
            op.nShiftType = (nWord >> 5) & 3;
            op.nShiftAmount = (nWord >> 7) & 0x1F;
        }
        op.sText = op.bLoad ? QStringLiteral("ldr") : QStringLiteral("str");
        return op;
    }

    if (nGroup == 2) {
        // Branch / branch with link.
        if (((nWord >> 25) & 0x7) == 0x5) {
            op.kind = OP::ARM_B;
            op.bLink = ((nWord >> 24) & 1) != 0;
            qint32 nImm = nWord & 0xFFFFFF;
            if (nImm & 0x800000) {
                nImm |= ~0xFFFFFF;
            }
            op.nTarget = nPc + 8 + ((qint64)nImm << 2);
            op.sText = op.bLink ? QStringLiteral("bl") : QStringLiteral("b");
            return op;
        }
    }

    // SVC / SWI
    if (((nWord >> 24) & 0xF) == 0xF) {
        op.kind = OP::ARM_HALT;
        op.sText = QStringLiteral("svc");
        return op;
    }

    op.kind = OP::ARM_UNIMPL;
    op.sText = QString("dcd %1").arg(nWord, 8, 16, QChar('0'));
    return op;
}

void XEmuArm::_exec(const OP &op, XEmuRegisters *pRegisters, STEP_INFO &info)
{
    m_bExecFault = false;
    m_pMemoryManager->fireCodeHook(op.nPc, 4);  // code hook: once per instruction

    info.result = STEP_OK;
    info.nAddress = op.nPc;
    info.nLength = 4;
    info.sText = op.sText;

    XADDR nNext = op.nPc + 4;
    bool bBranch = false;

    if (!_evalCond(pRegisters, op.nCond)) {
        pRegisters->nRIP = nNext;  // condition failed -> skip
        return;
    }

    switch (op.kind) {
        case OP::ARM_DP: {
            quint32 a = (quint32)pRegisters->nGPR[op.nRn];
            quint32 b;
            if (op.bImmOperand) {
                b = op.nImm;
            } else {
                b = (quint32)pRegisters->nGPR[op.nRm];
                switch (op.nShiftType) {
                    case 0: b <<= op.nShiftAmount; break;
                    case 1: b = (op.nShiftAmount ? (b >> op.nShiftAmount) : 0); break;
                    case 2: b = (quint32)((qint32)b >> (op.nShiftAmount ? op.nShiftAmount : 31)); break;
                    case 3: b = (b >> op.nShiftAmount) | (b << (32 - op.nShiftAmount)); break;
                }
            }

            quint32 nResult = 0;
            bool bWrite = true;
            switch (op.nOpcode) {
                case 0x0: nResult = a & b; break;                       // AND
                case 0x1: nResult = a ^ b; break;                       // EOR
                case 0x2: nResult = a - b; break;                       // SUB
                case 0x3: nResult = b - a; break;                       // RSB
                case 0x4: nResult = a + b; break;                       // ADD
                case 0x8: nResult = a & b; bWrite = false; break;       // TST
                case 0x9: nResult = a ^ b; bWrite = false; break;       // TEQ
                case 0xA: nResult = a - b; bWrite = false; break;       // CMP
                case 0xB: nResult = a + b; bWrite = false; break;       // CMN
                case 0xC: nResult = a | b; break;                       // ORR
                case 0xD: nResult = b; break;                           // MOV
                case 0xE: nResult = a & ~b; break;                      // BIC
                case 0xF: nResult = ~b; break;                          // MVN
                default: info.result = STEP_UNIMPLEMENTED; return;
            }

            if (op.bSetFlags) {
                quint64 nFlags = pRegisters->nRFLAGS & ~(N_FLAG | Z_FLAG | C_FLAG | V_FLAG);
                if (nResult & 0x80000000) nFlags |= N_FLAG;
                if (nResult == 0) nFlags |= Z_FLAG;
                // C/V only meaningful for add/sub; approximate for CMP/SUB.
                if ((op.nOpcode == 0x2) || (op.nOpcode == 0xA)) {
                    if (a >= b) nFlags |= C_FLAG;
                    if (((a ^ b) & (a ^ nResult)) & 0x80000000) nFlags |= V_FLAG;
                } else if ((op.nOpcode == 0x4) || (op.nOpcode == 0xB)) {
                    if ((quint64)a + b > 0xFFFFFFFF) nFlags |= C_FLAG;
                    if ((~(a ^ b) & (a ^ nResult)) & 0x80000000) nFlags |= V_FLAG;
                }
                pRegisters->nRFLAGS = nFlags;
            }

            if (bWrite) {
                if (op.nRd == 15) {
                    pRegisters->nRIP = nResult;
                    bBranch = true;
                } else {
                    pRegisters->nGPR[op.nRd] = nResult;
                }
            }
            break;
        }
        case OP::ARM_LDST: {
            quint32 nBase = (quint32)pRegisters->nGPR[op.nRn];
            if (op.nRn == 15) {
                nBase = (quint32)(op.nPc + 8);
            }
            quint32 nOffset = op.bImmOperand ? op.nImm : (quint32)pRegisters->nGPR[op.nRm];
            quint32 nAddress = op.bPre ? (op.bUp ? nBase + nOffset : nBase - nOffset) : nBase;

            bool bOk = false;
            if (op.bLoad) {
                quint32 nValue = op.bByte ? m_pMemoryManager->readByte(nAddress, &bOk) : m_pMemoryManager->readDword(nAddress, &bOk);
                if (op.nRd == 15) {
                    pRegisters->nRIP = nValue;
                    bBranch = true;
                } else {
                    pRegisters->nGPR[op.nRd] = nValue;
                }
            } else {
                quint32 nValue = (quint32)pRegisters->nGPR[op.nRd];
                _noteWrite(nAddress, op.bByte ? 1 : 4);
                bOk = op.bByte ? m_pMemoryManager->writeByte(nAddress, (quint8)nValue) : m_pMemoryManager->writeDword(nAddress, nValue);
            }
            if (!bOk) {
                m_bExecFault = true;
            }

            if ((!op.bPre || op.bWriteBack) && (op.nRn != 15)) {
                quint32 nNewBase = op.bUp ? nBase + nOffset : nBase - nOffset;
                pRegisters->nGPR[op.nRn] = op.bPre ? nNewBase : nNewBase;  // write-back
            }
            break;
        }
        case OP::ARM_B:
            if (op.bLink) {
                pRegisters->nGPR[14] = nNext;  // LR
            }
            pRegisters->nRIP = op.nTarget;
            bBranch = true;
            break;
        case OP::ARM_BX:
            pRegisters->nRIP = pRegisters->nGPR[op.nRm] & ~Q_UINT64_C(1);  // ignore thumb bit
            bBranch = true;
            break;
        case OP::ARM_HALT:
            info.result = STEP_HALT;
            pRegisters->nRIP = nNext;
            return;
        case OP::ARM_UNIMPL:
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

XEmuArch::STEP_INFO XEmuArm::step(XEmuRegisters *pRegisters)
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

qint64 XEmuArm::run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo)
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

QString XEmuArm::getRegistersText(const XEmuRegisters *pRegisters) const
{
    QString sResult;
    static const char *const pszNames[16] = {"r0", "r1", "r2",  "r3",  "r4",  "r5", "r6", "r7",
                                             "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"};
    for (int i = 0; i < 15; i++) {
        sResult += QString("%1 = %2\n").arg(QString::fromLatin1(pszNames[i]), -3).arg((quint32)pRegisters->nGPR[i], 8, 16, QChar('0'));
    }
    sResult += QString("pc  = %1\n").arg((quint32)pRegisters->nRIP, 8, 16, QChar('0'));
    sResult += QString("cpsr = %1%2%3%4\n")
                   .arg((pRegisters->nRFLAGS & N_FLAG) ? 'N' : '-')
                   .arg((pRegisters->nRFLAGS & Z_FLAG) ? 'Z' : '-')
                   .arg((pRegisters->nRFLAGS & C_FLAG) ? 'C' : '-')
                   .arg((pRegisters->nRFLAGS & V_FLAG) ? 'V' : '-');
    return sResult;
}
