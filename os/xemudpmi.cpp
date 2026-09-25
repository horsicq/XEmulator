/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#include "xemudpmi.h"

#include "xemumemorymanager.h"
#include "xemumsdosint.h"
#include "xemuregisters.h"
#include "xemux86.h"

namespace {
constexpr quint32 kMaxDpmiBlock = 32u * 1024u * 1024u;
constexpr quint32 kRealModeCallSize = 0x32;

quint16 reg16(const XEmuRegisters *p, XEmuRegisters::GPR nReg)
{
    return (quint16)p->getGPR(nReg, 2);
}

quint32 reg32(const XEmuRegisters *p, XEmuRegisters::GPR nReg)
{
    return (quint32)p->getGPR(nReg, 4);
}
}

XEmuDpmi::XEmuDpmi(XEmuMemoryManager *pMemory, XEmuX86 *pCpu, XEmuMsdosInt *pDos)
    : m_pMemory(pMemory), m_pCpu(pCpu), m_pDos(pDos)
{
}

void XEmuDpmi::reset(quint16 nPspSegment)
{
    m_bActive = false;
    m_nPspSegment = nPspSegment;
    m_nNextSelector = 0x1007;
    m_descriptors.clear();
    m_allocations.clear();
    if (m_pCpu) {
        m_pCpu->setProtectedMode(false);
        m_pCpu->setBits(16);
    }
}

void XEmuDpmi::installSwitchStub()
{
    // The FAR CALL reaches real-mode ROM, then issues a private INT. Do not use
    // a DOS/BIOS vector: ordinary guest software can still use those vectors.
    const XADDR nStub = ((XADDR)N_SWITCH_SEGMENT << 4) + N_SWITCH_OFFSET;
    m_pMemory->writeByte(nStub, 0xCD);
    m_pMemory->writeByte(nStub + 1, N_SWITCH_VECTOR);
    m_pMemory->writeByte(nStub + 2, 0xCB);  // fail closed if the private INT is not serviced
}

bool XEmuDpmi::detect(XEmuRegisters *pRegisters)
{
    if (!m_pCpu || m_bActive) {
        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 1);
        return true;
    }
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, 0);
    pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, 1);  // 32-bit client supported
    pRegisters->setGPR(XEmuRegisters::GPR_RCX, 1, 3);  // 80386
    pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, 9); // DPMI 0.9
    pRegisters->setGPR(XEmuRegisters::GPR_RSI, 2, 0); // no private host data needed
    pRegisters->nES = N_SWITCH_SEGMENT;
    pRegisters->setGPR(XEmuRegisters::GPR_RDI, 2, N_SWITCH_OFFSET);
    return true;
}

quint16 XEmuDpmi::_allocateDescriptor(XADDR nBase, quint32 nLimit, quint16 nRights, bool bDefault32)
{
    if (m_nNextSelector > 0xFFF7) {
        return 0;
    }
    const quint16 nSelector = (quint16)m_nNextSelector;
    m_nNextSelector += 8;
    DESCRIPTOR descriptor;
    descriptor.nBase = nBase;
    descriptor.nLimit = nLimit;
    descriptor.nRights = nRights;
    descriptor.bDefault32 = bDefault32;
    m_descriptors.insert(nSelector, descriptor);
    _publish(nSelector);
    return nSelector;
}

void XEmuDpmi::_publish(quint16 nSelector)
{
    const DESCRIPTOR &d = m_descriptors[nSelector];
    m_pCpu->setSelectorDescriptor(nSelector, d.nBase, d.nLimit, d.bDefault32);
}

void XEmuDpmi::_fail(XEmuRegisters *pRegisters, quint16 nError) const
{
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, true);
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nError);
}

bool XEmuDpmi::switchFromRealMode(XEmuRegisters *pRegisters)
{
    const XADDR nAfterInt = ((XADDR)N_SWITCH_SEGMENT << 4) + N_SWITCH_OFFSET + 2;
    if (!m_pCpu || m_bActive || pRegisters->nCS != N_SWITCH_SEGMENT || pRegisters->nRIP != nAfterInt) {
        return false;
    }

    const quint16 nSp = reg16(pRegisters, XEmuRegisters::GPR_RSP);
    const XADDR nStack = ((XADDR)pRegisters->nSS << 4) + nSp;
    bool bOkIp = false, bOkCs = false;
    const quint16 nReturnIp = m_pMemory->readWord(nStack, &bOkIp);
    const quint16 nReturnCs = m_pMemory->readWord(((XADDR)pRegisters->nSS << 4) + (quint16)(nSp + 2), &bOkCs);
    if (!bOkIp || !bOkCs || (reg16(pRegisters, XEmuRegisters::GPR_RAX) != 1)) {
        _fail(pRegisters, 0x8001);
        return true;  // execute the stub's RETF in real mode
    }

    const quint16 nOldDs = pRegisters->nDS;
    const quint16 nOldSs = pRegisters->nSS;
    const quint16 nCode = _allocateDescriptor((XADDR)nReturnCs << 4, 0xFFFF, 0x009A, false);
    const quint16 nStackSelector = _allocateDescriptor((XADDR)nOldSs << 4, 0xFFFF, 0x4092, true);
    const quint16 nData = _allocateDescriptor((XADDR)nOldDs << 4, 0xFFFF, 0x4092, true);
    // DPMI returns a PSP selector in ES, not the private-data segment passed
    // to the switch entry. FASM reads its command tail through this selector.
    const quint16 nPsp = _allocateDescriptor((XADDR)m_nPspSegment << 4, 0xFF, 0x4092, true);
    if (!nCode || !nStackSelector || !nData || !nPsp) {
        _fail(pRegisters, 0x8011);
        return true;
    }

    pRegisters->setGPR(XEmuRegisters::GPR_RSP, 4, (quint32)(quint16)(nSp + 4));
    pRegisters->nCS = nCode;
    pRegisters->nSS = nStackSelector;
    pRegisters->nDS = nData;
    pRegisters->nES = nPsp;
    pRegisters->nFS = 0;
    pRegisters->nGS = 0;
    pRegisters->nFSBase = 0;
    pRegisters->nGSBase = 0;
    pRegisters->nRIP = ((XADDR)nReturnCs << 4) + nReturnIp;
    pRegisters->nCR0 |= 1;
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
    // The 32-bit client still returns into its original 16-bit CS. Its
    // later RETFD selects the 32-bit code descriptor it creates via INT 31h.
    m_pCpu->setBits(16);
    m_pCpu->setProtectedMode(true);
    m_bActive = true;
    return true;
}

bool XEmuDpmi::_pointer(quint16 nSelector, quint32 nOffset, quint32 nSize, XADDR *pLinear) const
{
    const auto it = m_descriptors.constFind(nSelector);
    if (it == m_descriptors.cend() || !nSize || nOffset > it->nLimit || nSize - 1 > it->nLimit - nOffset) {
        return false;
    }
    const XADDR nLinear = it->nBase + nOffset;
    if (nLinear > 0xFFFFFFFFull || !m_pMemory->isCommitted(nLinear, nSize)) {
        return false;
    }
    *pLinear = nLinear;
    return true;
}

bool XEmuDpmi::_simulateDosInterrupt(XEmuRegisters *pRegisters)
{
    const quint16 nBx = reg16(pRegisters, XEmuRegisters::GPR_RBX);
    if ((nBx & 0xFF) != 0x21 || (nBx >> 8) != 0 || reg16(pRegisters, XEmuRegisters::GPR_RCX) != 0) {
        _fail(pRegisters, 0x8001);  // only INT 21h, with no copied stack words
        return true;
    }

    XADDR nCall = 0;
    if (!_pointer(pRegisters->nES, reg32(pRegisters, XEmuRegisters::GPR_RDI), kRealModeCallSize, &nCall)) {
        _fail(pRegisters, 0x8022);
        return true;
    }

    XEmuRegisters real;
    real.reset();
    real.setGPR(XEmuRegisters::GPR_RDI, 4, m_pMemory->readDword(nCall + 0x00));
    real.setGPR(XEmuRegisters::GPR_RSI, 4, m_pMemory->readDword(nCall + 0x04));
    real.setGPR(XEmuRegisters::GPR_RBP, 4, m_pMemory->readDword(nCall + 0x08));
    real.setGPR(XEmuRegisters::GPR_RBX, 4, m_pMemory->readDword(nCall + 0x10));
    real.setGPR(XEmuRegisters::GPR_RDX, 4, m_pMemory->readDword(nCall + 0x14));
    real.setGPR(XEmuRegisters::GPR_RCX, 4, m_pMemory->readDword(nCall + 0x18));
    real.setGPR(XEmuRegisters::GPR_RAX, 4, m_pMemory->readDword(nCall + 0x1C));
    real.nRFLAGS = (m_pMemory->readWord(nCall + 0x20) | 2u);
    real.nES = m_pMemory->readWord(nCall + 0x22);
    real.nDS = m_pMemory->readWord(nCall + 0x24);
    real.nFS = m_pMemory->readWord(nCall + 0x26);
    real.nGS = m_pMemory->readWord(nCall + 0x28);
    real.nCS = m_pMemory->readWord(nCall + 0x2C);
    real.nSS = m_pMemory->readWord(nCall + 0x30);
    real.setGPR(XEmuRegisters::GPR_RSP, 2, m_pMemory->readWord(nCall + 0x2E));

    // XEmuMsdosInt expects real segment:offset pointers. Do not expose the
    // protected selectors or stack to it; only copy back the DPMI call frame.
    bool bTerminate = false;
    m_pDos->int21(&real, &bTerminate);
    m_pMemory->writeDword(nCall + 0x00, reg32(&real, XEmuRegisters::GPR_RDI));
    m_pMemory->writeDword(nCall + 0x04, reg32(&real, XEmuRegisters::GPR_RSI));
    m_pMemory->writeDword(nCall + 0x08, reg32(&real, XEmuRegisters::GPR_RBP));
    m_pMemory->writeDword(nCall + 0x10, reg32(&real, XEmuRegisters::GPR_RBX));
    m_pMemory->writeDword(nCall + 0x14, reg32(&real, XEmuRegisters::GPR_RDX));
    m_pMemory->writeDword(nCall + 0x18, reg32(&real, XEmuRegisters::GPR_RCX));
    m_pMemory->writeDword(nCall + 0x1C, reg32(&real, XEmuRegisters::GPR_RAX));
    m_pMemory->writeWord(nCall + 0x20, (quint16)real.nRFLAGS);
    m_pMemory->writeWord(nCall + 0x22, real.nES);
    m_pMemory->writeWord(nCall + 0x24, real.nDS);
    m_pMemory->writeWord(nCall + 0x26, real.nFS);
    m_pMemory->writeWord(nCall + 0x28, real.nGS);
    m_pMemory->writeWord(nCall + 0x2E, reg16(&real, XEmuRegisters::GPR_RSP));
    m_pMemory->writeWord(nCall + 0x30, real.nSS);
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
    return !bTerminate;
}

bool XEmuDpmi::interrupt31(XEmuRegisters *pRegisters)
{
    if (!m_bActive || !m_pCpu) {
        _fail(pRegisters, 0x8001);
        return true;
    }

    const quint16 nFunction = reg16(pRegisters, XEmuRegisters::GPR_RAX);
    const quint16 nBx = reg16(pRegisters, XEmuRegisters::GPR_RBX);
    const quint16 nCx = reg16(pRegisters, XEmuRegisters::GPR_RCX);
    const quint16 nDx = reg16(pRegisters, XEmuRegisters::GPR_RDX);
    switch (nFunction) {
        case 0x0000: {  // allocate consecutive LDT descriptors
            if (!nCx || nCx > 256 || m_nNextSelector + (quint32)nCx * 8 > 0x10000) {
                _fail(pRegisters, 0x8011);
                return true;
            }
            const quint16 nFirst = (quint16)m_nNextSelector;
            for (quint16 i = 0; i < nCx; i++) {
                _allocateDescriptor(0, 0xFFFF, 0x0092, false);
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nFirst);
            break;
        }
        case 0x0007:  // set descriptor base, CX:DX
        case 0x0008:  // set descriptor limit, CX:DX
        case 0x0009: {  // set access rights, CX
            auto it = m_descriptors.find(nBx);
            if (it == m_descriptors.end()) {
                _fail(pRegisters, 0x8022);
                return true;
            }
            if (nFunction == 0x0007) {
                it->nBase = ((XADDR)nCx << 16) | nDx;
            } else if (nFunction == 0x0008) {
                const quint32 nLimit = ((quint32)nCx << 16) | nDx;
                if (nLimit > 0xFFFFF && (nLimit & 0xFFF) != 0xFFF) {
                    _fail(pRegisters, 0x8021);
                    return true;
                }
                it->nLimit = nLimit;
            } else {
                if ((nCx & 0x90) != 0x90 || (nCx & 0x2000)) {
                    _fail(pRegisters, 0x8021);
                    return true;
                }
                it->nRights = nCx;
                it->bDefault32 = (nCx & 0x4000) != 0;
            }
            _publish(nBx);
            break;
        }
        case 0x0100: {  // allocate DOS paragraphs, or query largest with BX=FFFFh
            if (!nBx) {
                _fail(pRegisters, 8);
                return true;
            }
            XEmuRegisters dos;
            dos.reset();
            dos.setGPR(XEmuRegisters::GPR_RAX, 2, 0x4800);
            dos.setGPR(XEmuRegisters::GPR_RBX, 2, nBx);
            bool bTerminate = false;
            m_pDos->int21(&dos, &bTerminate);
            if (dos.getFlag(XEmuRegisters::FLAG_CF)) {
                pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, reg16(&dos, XEmuRegisters::GPR_RBX));
                _fail(pRegisters, reg16(&dos, XEmuRegisters::GPR_RAX));
                return true;
            }
            const quint16 nSeg = reg16(&dos, XEmuRegisters::GPR_RAX);
            const quint16 nSelector = _allocateDescriptor((XADDR)nSeg << 4, (quint32)nBx * 16 - 1, 0x4092, true);
            if (!nSelector) {
                m_pDos->freeSeg(nSeg);
                _fail(pRegisters, 0x8011);
                return true;
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nSeg);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 2, nSelector);
            break;
        }
        case 0x0300:
            return _simulateDosInterrupt(pRegisters);

        case 0x0500: {  // report one conservative, contiguous free block
            XADDR nInfo = 0;
            if (!_pointer(pRegisters->nES, reg32(pRegisters, XEmuRegisters::GPR_RDI), 0x30, &nInfo)) {
                _fail(pRegisters, 0x8022);
                return true;
            }
            const quint32 nFree = m_allocations.isEmpty() ? kMaxDpmiBlock : 0;
            m_pMemory->writeDword(nInfo, nFree);
            for (quint32 i = 4; i < 0x30; i += 4) {
                m_pMemory->writeDword(nInfo + i, 0xFFFFFFFFu);
            }
            break;
        }
        case 0x0501: {  // allocate committed linear block, return base BX:CX / handle SI:DI
            const quint32 nBytes = ((quint32)nBx << 16) | nCx;
            if (!nBytes || nBytes > kMaxDpmiBlock || !m_allocations.isEmpty()) {
                _fail(pRegisters, 0x8012);
                return true;
            }
            const XADDR nBase = m_pMemory->findFree(nBytes, 0x200000, 0x1000);
            if (nBase < 0x200000 || nBase > 0xFFFFFFFFull ||
                !m_pMemory->mapFixed(nBase, nBytes, XEmuMemoryManager::MEMORY_FLAGS(true, true, true), QStringLiteral("DPMI_memory"))) {
                _fail(pRegisters, 0x8012);
                return true;
            }
            const quint32 nHandle = (quint32)nBase;
            m_allocations.insert(nHandle, nBytes);
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 2, nHandle >> 16);
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 2, nHandle & 0xFFFF);
            pRegisters->setGPR(XEmuRegisters::GPR_RSI, 2, nHandle >> 16);
            pRegisters->setGPR(XEmuRegisters::GPR_RDI, 2, nHandle & 0xFFFF);
            break;
        }
        default:
            _fail(pRegisters, 0x8001);  // unsupported DPMI service, never silently succeed
            return true;
    }
    pRegisters->setFlag(XEmuRegisters::FLAG_CF, false);
    return true;
}
