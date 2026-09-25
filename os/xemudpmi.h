/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * SPDX-License-Identifier: MIT
 */
#ifndef XEMUDPMI_H
#define XEMUDPMI_H

#include <QMap>

#include "xemutypes.h"

class XEmuMemoryManager;
class XEmuMsdosInt;
class XEmuRegisters;
class XEmuX86;

// Minimal DPMI 0.9 host for 32-bit DOS clients. The CPU owns segmentation;
// this class owns the descriptors, DOS bridge and DPMI allocation policy.
class XEmuDpmi {
public:
    XEmuDpmi(XEmuMemoryManager *pMemory, XEmuX86 *pCpu, XEmuMsdosInt *pDos);

    void reset(quint16 nPspSegment);
    void setPspSegment(quint16 nPspSegment) { m_nPspSegment = nPspSegment; }
    void installSwitchStub();
    bool isActive() const { return m_bActive; }
    bool detect(XEmuRegisters *pRegisters);
    bool switchFromRealMode(XEmuRegisters *pRegisters);
    bool interrupt31(XEmuRegisters *pRegisters);

    static const quint16 N_SWITCH_SEGMENT = 0xF000;
    static const quint16 N_SWITCH_OFFSET = 0xFE00;
    static const quint8 N_SWITCH_VECTOR = 0xE0;

private:
    struct DESCRIPTOR {
        XADDR nBase = 0;
        quint32 nLimit = 0xFFFF;
        quint16 nRights = 0x0092;
        bool bDefault32 = false;
    };

    quint16 _allocateDescriptor(XADDR nBase, quint32 nLimit, quint16 nRights, bool bDefault32);
    void _publish(quint16 nSelector);
    bool _pointer(quint16 nSelector, quint32 nOffset, quint32 nSize, XADDR *pLinear) const;
    bool _simulateDosInterrupt(XEmuRegisters *pRegisters);
    void _fail(XEmuRegisters *pRegisters, quint16 nError) const;

    XEmuMemoryManager *m_pMemory;
    XEmuX86 *m_pCpu;
    XEmuMsdosInt *m_pDos;
    QMap<quint16, DESCRIPTOR> m_descriptors;
    QMap<quint32, quint32> m_allocations;
    quint32 m_nNextSelector = 0x1007;
    quint16 m_nPspSegment = 0;
    bool m_bActive = false;
};

#endif  // XEMUDPMI_H
