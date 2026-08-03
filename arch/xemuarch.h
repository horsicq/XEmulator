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
#ifndef XEMUARCH_H
#define XEMUARCH_H

#include <QString>

#include "xemumemorymanager.h"
#include "xemuregisters.h"
#include "xemutypes.h"

// Abstract processor architecture. A concrete implementation knows how to decode
// and execute one instruction of its instruction set against the register file and
// the memory manager, and how to set up the initial thread state.
class XEmuArch {
public:
    enum STEP_RESULT {
        STEP_OK = 0,
        STEP_HALT,           // INT3 / HLT — normal stop
        STEP_FAULT,          // memory access violation
        STEP_UNIMPLEMENTED,  // opcode not handled by this (subset) core
        STEP_SYSCALL,        // syscall / int 0x80 — the OS layer must service it
    };

    struct STEP_INFO {
        STEP_RESULT result;
        XADDR nAddress;     // instruction pointer before the step
        quint32 nLength;    // number of bytes consumed
        QString sText;      // best-effort textual form of the instruction
        QString sComment;   // extra information (fault reason, target, ...)
        int nVector;        // software-interrupt vector for STEP_SYSCALL (INT n); -1 for a bare syscall

        STEP_INFO() : result(STEP_OK), nAddress(0), nLength(0), nVector(-1)
        {
        }
    };

    explicit XEmuArch(XEmuMemoryManager *pMemoryManager);
    virtual ~XEmuArch() = 0;

    virtual QString getArchName() const = 0;
    virtual XEmuArchType getArchType() const = 0;
    virtual quint8 getBits() const = 0;
    virtual void setBits(quint8 nBits) = 0;

    // Initial-thread-state helpers used by the OS loaders. Defaults follow x86
    // conventions; other architectures override them.
    virtual void setPC(XEmuRegisters *pRegisters, XADDR nAddress)
    {
        pRegisters->nRIP = nAddress;
    }
    virtual XADDR getPC(const XEmuRegisters *pRegisters) const
    {
        return pRegisters->nRIP;
    }
    virtual void setStackPointer(XEmuRegisters *pRegisters, XADDR nAddress)
    {
        pRegisters->nGPR[XEmuRegisters::GPR_RSP] = nAddress;
    }
    virtual XADDR getStackPointer(const XEmuRegisters *pRegisters) const
    {
        return pRegisters->nGPR[XEmuRegisters::GPR_RSP];
    }
    virtual void setThreadPointer(XEmuRegisters *pRegisters, XADDR nAddress)
    {
        pRegisters->nFSBase = nAddress;
    }
    virtual void setArgument(XEmuRegisters *pRegisters, int nIndex, quint64 nValue)
    {
        Q_UNUSED(pRegisters)
        Q_UNUSED(nIndex)
        Q_UNUSED(nValue)
    }

    // Execute exactly one instruction pointed to by the instruction pointer.
    virtual STEP_INFO step(XEmuRegisters *pRegisters) = 0;

    // Linear address of the access that raised the most recent STEP_FAULT (0 if the
    // arch does not track it). The OS layer uses it to build an exception record for
    // guest exception dispatch (Win32 SEH). On a fault the arch leaves the PC at the
    // faulting instruction.
    virtual XADDR getFaultAddress() const { return 0; }

    // Execute up to nMaxInsns instructions using the translation-block engine
    // (translate/cache blocks, interpret their micro-ops). Returns the number of
    // instructions executed; pStopInfo (optional) receives the terminating step.
    virtual qint64 run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo) = 0;

    // Number of translation blocks currently cached (0 if the arch has no cache).
    virtual int getBlockCacheCount() const = 0;

    // Discard cached translations (e.g. after guest memory changed).
    virtual void resetCache() = 0;

    virtual QString getRegistersText(const XEmuRegisters *pRegisters) const = 0;

protected:
    XEmuMemoryManager *m_pMemoryManager;
};

#endif  // XEMUARCH_H
