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
#ifndef XEMUTB_H
#define XEMUTB_H

#include <QHash>
#include <QString>
#include <QVector>

#include "xbinary.h"

// QEMU-style intermediate representation and translation-block cache.
//
// Guest instructions are decoded once into architecture-neutral micro-ops
// (XEmuMicroOp), grouped into a straight-line Translation Block (XEmuTB) that ends
// at the first control transfer, and the block is cached by its guest start
// address (XEmuTBCache). Execution interprets the cached micro-ops instead of
// re-decoding the guest bytes on every pass -- the same "translate once, execute
// many" idea QEMU/TCG uses, with an interpreter backend in the spirit of TCG's TCI.

// One decoded operand: a register, a memory reference or nothing. Memory operands
// store register *indices* (never captured values) so a translated block stays
// valid across executions with different register contents.
struct XEmuOperand {
    bool bIsReg;
    bool bIsMem;
    int nReg;        // register index for a register operand
    bool bHigh8;     // byte operand is a high-byte register (AH/CH/DH/BH); accesses bits 8..15 of nReg
    bool bMMX;       // register operand is an MMX register (MM0-MM7); nReg is 0..7
    int nBaseReg;    // memory base register index, or -1
    int nIndexReg;   // memory index register index, or -1
    int nScale;      // 1/2/4/8
    qint64 nDisp;    // displacement
    bool bRipRel;    // RIP-relative (address = insn_pc + insn_len + disp)
    int nSegSource;  // 0 none, 1 FS, 2 GS

    XEmuOperand() : bIsReg(false), bIsMem(false), nReg(0), bHigh8(false), bMMX(false), nBaseReg(-1), nIndexReg(-1), nScale(1), nDisp(0), bRipRel(false), nSegSource(0)
    {
    }

    static XEmuOperand reg(int nRegIndex)
    {
        XEmuOperand operand;
        operand.bIsReg = true;
        operand.nReg = nRegIndex;
        return operand;
    }

    static XEmuOperand mmx(int nRegIndex)
    {
        XEmuOperand operand;
        operand.bIsReg = true;
        operand.bMMX = true;
        operand.nReg = nRegIndex & 7;
        return operand;
    }

    // Build a byte register operand from a raw 3-bit encoding. Without a REX prefix the
    // encodings 4..7 name the high-byte registers AH/CH/DH/BH (bits 8..15 of AX/CX/DX/BX),
    // not SPL/BPL/SIL/DIL; with REX present they are the low bytes (extended by REX.B/R).
    static XEmuOperand reg8(int nRawField, bool bHasRex, bool bRexExtend)
    {
        XEmuOperand operand;
        operand.bIsReg = true;
        if (!bHasRex && (nRawField >= 4) && (nRawField <= 7)) {
            operand.nReg = nRawField - 4;
            operand.bHigh8 = true;
        } else {
            operand.nReg = nRawField + (bRexExtend ? 8 : 0);
        }
        return operand;
    }
};

// Micro-op kinds. Each guest instruction maps to exactly one of these; the operand
// slots (dst/src/imm) carry the details. Control-transfer kinds terminate a block.
enum XEmuMicroOpKind {
    MOP_NOP = 0,
    MOP_ALU_RM_R,     // rm = aluOp(rm, reg)
    MOP_ALU_R_RM,     // reg = aluOp(reg, rm)
    MOP_ALU_RAX_IMM,  // rAX = aluOp(rAX, imm)
    MOP_ALU_RM_IMM,   // rm = aluOp(rm, imm)   (group 1)
    MOP_MOV,          // dst = src   (dst/src any operand)
    MOP_MOV_IMM,      // dst = imm
    MOP_LEA,          // reg = effective address
    MOP_MOVZX,        // reg = zero_extend(rm, srcSize)
    MOP_MOVSX,        // reg = sign_extend(rm, srcSize)
    MOP_TEST,         // flags = src1 & src2
    MOP_TEST_IMM,     // flags = dst & imm
    MOP_PUSH,         // push(src)
    MOP_POP,          // dst = pop()
    MOP_INCDEC,       // rm +/- 1   (nAluOp: 0 = inc, 1 = dec)
    MOP_SETCC,        // rm = cond ? 1 : 0
    MOP_JMP,          // pc = branchTarget
    MOP_JMP_IND,      // pc = src
    MOP_JCC,          // pc = cond ? branchTarget : fallthrough
    MOP_CALL,         // push(next); pc = branchTarget
    MOP_CALL_IND,     // push(next); pc = src
    MOP_JMP_FAR,      // far jmp ptr16:16 (0xEA): CS = nImm, IP = nBranchTarget
    MOP_CALL_FAR,     // far call ptr16:16 (0x9A): push CS; push next-IP; CS = nImm, IP = nBranchTarget
    MOP_JMP_FAR_IND,  // far jmp m16:16 (FF /5): load CS:IP from the memory operand src
    MOP_CALL_FAR_IND, // far call m16:16 (FF /3): push CS; push next-IP; load CS:IP from src
    MOP_RETF,         // far ret (0xCB / 0xCA): IP = pop(); CS = pop()  (nImm bytes released)
    MOP_IRET,         // interrupt return (0xCF): IP = pop(); CS = pop(); FLAGS = pop()
    MOP_LOADFAR,      // les/lds (0xC4/0xC5): dst = [src]; ES|DS = [src + opsize]  (nCond: 0 ES, 1 DS)
    MOP_RET,          // pc = pop()  (nImm bytes released)
    MOP_HALT,         // int3 / hlt / syscall
    MOP_RDTSC,        // edx:eax = timestamp counter
    MOP_CPUID,        // eax/ebx/ecx/edx = cpuid(eax)
    MOP_PUSHA,        // pushad/pushaw (32-bit only)
    MOP_POPA,         // popad/popaw  (32-bit only)
    MOP_SHIFT,        // rm = shift/rotate(rm, count)  (nAluOp: 0 rol..7 sar; nCond: 0 imm, 1 CL)
    MOP_STRING,       // movs/stos/lods/scas/cmps  (nAluOp: kind; nCond: 0 none, 1 rep/repe, 2 repne)
    MOP_MULDIV,       // group-3 not/neg/mul/imul/div/idiv  (nAluOp: modrm ext 2..7)
    MOP_XCHG,         // swap(dst, src)
    MOP_CDQ,          // sign-extend accumulator  (nAluOp: 0 cbw/cwde/cdqe, 1 cwd/cdq/cqo)
    MOP_BSWAP,        // reverse byte order of a register
    MOP_BSF,          // bit scan forward (0F BC): dst = index of lowest set bit of src; ZF=1 if src==0
    MOP_BSR,          // bit scan reverse (0F BD): dst = index of highest set bit of src; ZF=1 if src==0
    MOP_XADD,         // exchange-and-add (0F C0/C1): tmp=dst+src (ADD flags); src=dst; dst=tmp
    MOP_BT,           // bit test group: BT/BTS/BTR/BTC  (nAluOp: 0 BT, 1 BTS, 2 BTR, 3 BTC; nCond: 0 imm8 index, 1 register index). CF = tested bit.
    MOP_SHIFTD,       // double-precision shift SHLD/SHRD (0F A4/A5/AC/AD)  (nAluOp: 0 SHLD, 1 SHRD; nCond: 0 imm8 count, 1 CL). dst=r/m, src=reg.
    MOP_MMX,          // MMX packed-integer op  (nAluOp: MMXOP id; dst/src MMX regs or m64; MOVD uses r/m32). nCond: 1 = shift count is imm8.
    MOP_IMUL2,        // reg = reg * rm (signed, truncated)  (0F AF; three-operand via nImm when nSrcSize<0)
    MOP_LOOP,         // loopne/loope/loop/jecxz  (nAluOp: opcode - 0xE0)
    MOP_SYSCALL,      // syscall / int 0x80  (nAluOp: 0 syscall, 1 int 0x80)
    MOP_FLAGOP,       // clc/stc/cmc/cld/std/cli/sti  (nAluOp selects)
    MOP_CMOVCC,       // reg = cond ? rm : reg  (0F 40..4F; nCond = condition)
    MOP_PUSHF,        // pushf/pushfd/pushfq: push(EFLAGS)   (nSize = 2/4/8)
    MOP_POPF,         // popf/popfd/popfq:  EFLAGS = pop()   (nSize = 2/4/8)
    MOP_SAHF,         // store AH into the low byte of EFLAGS (SF ZF AF PF CF)
    MOP_LAHF,         // load the low byte of EFLAGS into AH
    MOP_LEAVE,        // leave: rSP = rBP; rBP = pop()
    MOP_ENTER,        // enter imm16, imm8: build a stack frame  (nImm = size, nAluOp = level)
    MOP_IN,           // in AL/AX/eAX, imm8/DX   (port read; unmodelled ports read as all-ones)
    MOP_OUT,          // out imm8/DX, AL/AX/eAX  (port write; unmodelled ports are a no-op)
    MOP_XLAT,         // xlat: AL = [DS:(r)BX + AL]  (table lookup)
    MOP_SALC,         // salc/setalc (undocumented 0xD6): AL = CF ? 0xFF : 0x00  (no flags affected)
    MOP_SMSW,         // smsw r/m16 (0F 01 /4): store machine status word (CR0 low bits)
    MOP_LSL,          // lar/lsl r32,r/m (0F 02/03): load access-rights / segment limit, set ZF (nImm carries the value)
    MOP_MOVFROMCR,    // mov r32, crN (0F 20): read a control register (real-mode fixed values)
    MOP_MOVDR,        // mov r32,drN / mov drN,r32 (0F 21 / 0F 23): debug registers, stored and masked
    MOP_PUSHSEG,      // push segment register  (nAluOp: 0 ES,1 CS,2 SS,3 DS,4 FS,5 GS)
    MOP_POPSEG,       // pop  segment register  (nAluOp: as above)
    MOP_BCD,          // BCD/ASCII adjust: DAA/DAS/AAA/AAS/AAM/AAD  (nAluOp 0..5; nImm = base)
    MOP_MOVSEG,       // mov Sreg,r/m16 (nCond 0) or mov r/m16,Sreg (nCond 1); nAluOp = seg index
    MOP_FPU,          // x87 ESC opcode (nAluOp = 0xD8..0xDF, nImm = ModRM, dst = mem operand, nSrcSize = mem type)
    MOP_INTO,         // into (0xCE): if OF, software interrupt 4; else fall through
    MOP_ARPL,         // arpl r/m16, r16 (0x63, 16/32-bit modes): adjust RPL, set ZF if adjusted
    MOP_UNIMPL        // opcode outside the supported subset
};

// A single decoded micro-op.
struct XEmuMicroOp {
    XEmuMicroOpKind kind;
    int nSize;       // operation width in bytes (1/2/4/8)
    int nSrcSize;    // source width (MOVZX/MOVSX)
    int nAluOp;      // ALU operation id / inc-dec selector
    quint8 nCond;    // condition code (Jcc/SETcc)
    XEmuOperand dst;
    XEmuOperand src;
    quint64 nImm;
    XADDR nAddress;      // guest address of this instruction
    quint32 nLength;     // encoded length in bytes
    XADDR nBranchTarget;  // absolute target for direct control transfers
    QString sText;        // short mnemonic (for tracing)

    XEmuMicroOp() : kind(MOP_NOP), nSize(4), nSrcSize(1), nAluOp(0), nCond(0), nImm(0), nAddress(0), nLength(0), nBranchTarget(0)
    {
    }

    bool isBlockTerminator() const
    {
        return (kind == MOP_JMP) || (kind == MOP_JMP_IND) || (kind == MOP_JCC) || (kind == MOP_CALL) || (kind == MOP_CALL_IND) || (kind == MOP_JMP_FAR) ||
               (kind == MOP_CALL_FAR) || (kind == MOP_JMP_FAR_IND) || (kind == MOP_CALL_FAR_IND) || (kind == MOP_RETF) || (kind == MOP_IRET) || (kind == MOP_RET) ||
               (kind == MOP_LOOP) || (kind == MOP_HALT) || (kind == MOP_SYSCALL) || (kind == MOP_INTO) || (kind == MOP_UNIMPL);
    }
};

// A translation block: the micro-ops for one straight-line run of guest code.
struct XEmuTB {
    XADDR nStartAddress;
    XADDR nEndAddress;  // guest address just past the last instruction
    QVector<XEmuMicroOp> listOps;

    XEmuTB() : nStartAddress(0), nEndAddress(0)
    {
    }
};

// Cache of translation blocks keyed by guest start address.
class XEmuTBCache {
public:
    XEmuTBCache()
    {
    }
    ~XEmuTBCache()
    {
        clear();
    }

    XEmuTB *find(XADDR nAddress) const
    {
        return m_mapBlocks.value(nAddress, nullptr);
    }

    void insert(XEmuTB *pBlock)
    {
        m_mapBlocks.insert(pBlock->nStartAddress, pBlock);
    }

    void clear()
    {
        qDeleteAll(m_mapBlocks);
        m_mapBlocks.clear();
    }

    // Drop every block that overlaps [nFrom, nTo) -- needed when guest code changes
    // (self-modifying code / freshly mapped pages).
    void invalidate(XADDR nFrom, XADDR nTo)
    {
        QList<XADDR> listRemove;
        for (QHash<XADDR, XEmuTB *>::const_iterator it = m_mapBlocks.constBegin(); it != m_mapBlocks.constEnd(); ++it) {
            XEmuTB *pBlock = it.value();
            if ((pBlock->nStartAddress < nTo) && (nFrom < pBlock->nEndAddress)) {
                listRemove.append(it.key());
            }
        }
        for (int i = 0; i < listRemove.size(); i++) {
            delete m_mapBlocks.take(listRemove.at(i));
        }
    }

    int count() const
    {
        return m_mapBlocks.size();
    }

private:
    XEmuTBCache(const XEmuTBCache &) = delete;
    XEmuTBCache &operator=(const XEmuTBCache &) = delete;

    QHash<XADDR, XEmuTB *> m_mapBlocks;
};

#endif  // XEMUTB_H
