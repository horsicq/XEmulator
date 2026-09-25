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
#include "xemux86.h"

#include <cmath>
#include <cstring>

namespace {
const char *const g_pszAluNames[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};

void multiplyUnsigned64(quint64 a, quint64 b, quint64 *lo, quint64 *hi)
{
    const quint64 a0 = static_cast<quint32>(a), a1 = a >> 32;
    const quint64 b0 = static_cast<quint32>(b), b1 = b >> 32;
    const quint64 p00 = a0 * b0, p01 = a0 * b1;
    const quint64 p10 = a1 * b0, p11 = a1 * b1;
    const quint64 middle = (p00 >> 32) + static_cast<quint32>(p01) + static_cast<quint32>(p10);
    *lo = (middle << 32) | static_cast<quint32>(p00);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
}

void multiplySigned64(quint64 a, quint64 b, quint64 *lo, quint64 *hi)
{
    multiplyUnsigned64(a, b, lo, hi);
    if (a >> 63) *hi -= b;
    if (b >> 63) *hi -= a;
}

bool divideUnsigned128(quint64 hi, quint64 lo, quint64 divisor, quint64 *quotient, quint64 *remainder)
{
    if (!divisor || hi >= divisor) return false;
    if (!hi) {
        *quotient = lo / divisor;
        *remainder = lo % divisor;
        return true;
    }
    quint64 q = 0, r = hi;
    for (int bit = 63; bit >= 0; --bit) {
        const bool carry = (r >> 63) != 0;
        r = (r << 1) | ((lo >> bit) & 1);
        if (carry || r >= divisor) {
            r -= divisor;
            q |= quint64(1) << bit;
        }
    }
    *quotient = q;
    *remainder = r;
    return true;
}

bool divideSigned128(quint64 hi, quint64 lo, quint64 divisor, quint64 *quotient, quint64 *remainder)
{
    const bool negativeNumerator = (hi >> 63) != 0;
    const bool negativeDivisor = (divisor >> 63) != 0;
    if (negativeNumerator) {
        lo = ~lo + 1;
        hi = ~hi + (lo == 0);
    }
    if (negativeDivisor) divisor = ~divisor + 1;
    quint64 q = 0, r = 0;
    if (!divideUnsigned128(hi, lo, divisor, &q, &r)) return false;
    const bool negativeQuotient = negativeNumerator != negativeDivisor;
    if (q > (negativeQuotient ? (quint64(1) << 63) : ((quint64(1) << 63) - 1))) return false;
    *quotient = negativeQuotient ? ~q + 1 : q;
    *remainder = negativeNumerator ? ~r + 1 : r;
    return true;
}

double readF80Value(XEmuMemoryManager *pMemoryManager, XADDR nAddress)
{
    quint64 nMantissa = 0;
    for (int i = 0; i < 8; i++) {
        nMantissa |= static_cast<quint64>(pMemoryManager->readByte(nAddress + i)) << (i * 8);
    }
    const quint16 nSignedExponent = static_cast<quint16>(pMemoryManager->readByte(nAddress + 8) | (pMemoryManager->readByte(nAddress + 9) << 8));
    const int nSign = (nSignedExponent >> 15) & 1;
    const int nExponent = nSignedExponent & 0x7FFF;
    if ((nExponent == 0) && (nMantissa == 0)) return nSign ? -0.0 : 0.0;
    const double nValue = std::ldexp(static_cast<double>(nMantissa), nExponent - 16383 - 63);
    return nSign ? -nValue : nValue;
}

void writeF80Value(XEmuMemoryManager *pMemoryManager, XADDR nAddress, double nValue)
{
    quint64 nMantissa = 0;
    quint16 nSignedExponent = 0;
    if ((nValue != 0.0) && !std::isnan(nValue) && !std::isinf(nValue)) {
        const int nSign = std::signbit(nValue) ? 1 : 0;
        const double nMagnitude = std::fabs(nValue);
        int nExponent = 0;
        const double nFraction = std::frexp(nMagnitude, &nExponent);
        nMantissa = static_cast<quint64>(std::ldexp(nFraction, 64));
        nSignedExponent = static_cast<quint16>((nSign << 15) | ((nExponent - 1 + 16383) & 0x7FFF));
    }
    for (int i = 0; i < 8; i++) {
        pMemoryManager->writeByte(nAddress + i, static_cast<quint8>(nMantissa >> (i * 8)));
    }
    pMemoryManager->writeByte(nAddress + 8, static_cast<quint8>(nSignedExponent & 0xFF));
    pMemoryManager->writeByte(nAddress + 9, static_cast<quint8>(nSignedExponent >> 8));
}

double fpuArithmetic(int nSelector, double nFirst, double nSecond)
{
    switch (nSelector) {
        case 0: return nFirst + nSecond;
        case 1: return nFirst * nSecond;
        case 4: return nFirst - nSecond;
        case 5: return nSecond - nFirst;
        case 6: return nFirst / nSecond;
        case 7: return nSecond / nFirst;
    }
    return nFirst;
}

quint64 wrapNearBranch(quint8 nBits, quint64 nCodeSegmentBase, quint64 nLinearTarget)
{
    return (nBits == 16) ? (nCodeSegmentBase + ((nLinearTarget - nCodeSegmentBase) & 0xFFFF)) : nLinearTarget;
}

void setAxBytes(XEmuRegisters *pRegisters, quint8 nAl, quint8 nAh)
{
    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, static_cast<quint16>((nAh << 8) | nAl));
}

void dumpMemoryOperand(const char *pWhich, const XEmuOperand &operand)
{
    if (operand.bIsMem) {
        fprintf(stderr, "  %s: mem base=%d index=%d scale=%d disp=%lld seg=%d\n", pWhich, operand.nBaseReg, operand.nIndexReg, operand.nScale,
                static_cast<long long>(operand.nDisp), operand.nSegSource);
    }
}
}

// ---- host-CPU native shift fallback (x86-64 host only) --------------------------------
// A shift/double-shift with a count greater than the operand width is architecturally
// UNDEFINED, and the value real silicon produces is microarchitecture-specific (not
// derivable from a formula). VMProtect deliberately uses such shifts as an anti-emulation
// trap and folds the result/flags into its VM key. Since XEmulator runs on an x86 host and
// the target expects that host's behaviour, we reproduce these rare cases exactly by
// executing the equivalent instruction on the host CPU. Only the 8/16-bit undefined region
// is routed here (32/64-bit counts are masked below the width and never reach it).
#if defined(_M_X64) && defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
namespace {

class HostExecPage {
public:
    HostExecPage()
        : m_pPage((quint8 *)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
    {
    }

    ~HostExecPage()
    {
        if (m_pPage) {
            VirtualFree(m_pPage, 0, MEM_RELEASE);
        }
    }

    _Ret_maybenull_ _Post_writable_byte_size_(0x1000) quint8 *data() const
    {
        return m_pPage;
    }

private:
    HostExecPage(const HostExecPage &) = delete;
    HostExecPage &operator=(const HostExecPage &) = delete;

    quint8 *m_pPage;
};

_Ret_maybenull_ _Post_writable_byte_size_(0x1000) quint8 *hostExecPage()
{
    // The generated instruction bytes are mutated before every call. Keeping
    // one page per thread avoids cross-thread publication/execution races.
    thread_local HostExecPage page;
    return page.data();
}

int hostDivExceptionFilter(DWORD nCode)
{
    return ((nCode == EXCEPTION_INT_DIVIDE_BY_ZERO) || (nCode == EXCEPTION_INT_OVERFLOW)) ? EXCEPTION_EXECUTE_HANDLER
                                                                                          : EXCEPTION_CONTINUE_SEARCH;
}

// eax=dst(operand-sized), edx=src, cl=count; runs `insn`, returns eax; *pFlags in/out.
bool hostShiftExec(const quint8 *insn, int ilen, quint32 dst, quint32 src, quint8 count, quint32 *pFlags, quint32 *pResult)
{
    if (!insn || (ilen <= 0) || !pFlags || !pResult) {
        return false;
    }

    struct Ctx {
        quint32 eax, ecx, edx, flags;
    };
    Ctx ctx;
    ctx.eax = dst;
    ctx.ecx = count;
    ctx.edx = src;
    ctx.flags = *pFlags;

    quint8 *page = hostExecPage();
    if (!page) {
        return false;
    }
    // Only volatile registers (rax/rcx/rdx/r10/r11) are used, so no save/restore is needed.
    static const quint8 pro[] = {
        0x49, 0x89, 0xCB,             // mov  r11, rcx           ; r11 = &ctx
        0x41, 0x8B, 0x43, 0x0C,       // mov  eax, [r11+12]      ; flags
        0x50, 0x9D,                   // push rax; popfq
        0x41, 0x8B, 0x43, 0x00,       // mov  eax, [r11+0]       ; dst
        0x41, 0x8B, 0x4B, 0x04,       // mov  ecx, [r11+4]       ; count (cl)
        0x41, 0x8B, 0x53, 0x08        // mov  edx, [r11+8]       ; src
    };
    static const quint8 epi[] = {
        0x9C, 0x41, 0x5A,             // pushfq; pop r10
        0x41, 0x89, 0x43, 0x00,       // mov  [r11+0], eax
        0x45, 0x89, 0x53, 0x0C,       // mov  [r11+12], r10d
        0xC3                          // ret
    };
    int i = 0;
    if ((sizeof(pro) + (size_t)ilen + sizeof(epi)) > 0x1000) {
        return false;
    }
    memcpy(page + i, pro, sizeof(pro)); i += (int)sizeof(pro);
    memcpy(page + i, insn, ilen);      i += ilen;
    memcpy(page + i, epi, sizeof(epi)); i += (int)sizeof(epi);
    if (!FlushInstructionCache(GetCurrentProcess(), page, i)) {
        return false;
    }
    ((void(__fastcall *)(Ctx *))page)(&ctx);
    *pFlags = ctx.flags;
    *pResult = ctx.eax;
    return true;
}

// Build the host instruction for a shift op using ax/al (dst), dx (src), cl (count).
// kind: 4 SHL, 5 SHR, 7 SAR (nShiftOp); 100 SHLD, 101 SHRD. nSize: 1 or 2 (bytes).
int buildShiftInsn(quint8 *out, int kind, int nSize)
{
    int i = 0;
    if (kind == 100 || kind == 101) {  // SHLD/SHRD ax,dx,cl (16-bit only)
        out[i++] = 0x66;
        out[i++] = 0x0F;
        out[i++] = (kind == 100) ? 0xA5 : 0xAD;
        out[i++] = 0xD0;  // modrm: mod3, reg=dx(2), rm=ax(0)
        return i;
    }
    if (kind == 6) {
        kind = 4;  // SAL == SHL
    }
    if (nSize == 2) {
        out[i++] = 0x66;
    }
    out[i++] = (nSize == 1) ? 0xD2 : 0xD3;                 // shift r/m,cl
    out[i++] = (quint8)(0xC0 | ((quint8)kind << 3) | 0x00);  // /kind, rm=ax
    return i;
}

// Run div/idiv on the host to obtain its (undefined) flags; the emulator keeps its own
// result. eax=dividend low, edx=dividend high, ecx=divisor. SEH-guarded because the
// emulator truncates the quotient where the host would raise #DE. Only *pFlags is updated.
bool hostExecDiv(bool bIdiv, int nSize, quint32 eax, quint32 edx, quint32 divisor, quint32 *pFlags)
{
    if (!pFlags) {
        return false;
    }

    struct Ctx {
        quint32 eax, ecx, edx, flags;
    };
    Ctx ctx;
    ctx.eax = eax;
    ctx.ecx = divisor;
    ctx.edx = edx;
    ctx.flags = *pFlags;

    quint8 insn[4];
    int k = 0;
    if (nSize == 2) {
        insn[k++] = 0x66;
    }
    insn[k++] = (nSize == 1) ? 0xF6 : 0xF7;
    insn[k++] = bIdiv ? 0xF9 : 0xF1;  // /7 idiv, /6 div ; rm = ecx/cl

    quint8 *page = hostExecPage();
    if (!page) {
        return false;
    }
    static const quint8 pro[] = {
        0x49, 0x89, 0xCB, 0x41, 0x8B, 0x43, 0x0C, 0x50, 0x9D,
        0x41, 0x8B, 0x43, 0x00, 0x41, 0x8B, 0x4B, 0x04, 0x41, 0x8B, 0x53, 0x08
    };
    static const quint8 epi[] = {0x9C, 0x41, 0x5A, 0x41, 0x89, 0x43, 0x00, 0x45, 0x89, 0x53, 0x0C, 0xC3};
    int n = 0;
    memcpy(page + n, pro, sizeof(pro)); n += (int)sizeof(pro);
    memcpy(page + n, insn, k);          n += k;
    memcpy(page + n, epi, sizeof(epi)); n += (int)sizeof(epi);
    if (!FlushInstructionCache(GetCurrentProcess(), page, n)) {
        return false;
    }
    bool bExecuted = false;
    __try {
        ((void(__fastcall *)(Ctx *))page)(&ctx);
        *pFlags = ctx.flags;
        bExecuted = true;
    } __except (hostDivExceptionFilter(GetExceptionCode())) {
        // Host raised #DE where the emulator truncated; leave flags unchanged.
        bExecuted = false;
    }
    return bExecuted;
}

}  // namespace
#endif  // _M_X64 && _WIN32

// Legacy high-byte register fixup: without a REX prefix, a byte-sized register
// operand encoded 4..7 names AH/CH/DH/BH, not SPL/BPL/SIL/DIL.
static void x86FixHigh8(XEmuOperand &o, int nWidth)
{
    if ((nWidth == 1) && o.bIsReg && !o.bHigh8 && (o.nReg >= 4) && (o.nReg <= 7)) {
        o.nReg -= 4;
        o.bHigh8 = true;
    }
}

XEmuX86::XEmuX86(XEmuMemoryManager *pMemoryManager, quint8 nBits)
    : XEmuArch(pMemoryManager), m_nBits(nBits), m_nTsc(0), m_pExecRegs(nullptr), m_bExecFault(false), m_nFaultAddr(0), m_fpuTop(0), m_fpuControl(0x037F),
      m_fpuStatusCC(0), m_bFpuInit(false)
{
    // Default the modeled I/O ports to open-bus 0xFF, then seed the values real DOS leaves:
    // port 0x21 (8259 master IMR) = 0xF8 (IRQ 0/1/2 enabled, 3-7 masked -- the standard DOS mask).
    for (int i = 0; i < 0x400; i++) {
        m_ioPorts[i] = 0xFF;
    }
    m_ioPorts[0x21] = 0xF8;
    m_nInsnCount = 0;
    m_bPitHiByte = false;
    m_bTrapTaken = false;
    m_bSsBlock = false;
    memset(m_dr, 0, sizeof(m_dr));
    // Architectural RESET values, not zero. A protector that reads DR6/DR7 before writing anything
    // uses them to decide whether it is on a real CPU -- CSCRYPT Pro 3.30/386 reads them first and
    // silently refuses to pack when they come back as 0.
    m_dr[6] = 0xFFFF0FF0u;
    m_dr[7] = 0x00000400u;
    memset(m_smcMap, 0, sizeof(m_smcMap));
    _fpuInit();
}

QString XEmuX86::getArchName() const
{
    if (m_nBits == 16) {
        return QStringLiteral("x86-16");
    }
    return (m_nBits == 64) ? QStringLiteral("x86-64") : QStringLiteral("x86");
}

XEmuArchType XEmuX86::getArchType() const
{
    if (m_nBits == 16) {
        return XARCH_X86_16;
    }
    return (m_nBits == 64) ? XARCH_X86_64 : XARCH_X86_32;
}

quint8 XEmuX86::getBits() const
{
    return m_nBits;
}

void XEmuX86::setBits(quint8 nBits)
{
    m_nBits = nBits;
    m_tbCache.clear();  // cached translations are mode-specific
}

void XEmuX86::setProtectedMode(bool enabled)
{
    if (m_bProtectedMode != enabled) {
        m_bProtectedMode = enabled;
        resetCache();
    }
}

void XEmuX86::setSelectorDescriptor(quint16 selector, XADDR base, quint32 limit, bool default32)
{
    SelectorDescriptor descriptor;
    descriptor.base = base;
    descriptor.limit = limit;
    descriptor.default32 = default32;
    m_selectors.insert(selector, descriptor);
    resetCache();
}

XADDR XEmuX86::selectorBase(quint16 selector) const
{
    if (m_bProtectedMode || m_nBits == 32) {
        auto it = m_selectors.constFind(selector);
        return it == m_selectors.cend() ? 0 : it->base;
    }
    return m_nBits == 16 ? ((XADDR)selector << 4) : 0;
}

bool XEmuX86::selectorDefault32(quint16 selector) const
{
    if (m_bProtectedMode) {
        auto it = m_selectors.constFind(selector);
        return it != m_selectors.cend() && it->default32;
    }
    return m_nBits == 32;
}

int XEmuX86::getBlockCacheCount() const
{
    return m_tbCache.count();
}

void XEmuX86::resetCache()
{
    m_tbCache.clear();
    m_codePages.clear();
}

// Guest memory at [nAddress, nAddress+nSize) just changed. Drop any translation covering it, or the
// stale decode is what runs next -- self-modifying and self-decrypting code is the norm for packers,
// not an exotic case. This is called from EVERY store path; _memWriteSized alone is not enough,
// because it only serves the string ops, the BT family, FPU stores and the INT frame, while ordinary
// `mov [mem],reg/imm` and PUSH go through _writeOpnd/_push.
void XEmuX86::_noteWrite(XADDR nAddress, int nSize)
{
    if (m_tbCache.count() == 0) {
        return;  // nothing translated yet -- the overwhelmingly common case, and free
    }
    const XADDR nEnd = nAddress + (XADDR)nSize;
    const quint64 nFirst = nAddress >> N_CODE_PAGE_SHIFT;
    const quint64 nLast = (nEnd - 1) >> N_CODE_PAGE_SHIFT;
    for (quint64 nPage = nFirst; nPage <= nLast; nPage++) {
        if (m_codePages.contains(nPage)) {
            m_tbCache.invalidate(nAddress, nEnd);
            return;
        }
    }
}

quint64 XEmuX86::_mask(int nSize)
{
    switch (nSize) {
        case 1: return 0xFF;
        case 2: return 0xFFFF;
        case 4: return 0xFFFFFFFF;
        default: return ~Q_UINT64_C(0);
    }
}

quint64 XEmuX86::_signBit(int nSize)
{
    switch (nSize) {
        case 1: return 0x80;
        case 2: return 0x8000;
        case 4: return 0x80000000;
        default: return Q_UINT64_C(0x8000000000000000);
    }
}

qint64 XEmuX86::_signExtend(quint64 nValue, int nSize)
{
    switch (nSize) {
        case 1: return (qint64)(qint8)(quint8)nValue;
        case 2: return (qint64)(qint16)(quint16)nValue;
        case 4: return (qint64)(qint32)(quint32)nValue;
        default: return (qint64)nValue;
    }
}

bool XEmuX86::_parity(quint8 nValue)
{
    int nCount = 0;
    for (int i = 0; i < 8; i++) {
        if (nValue & (1 << i)) {
            nCount++;
        }
    }
    return (nCount % 2) == 0;
}

int XEmuX86::_stackSize(const DEC &dec) const
{
    // PUSH/POP of a register/immediate/segment follow the OPERAND-size attribute, which the 0x66
    // prefix toggles (2<->4 in 16/32-bit). The old code always returned 2 in real mode, so a
    // 0x66-prefixed `push eax` pushed only 2 bytes -- misaligning the stack against a 32-bit popfd
    // (as aPACK's CPU/anti-debug check does). In 64-bit mode PUSH/POP default to 8 (0x66 -> 2),
    // and REX.W has no effect.
    if (m_nBits == 64) {
        return dec.bOpSize16 ? 2 : 8;
    }
    return dec.nOpSize;
}

// --- Translator --------------------------------------------------------------

quint8 XEmuX86::_fetch8(DEC &dec)
{
    bool bOk = false;
    // Code fetches wrap at 1 MiB in real mode exactly like data accesses (see _wrapA20): a program
    // whose CS:IP arithmetic overflows -- MASK jumps past the top -- must execute from low memory,
    // not fault at the end of the mapped region.
    quint8 nValue = m_pMemoryManager->fetchByte(_wrapA20(dec.nFetch), &bOk);
    if (!bOk) {
        dec.bFault = true;
    }
    dec.nFetch += 1;
    return nValue;
}

quint16 XEmuX86::_fetch16(DEC &dec)
{
    bool bOk = false;
    quint16 nValue = m_pMemoryManager->fetchWord(dec.nFetch, &bOk);
    if (!bOk) {
        dec.bFault = true;
    }
    dec.nFetch += 2;
    return nValue;
}

quint32 XEmuX86::_fetch32(DEC &dec)
{
    bool bOk = false;
    quint32 nValue = m_pMemoryManager->fetchDword(dec.nFetch, &bOk);
    if (!bOk) {
        dec.bFault = true;
    }
    dec.nFetch += 4;
    return nValue;
}

quint64 XEmuX86::_fetch64(DEC &dec)
{
    bool bOk = false;
    quint64 nValue = m_pMemoryManager->fetchQword(dec.nFetch, &bOk);
    if (!bOk) {
        dec.bFault = true;
    }
    dec.nFetch += 8;
    return nValue;
}

void XEmuX86::_decodeModRM(DEC &dec, int &nRegField, XEmuOperand &rm)
{
    quint8 nModRM = _fetch8(dec);
    int nMod = nModRM >> 6;
    int nReg = (nModRM >> 3) & 7;
    int nRM = nModRM & 7;

    nRegField = nReg + (dec.bRexR ? 8 : 0);

    rm = XEmuOperand();
    rm.nSegSource = dec.nSegSource;

    if (nMod == 3) {
        rm.bIsReg = true;
        rm.nReg = nRM + (dec.bRexB ? 8 : 0);
        return;
    }

    rm.bIsMem = true;

    // 16-bit (real-mode) addressing uses fixed base+index register pairs and 16-bit
    // displacements, and has no SIB byte.
    if (dec.nAddrSize == 2) {
        switch (nRM) {
            case 0: rm.nBaseReg = XEmuRegisters::GPR_RBX; rm.nIndexReg = XEmuRegisters::GPR_RSI; break;  // [BX+SI]
            case 1: rm.nBaseReg = XEmuRegisters::GPR_RBX; rm.nIndexReg = XEmuRegisters::GPR_RDI; break;  // [BX+DI]
            case 2: rm.nBaseReg = XEmuRegisters::GPR_RBP; rm.nIndexReg = XEmuRegisters::GPR_RSI; break;  // [BP+SI]
            case 3: rm.nBaseReg = XEmuRegisters::GPR_RBP; rm.nIndexReg = XEmuRegisters::GPR_RDI; break;  // [BP+DI]
            case 4: rm.nBaseReg = XEmuRegisters::GPR_RSI; break;                                          // [SI]
            case 5: rm.nBaseReg = XEmuRegisters::GPR_RDI; break;                                          // [DI]
            case 6:
                if (nMod == 0) {
                    rm.nDisp = (qint16)_fetch16(dec);  // [disp16]
                } else {
                    rm.nBaseReg = XEmuRegisters::GPR_RBP;  // [BP]
                }
                break;
            case 7: rm.nBaseReg = XEmuRegisters::GPR_RBX; break;  // [BX]
        }
        rm.nScale = 1;

        if (nMod == 1) {
            rm.nDisp += (qint8)_fetch8(dec);
        } else if (nMod == 2) {
            rm.nDisp += (qint16)_fetch16(dec);
        }
        return;
    }

    if (nRM == 4) {
        // SIB byte.
        quint8 nSIB = _fetch8(dec);
        int nScale = 1 << (nSIB >> 6);
        int nIndexField = (nSIB >> 3) & 7;
        int nIndex = nIndexField + (dec.bRexX ? 8 : 0);
        int nBase = (nSIB & 7) + (dec.bRexB ? 8 : 0);

        if (!((nIndexField == 4) && !dec.bRexX)) {  // index==RSP means "no index"
            rm.nIndexReg = nIndex;
            rm.nScale = nScale;
        }

        if (((nSIB & 7) == 5) && (nMod == 0)) {
            rm.nDisp = (qint32)_fetch32(dec);
        } else {
            rm.nBaseReg = nBase;
        }
    } else if ((nRM == 5) && (nMod == 0)) {
        qint32 nDisp = (qint32)_fetch32(dec);
        if (dec.nAddrSize == 8) {
            rm.bRipRel = true;  // RIP-relative in long mode
            rm.nDisp = nDisp;
        } else {
            rm.nDisp = (quint32)nDisp;  // absolute disp32 in 32-bit mode
        }
    } else {
        rm.nBaseReg = nRM + (dec.bRexB ? 8 : 0);
    }

    if (nMod == 1) {
        rm.nDisp += (qint8)_fetch8(dec);
    } else if (nMod == 2) {
        rm.nDisp += (qint32)_fetch32(dec);
    }
}

void XEmuX86::_decodeTwoByte(DEC &dec, XEmuMicroOp &op)
{
    quint8 nOpcode = _fetch8(dec);

    if (nOpcode == 0x00) {
        // Group 6: sldt/str/lldt/ltr/verr/verw. Anti-debug stubs read the LDT selector (sldt /0)
        // and task register (str /1) -- in real mode both are 0. lldt/ltr are benign no-ops here;
        // verr/verw (segment verify) are treated as no-ops.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        if ((nRegField == 0) || (nRegField == 1)) {  // sldt / str -> store 0
            op.kind = MOP_MOV_IMM;
            op.dst = rm;
            op.nSize = rm.bIsReg ? dec.nOpSize : 2;
            op.nImm = 0;
            op.sText = (nRegField == 0) ? QStringLiteral("sldt") : QStringLiteral("str");
        } else {
            op.kind = MOP_NOP;
            op.sText = QStringLiteral("grp6");
        }
    } else if (nOpcode == 0x01) {
        // Group 7: sgdt/sidt/lgdt/lidt/smsw/lmsw/invlpg. Only smsw (/4) matters for the real-mode
        // CPU/mode detection these packers do (they read the machine status word and test the PE
        // bit); the descriptor-table and lmsw forms are benign no-ops in this real-mode model.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        if (nRegField == 4) {  // smsw r/m16
            op.kind = MOP_SMSW;
            op.dst = rm;
            op.nSize = rm.bIsReg ? dec.nOpSize : 2;
            op.sText = QStringLiteral("smsw");
        } else {
            op.kind = MOP_NOP;
            op.sText = QStringLiteral("grp7");
        }
    } else if ((nOpcode == 0x02) || (nOpcode == 0x03)) {
        // LAR (0F 02) / LSL (0F 03) r32, r/m: load a selector's access-rights byte / segment
        // limit and set ZF when the selector is valid. Anti-debug/timing stubs (NsAnti, ...)
        // run these; a flat Win32 process's user selectors are valid, so return the flat values
        // (LSL -> 4GB limit; LAR -> a user code-segment AR) with ZF=1, matching an un-instrumented run.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_LSL;
        op.dst = XEmuOperand::reg(nRegField);
        op.nSize = dec.nOpSize;
        op.nImm = (nOpcode == 0x03) ? 0xFFFFFFFFu : 0x00CFFB00u;
        op.sText = (nOpcode == 0x03) ? QStringLiteral("lsl") : QStringLiteral("lar");
    } else if (nOpcode == 0x20) {
        // mov r32, crN (0F 20): read a control register. Real-mode packers read CR0 to check the
        // PE/PG bits; return the real-mode value. mov crN, r32 (0F 22) is a benign no-op here.
        int nCr = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nCr, rm);
        op.kind = MOP_MOVFROMCR;
        op.dst = rm;
        op.nAluOp = nCr;  // control-register number
        op.nSize = 4;
        op.sText = QStringLiteral("mov r,cr");
    } else if (nOpcode == 0x22) {
        int nCr = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nCr, rm);
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("mov cr,r");
    } else if (nOpcode == 0x21) {
        // mov r32, DRx (0F 21): read a debug register. Anti-debug stubs read DR0..DR7 and
        // check for hardware breakpoints; with no debugger every debug register reads 0.
        int nDr = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nDr, rm);
        op.kind = MOP_MOVDR;
        op.dst = rm;
        op.nAluOp = nDr & 7;
        op.nCond = 0;  // read
        op.nSize = 4;
        op.sText = QStringLiteral("mov r,dr");
    } else if (nOpcode == 0x23) {
        // mov DRx, r32 (0F 23): set a debug register -- a benign no-op in this model.
        int nDr = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nDr, rm);
        op.kind = MOP_MOVDR;
        op.src = rm;
        op.nAluOp = nDr & 7;
        op.nCond = 1;  // write
        op.nSize = 4;
        op.sText = QStringLiteral("mov dr,r");
    } else if ((nOpcode == 0xA0) || (nOpcode == 0xA8)) {
        // push fs (0F A0) / push gs (0F A8)
        op.kind = MOP_PUSHSEG;
        op.nAluOp = (nOpcode == 0xA0) ? 4 : 5;  // 4 FS, 5 GS
        op.sText = (nOpcode == 0xA0) ? QStringLiteral("push fs") : QStringLiteral("push gs");
    } else if ((nOpcode == 0xA1) || (nOpcode == 0xA9)) {
        // pop fs (0F A1) / pop gs (0F A9)
        op.kind = MOP_POPSEG;
        op.nAluOp = (nOpcode == 0xA1) ? 4 : 5;  // 4 FS, 5 GS
        op.sText = (nOpcode == 0xA1) ? QStringLiteral("pop fs") : QStringLiteral("pop gs");
    } else if ((nOpcode == 0xB2) || (nOpcode == 0xB4) || (nOpcode == 0xB5)) {
        // lss (0F B2) / lfs (0F B4) / lgs (0F B5): load a far pointer into a GP reg + SS/FS/GS.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_LOADFAR;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.nCond = (nOpcode == 0xB2) ? 2 : (nOpcode == 0xB4) ? 3 : 4;  // 2 SS, 3 FS, 4 GS
        op.sText = (nOpcode == 0xB2) ? QStringLiteral("lss") : (nOpcode == 0xB4) ? QStringLiteral("lfs") : QStringLiteral("lgs");
    } else if (nOpcode == 0x0B) {
        // ud2 (0F 0B): raises #UD / STATUS_ILLEGAL_INSTRUCTION. Route through the
        // software-interrupt path with vector 6 so the OS personality can dispatch it via
        // SEH. Packers (PeX, ...) execute ud2 on purpose and catch it with their own
        // handler as a control-flow / anti-debug trick, just like int3.
        op.kind = MOP_SYSCALL;
        op.nImm = 6;
        op.nAluOp = 2;  // general software interrupt
        op.sText = QStringLiteral("ud2");
    } else if ((nOpcode >= 0x80) && (nOpcode <= 0x8F)) {
        // Near Jcc: rel16 with a 16-bit operand size, rel32 otherwise.
        qint32 nRel = (dec.nOpSize == 2) ? (qint32)(qint16)_fetch16(dec) : (qint32)_fetch32(dec);
        op.kind = MOP_JCC;
        op.nCond = nOpcode - 0x80;
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = QStringLiteral("jcc");
    } else if ((nOpcode >= 0x40) && (nOpcode <= 0x4F)) {
        // cmovcc reg, r/m
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_CMOVCC;
        op.nCond = nOpcode - 0x40;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("cmovcc");
    } else if ((nOpcode >= 0x90) && (nOpcode <= 0x9F)) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_SETCC;
        op.nCond = nOpcode - 0x90;
        op.dst = rm;
        op.nSize = 1;
        op.sText = QStringLiteral("setcc");
    } else if ((nOpcode == 0xB6) || (nOpcode == 0xB7) || (nOpcode == 0xBE) || (nOpcode == 0xBF)) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = ((nOpcode == 0xBE) || (nOpcode == 0xBF)) ? MOP_MOVSX : MOP_MOVZX;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSrcSize = ((nOpcode == 0xB6) || (nOpcode == 0xBE)) ? 1 : 2;
        op.nSize = dec.nOpSize;
        op.sText = (op.kind == MOP_MOVSX) ? QStringLiteral("movsx") : QStringLiteral("movzx");
    } else if (nOpcode == 0x1F) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("nop");
    } else if (nOpcode == 0x1E) {
        _fetch8(dec);  // endbr32/endbr64 (with F3 prefix) -> nop
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("nop");
    } else if (nOpcode == 0x05) {
        op.kind = MOP_SYSCALL;
        op.nAluOp = 0;
        op.sText = QStringLiteral("syscall");
    } else if (nOpcode == 0x31) {
        op.kind = MOP_RDTSC;
        op.sText = QStringLiteral("rdtsc");
    } else if (nOpcode == 0xA2) {
        op.kind = MOP_CPUID;
        op.sText = QStringLiteral("cpuid");
    } else if (nOpcode == 0xAF) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_IMUL2;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSrcSize = 0;  // two-operand form (no immediate)
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("imul");
    } else if ((nOpcode == 0xB0) || (nOpcode == 0xB1)) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_CMPXCHG;
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = (nOpcode == 0xB0) ? 1 : dec.nOpSize;
        op.sText = QStringLiteral("cmpxchg");
    } else if ((nOpcode == 0xC0) || (nOpcode == 0xC1)) {
        // XADD r/m, reg. dst = r/m (destination), src = reg. 0xC0 is the byte form.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_XADD;
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = (nOpcode == 0xC0) ? 1 : dec.nOpSize;
        op.sText = QStringLiteral("xadd");
    } else if ((nOpcode == 0xBC) || (nOpcode == 0xBD)) {
        // BSF/BSR reg, r/m -- bit scan forward/reverse. dst = bit index of the lowest
        // (BSF) or highest (BSR) set bit of src; ZF flags a zero source. (Plain BSF/BSR;
        // the F3-prefixed TZCNT/LZCNT variants are not distinguished here.)
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = (nOpcode == 0xBC) ? MOP_BSF : MOP_BSR;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.sText = (nOpcode == 0xBC) ? QStringLiteral("bsf") : QStringLiteral("bsr");
    } else if ((nOpcode >= 0xC8) && (nOpcode <= 0xCF)) {
        op.kind = MOP_BSWAP;
        op.dst = XEmuOperand::reg((nOpcode - 0xC8) + (dec.bRexB ? 8 : 0));
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("bswap");
    } else if (_decodeSSE(dec, op, nOpcode)) {
        // XMM instruction.
    } else if (_decodeMMX(dec, op, nOpcode)) {
        // MMX packed-integer instruction (handled).
    } else if ((nOpcode == 0xA4) || (nOpcode == 0xA5) || (nOpcode == 0xAC) || (nOpcode == 0xAD)) {
        // SHLD/SHRD r/m, reg, imm8|CL -- double-precision shift. reg is the fill source.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_SHIFTD;
        op.nAluOp = ((nOpcode == 0xA4) || (nOpcode == 0xA5)) ? 0 : 1;  // 0 SHLD, 1 SHRD
        op.nCond = ((nOpcode == 0xA5) || (nOpcode == 0xAD)) ? 1 : 0;   // 1 = CL, 0 = imm8
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = dec.nOpSize;
        if (op.nCond == 0) {
            op.nImm = _fetch8(dec);  // imm8 count (A4/AC) follows the ModR/M
        }
        op.sText = (op.nAluOp == 0) ? QStringLiteral("shld") : QStringLiteral("shrd");
    } else if ((nOpcode == 0xA3) || (nOpcode == 0xAB) || (nOpcode == 0xB3) || (nOpcode == 0xBB)) {
        // BT/BTS/BTR/BTC r/m, reg -- bit index in a register (signed offset for memory).
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_BT;
        op.nAluOp = (nOpcode == 0xA3) ? 0 : (nOpcode == 0xAB) ? 1 : (nOpcode == 0xB3) ? 2 : 3;
        op.nCond = 1;  // register bit index
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("bt-group");
    } else if (nOpcode == 0xBA) {
        // Group 8: BT/BTS/BTR/BTC r/m, imm8. ModR/M reg field selects: /4 BT, /5 BTS,
        // /6 BTR, /7 BTC; /0../3 are reserved. The reg field here is an opcode extension,
        // not a register, so REX.R must be ignored -- mask it back off (_decodeModRM folds
        // REX.R into nRegField).
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        const int nExt = nRegField & 7;
        op.nImm = _fetch8(dec);
        if (nExt >= 4) {
            op.kind = MOP_BT;
            op.nAluOp = nExt - 4;  // 0 BT .. 3 BTC
            op.nCond = 0;          // immediate bit index
            op.dst = rm;
            op.nSize = dec.nOpSize;
            op.sText = QStringLiteral("bt-group");
        } else {
            op.kind = MOP_UNIMPL;
            op.sText = QStringLiteral("db 0f ba /%1").arg(nExt);
        }
    } else {
        op.kind = MOP_UNIMPL;
        op.sText = QString("db 0f %1").arg(nOpcode, 2, 16, QChar('0'));
    }
}

// --- MMX -------------------------------------------------------------------

namespace {

// MMX operation ids carried in XEmuMicroOp::nAluOp for MOP_MMX. The shift ops are kept
// contiguous (MMX_PSLLW..MMX_PSRAD) so the interpreter can range-test them.
enum MMXOP {
    MMX_PAND, MMX_PANDN, MMX_POR, MMX_PXOR,
    MMX_PADDB, MMX_PADDW, MMX_PADDD, MMX_PADDQ,
    MMX_PADDSB, MMX_PADDSW, MMX_PADDUSB, MMX_PADDUSW,
    MMX_PSUBB, MMX_PSUBW, MMX_PSUBD, MMX_PSUBQ,
    MMX_PSUBSB, MMX_PSUBSW, MMX_PSUBUSB, MMX_PSUBUSW,
    MMX_PCMPEQB, MMX_PCMPEQW, MMX_PCMPEQD,
    MMX_PCMPGTB, MMX_PCMPGTW, MMX_PCMPGTD,
    MMX_PACKSSWB, MMX_PACKSSDW, MMX_PACKUSWB,
    MMX_PUNPCKLBW, MMX_PUNPCKLWD, MMX_PUNPCKLDQ,
    MMX_PUNPCKHBW, MMX_PUNPCKHWD, MMX_PUNPCKHDQ,
    MMX_PMULLW, MMX_PMULHW, MMX_PMULHUW, MMX_PMADDWD,
    MMX_PAVGB, MMX_PAVGW, MMX_PMINUB, MMX_PMAXUB, MMX_PMINSW, MMX_PMAXSW, MMX_PSADBW,
    MMX_PSLLW, MMX_PSLLD, MMX_PSLLQ, MMX_PSRLW, MMX_PSRLD, MMX_PSRLQ, MMX_PSRAW, MMX_PSRAD,  // shifts (contiguous)
    MMX_PSHUFW, MMX_EMMS,
    MMX_MOVD_TO, MMX_MOVD_FROM, MMX_MOVQ_TO, MMX_MOVQ_FROM
};

enum SSEOP {
    SSE_MOV128_LOAD, SSE_MOV128_STORE, SSE_MOV_SCALAR_LOAD, SSE_MOV_SCALAR_STORE,
    SSE_PXOR, SSE_PCMPEQD, SSE_AND, SSE_PUNPCKLQDQ,
    SSE_UCOMI, SSE_ADD, SSE_MUL, SSE_DIV, SSE_CVTSI2FP, SSE_CVTTFP2SI,
    SSE_MOV_GPR_TO_XMM, SSE_MOV_XMM_TO_GPR, SSE_MOVQ_LOAD, SSE_MOVQ_STORE,
    SSE_MOVHPS_LOAD, SSE_MOVHPS_STORE
};

inline bool mmxIsShift(int nOp) { return (nOp >= MMX_PSLLW) && (nOp <= MMX_PSRAD); }

inline quint8 msatU8(qint32 v) { return (quint8)(v < 0 ? 0 : (v > 255 ? 255 : v)); }
inline quint8 msatS8(qint32 v) { return (quint8)(qint8)(v < -128 ? -128 : (v > 127 ? 127 : v)); }
inline quint16 msatU16(qint32 v) { return (quint16)(v < 0 ? 0 : (v > 65535 ? 65535 : v)); }
inline quint16 msatS16(qint32 v) { return (quint16)(qint16)(v < -32768 ? -32768 : (v > 32767 ? 32767 : v)); }

inline quint8 gB(quint64 v, int i) { return (quint8)(v >> (i * 8)); }
inline quint16 gW(quint64 v, int i) { return (quint16)(v >> (i * 16)); }
inline quint32 gD(quint64 v, int i) { return (quint32)(v >> (i * 32)); }

}  // namespace

bool XEmuX86::_decodeSSE(DEC &dec, XEmuMicroOp &op, quint8 opcode)
{
    const bool p66 = dec.bOpSize16;
    const int rep = dec.nRep;
    int operation = -1;
    int width = 16;
    QString mnemonic;
    switch (opcode) {
        case 0x10:
        case 0x11:
            operation = opcode == 0x10 ? SSE_MOV128_LOAD : SSE_MOV128_STORE;
            if (rep != 0) {
                operation = opcode == 0x10 ? SSE_MOV_SCALAR_LOAD : SSE_MOV_SCALAR_STORE;
                width = rep == 1 ? 4 : 8;
                mnemonic = rep == 1 ? QStringLiteral("movss") : QStringLiteral("movsd");
            } else {
                mnemonic = p66 ? QStringLiteral("movupd") : QStringLiteral("movups");
            }
            break;
        case 0x28:
        case 0x29:
            if (rep != 0) return false;
            operation = opcode == 0x28 ? SSE_MOV128_LOAD : SSE_MOV128_STORE;
            mnemonic = p66 ? QStringLiteral("movapd") : QStringLiteral("movaps");
            break;
        case 0x6F:
        case 0x7F:
            if (!p66 && rep != 1) return false;
            operation = opcode == 0x6F ? SSE_MOV128_LOAD : SSE_MOV128_STORE;
            mnemonic = p66 ? QStringLiteral("movdqa") : QStringLiteral("movdqu");
            break;
        case 0x6E:
            if (!p66 || rep != 0) return false;
            operation = SSE_MOV_GPR_TO_XMM;
            width = dec.bRexW ? 8 : 4;
            mnemonic = dec.bRexW ? QStringLiteral("movq") : QStringLiteral("movd");
            break;
        case 0x7E:
            if (p66 && rep == 0) {
                operation = SSE_MOV_XMM_TO_GPR;
                width = dec.bRexW ? 8 : 4;
            } else if (rep == 1 && !p66) {
                operation = SSE_MOVQ_LOAD;
                width = 8;
            } else return false;
            mnemonic = width == 8 ? QStringLiteral("movq") : QStringLiteral("movd");
            break;
        case 0xD6:
            if (!p66 || rep != 0) return false;
            operation = SSE_MOVQ_STORE; width = 8; mnemonic = QStringLiteral("movq"); break;
        case 0x16:
        case 0x17:
            if (rep != 0 || p66) return false;
            operation = opcode == 0x16 ? SSE_MOVHPS_LOAD : SSE_MOVHPS_STORE;
            width = 8; mnemonic = QStringLiteral("movhps"); break;
        case 0xEF:
            if (!p66 || rep != 0) return false;
            operation = SSE_PXOR; mnemonic = QStringLiteral("pxor"); break;
        case 0x76:
            if (!p66 || rep != 0) return false;
            operation = SSE_PCMPEQD; mnemonic = QStringLiteral("pcmpeqd"); break;
        case 0x54:
            if (rep != 0) return false;
            operation = SSE_AND; mnemonic = p66 ? QStringLiteral("andpd") : QStringLiteral("andps"); break;
        case 0x6C:
            if (!p66 || rep != 0) return false;
            operation = SSE_PUNPCKLQDQ; mnemonic = QStringLiteral("punpcklqdq"); break;
        case 0x2E:
        case 0x2F:
            if (rep != 0) return false;
            operation = SSE_UCOMI; width = p66 ? 8 : 4;
            mnemonic = p66 ? QStringLiteral("ucomisd") : QStringLiteral("ucomiss"); break;
        case 0x58:
        case 0x59:
        case 0x5E:
            if (rep == 0) return false;
            operation = opcode == 0x58 ? SSE_ADD : opcode == 0x59 ? SSE_MUL : SSE_DIV;
            width = rep == 1 ? 4 : 8;
            mnemonic = opcode == 0x58 ? (rep == 1 ? QStringLiteral("addss") : QStringLiteral("addsd"))
                       : opcode == 0x59 ? (rep == 1 ? QStringLiteral("mulss") : QStringLiteral("mulsd"))
                                       : (rep == 1 ? QStringLiteral("divss") : QStringLiteral("divsd"));
            break;
        case 0x2A:
            if (rep == 0) return false;
            operation = SSE_CVTSI2FP; width = rep == 1 ? 4 : 8;
            mnemonic = rep == 1 ? QStringLiteral("cvtsi2ss") : QStringLiteral("cvtsi2sd"); break;
        case 0x2C:
            if (rep == 0) return false;
            operation = SSE_CVTTFP2SI; width = rep == 1 ? 4 : 8;
            mnemonic = rep == 1 ? QStringLiteral("cvttss2si") : QStringLiteral("cvttsd2si"); break;
        default: return false;
    }

    int reg = 0;
    XEmuOperand rm;
    _decodeModRM(dec, reg, rm);
    if ((operation == SSE_MOVHPS_LOAD || operation == SSE_MOVHPS_STORE) && rm.bIsReg) return false;
    const XEmuOperand xmmReg = XEmuOperand::xmm(reg);
    const XEmuOperand xmmRm = rm.bIsReg ? XEmuOperand::xmm(rm.nReg) : rm;
    op.kind = MOP_SSE;
    op.nAluOp = operation;
    op.nSize = width;
    op.nSrcSize = dec.bRexW ? 8 : 4;
    op.sText = mnemonic;
    if (operation == SSE_CVTSI2FP || operation == SSE_MOV_GPR_TO_XMM) {
        op.dst = xmmReg;
        op.src = rm;
    } else if (operation == SSE_CVTTFP2SI || operation == SSE_MOV_XMM_TO_GPR) {
        op.dst = XEmuOperand::reg(reg);
        op.src = operation == SSE_CVTTFP2SI ? xmmRm : xmmReg;
        if (operation == SSE_MOV_XMM_TO_GPR) op.dst = rm;
    } else if (operation == SSE_MOV128_STORE || operation == SSE_MOV_SCALAR_STORE ||
               operation == SSE_MOVQ_STORE || operation == SSE_MOVHPS_STORE) {
        op.dst = xmmRm;
        op.src = xmmReg;
    } else {
        op.dst = xmmReg;
        op.src = xmmRm;
    }
    return true;
}

bool XEmuX86::_decodeMMX(DEC &dec, XEmuMicroOp &op, quint8 nOpcode)
{
    // A mandatory 66/F2/F3 prefix on these two-byte opcodes selects the SSE/SSE2 (XMM)
    // form, which is a *different* instruction on a 128-bit register file we do not model.
    // Refuse to decode it as MMX -- returning false lets it fall through to MOP_UNIMPL so
    // it stops honestly instead of silently corrupting an mm register.
    if (dec.bOpSize16 || (dec.nRep != 0)) {
        return false;
    }

    int nRegField = 0;
    XEmuOperand rm;

    switch (nOpcode) {
        case 0x6E:  // MOVD mm, r/m32  (REX.W -> MOVQ mm, r/m64)
            _decodeModRM(dec, nRegField, rm);
            op.kind = MOP_MMX;
            op.nAluOp = MMX_MOVD_TO;
            op.dst = XEmuOperand::mmx(nRegField);
            op.src = rm;  // r/m32 or (REX.W) r/m64
            op.nSize = 8;
            op.nSrcSize = dec.bRexW ? 8 : 4;
            op.sText = QStringLiteral("movd");
            return true;
        case 0x7E:  // MOVD r/m32, mm  (REX.W -> MOVQ r/m64, mm)
            _decodeModRM(dec, nRegField, rm);
            op.kind = MOP_MMX;
            op.nAluOp = MMX_MOVD_FROM;
            op.dst = rm;  // r/m32 or (REX.W) r/m64
            op.src = XEmuOperand::mmx(nRegField);
            op.nSize = dec.bRexW ? 8 : 4;
            op.sText = QStringLiteral("movd");
            return true;
        case 0x6F:  // MOVQ mm, mm/m64
            _decodeModRM(dec, nRegField, rm);
            op.kind = MOP_MMX;
            op.nAluOp = MMX_MOVQ_TO;
            op.dst = XEmuOperand::mmx(nRegField);
            op.src = rm.bIsReg ? XEmuOperand::mmx(rm.nReg) : rm;
            op.nSize = 8;
            op.sText = QStringLiteral("movq");
            return true;
        case 0x7F:  // MOVQ mm/m64, mm
            _decodeModRM(dec, nRegField, rm);
            op.kind = MOP_MMX;
            op.nAluOp = MMX_MOVQ_FROM;
            op.dst = rm.bIsReg ? XEmuOperand::mmx(rm.nReg) : rm;
            op.src = XEmuOperand::mmx(nRegField);
            op.nSize = 8;
            op.sText = QStringLiteral("movq");
            return true;
        case 0x77:  // EMMS
            op.kind = MOP_MMX;
            op.nAluOp = MMX_EMMS;
            op.sText = QStringLiteral("emms");
            return true;
        case 0x70:  // PSHUFW mm, mm/m64, imm8
            _decodeModRM(dec, nRegField, rm);
            op.nImm = _fetch8(dec);
            op.kind = MOP_MMX;
            op.nAluOp = MMX_PSHUFW;
            op.dst = XEmuOperand::mmx(nRegField);
            op.src = rm.bIsReg ? XEmuOperand::mmx(rm.nReg) : rm;
            op.nSize = 8;
            op.sText = QStringLiteral("pshufw");
            return true;
        case 0x71:
        case 0x72:
        case 0x73: {  // PSxxW/D/Q mm, imm8 -- shift group (reg field selects)
            _decodeModRM(dec, nRegField, rm);
            op.nImm = _fetch8(dec);
            const int nSub = nRegField & 7;
            int nOp = -1;
            if (nOpcode == 0x71) {
                nOp = (nSub == 2) ? MMX_PSRLW : (nSub == 4) ? MMX_PSRAW : (nSub == 6) ? MMX_PSLLW : -1;
            } else if (nOpcode == 0x72) {
                nOp = (nSub == 2) ? MMX_PSRLD : (nSub == 4) ? MMX_PSRAD : (nSub == 6) ? MMX_PSLLD : -1;
            } else {
                nOp = (nSub == 2) ? MMX_PSRLQ : (nSub == 6) ? MMX_PSLLQ : -1;  // no arithmetic shift for Q
            }
            if (nOp < 0) {
                op.kind = MOP_UNIMPL;
                op.sText = QStringLiteral("db 0f %1 /%2").arg(nOpcode, 2, 16, QChar('0')).arg(nSub);
                return true;
            }
            op.kind = MOP_MMX;
            op.nAluOp = nOp;
            op.nCond = 1;  // count is imm8
            op.dst = XEmuOperand::mmx(rm.nReg);  // the r/m must be a register
            op.nSize = 8;
            op.sText = QStringLiteral("psh-imm");
            return true;
        }
        default:
            break;
    }

    // Generic form: dst = mm(reg), src = mm/m64 (for shifts, src is the count).
    int nOp = -1;
    switch (nOpcode) {
        case 0x60: nOp = MMX_PUNPCKLBW; break;
        case 0x61: nOp = MMX_PUNPCKLWD; break;
        case 0x62: nOp = MMX_PUNPCKLDQ; break;
        case 0x63: nOp = MMX_PACKSSWB; break;
        case 0x64: nOp = MMX_PCMPGTB; break;
        case 0x65: nOp = MMX_PCMPGTW; break;
        case 0x66: nOp = MMX_PCMPGTD; break;
        case 0x67: nOp = MMX_PACKUSWB; break;
        case 0x68: nOp = MMX_PUNPCKHBW; break;
        case 0x69: nOp = MMX_PUNPCKHWD; break;
        case 0x6A: nOp = MMX_PUNPCKHDQ; break;
        case 0x6B: nOp = MMX_PACKSSDW; break;
        case 0x74: nOp = MMX_PCMPEQB; break;
        case 0x75: nOp = MMX_PCMPEQW; break;
        case 0x76: nOp = MMX_PCMPEQD; break;
        case 0xD1: nOp = MMX_PSRLW; break;
        case 0xD2: nOp = MMX_PSRLD; break;
        case 0xD3: nOp = MMX_PSRLQ; break;
        case 0xD4: nOp = MMX_PADDQ; break;
        case 0xD5: nOp = MMX_PMULLW; break;
        case 0xD8: nOp = MMX_PSUBUSB; break;
        case 0xD9: nOp = MMX_PSUBUSW; break;
        case 0xDA: nOp = MMX_PMINUB; break;
        case 0xDB: nOp = MMX_PAND; break;
        case 0xDC: nOp = MMX_PADDUSB; break;
        case 0xDD: nOp = MMX_PADDUSW; break;
        case 0xDE: nOp = MMX_PMAXUB; break;
        case 0xDF: nOp = MMX_PANDN; break;
        case 0xE0: nOp = MMX_PAVGB; break;
        case 0xE1: nOp = MMX_PSRAW; break;
        case 0xE2: nOp = MMX_PSRAD; break;
        case 0xE3: nOp = MMX_PAVGW; break;
        case 0xE4: nOp = MMX_PMULHUW; break;
        case 0xE5: nOp = MMX_PMULHW; break;
        case 0xE8: nOp = MMX_PSUBSB; break;
        case 0xE9: nOp = MMX_PSUBSW; break;
        case 0xEA: nOp = MMX_PMINSW; break;
        case 0xEB: nOp = MMX_POR; break;
        case 0xEC: nOp = MMX_PADDSB; break;
        case 0xED: nOp = MMX_PADDSW; break;
        case 0xEE: nOp = MMX_PMAXSW; break;
        case 0xEF: nOp = MMX_PXOR; break;
        case 0xF1: nOp = MMX_PSLLW; break;
        case 0xF2: nOp = MMX_PSLLD; break;
        case 0xF3: nOp = MMX_PSLLQ; break;
        case 0xF5: nOp = MMX_PMADDWD; break;
        case 0xF6: nOp = MMX_PSADBW; break;
        case 0xF8: nOp = MMX_PSUBB; break;
        case 0xF9: nOp = MMX_PSUBW; break;
        case 0xFA: nOp = MMX_PSUBD; break;
        case 0xFB: nOp = MMX_PSUBQ; break;
        case 0xFC: nOp = MMX_PADDB; break;
        case 0xFD: nOp = MMX_PADDW; break;
        case 0xFE: nOp = MMX_PADDD; break;
        default: return false;  // not an MMX opcode
    }

    _decodeModRM(dec, nRegField, rm);
    op.kind = MOP_MMX;
    op.nAluOp = nOp;
    op.dst = XEmuOperand::mmx(nRegField);
    op.src = rm.bIsReg ? XEmuOperand::mmx(rm.nReg) : rm;
    op.nSize = 8;
    op.sText = QStringLiteral("mmx");
    return true;
}

quint64 XEmuX86::_readMMX(const XEmuMicroOp &op, const XEmuOperand &opnd)
{
    if (opnd.bIsReg) {
        return m_pExecRegs->nMMX[opnd.nReg & 7];
    }
    return _memReadSized(_resolveAddr(op, opnd), 8);
}

void XEmuX86::_writeMMX(const XEmuMicroOp &op, const XEmuOperand &opnd, quint64 nValue)
{
    if (opnd.bIsReg) {
        m_pExecRegs->nMMX[opnd.nReg & 7] = nValue;
        return;
    }
    _memWriteSized(_resolveAddr(op, opnd), nValue, 8);
}

quint64 XEmuX86::_mmxALU(int nOp, quint64 a, quint64 b)
{
    quint64 r = 0;

    switch (nOp) {
        case MMX_PAND: return a & b;
        case MMX_PANDN: return (~a) & b;
        case MMX_POR: return a | b;
        case MMX_PXOR: return a ^ b;

        // ---- byte lanes (8) ----
        case MMX_PADDB: for (int i = 0; i < 8; i++) r |= (quint64)(quint8)(gB(a, i) + gB(b, i)) << (i * 8); return r;
        case MMX_PSUBB: for (int i = 0; i < 8; i++) r |= (quint64)(quint8)(gB(a, i) - gB(b, i)) << (i * 8); return r;
        case MMX_PADDSB: for (int i = 0; i < 8; i++) r |= (quint64)msatS8((qint8)gB(a, i) + (qint8)gB(b, i)) << (i * 8); return r;
        case MMX_PSUBSB: for (int i = 0; i < 8; i++) r |= (quint64)msatS8((qint8)gB(a, i) - (qint8)gB(b, i)) << (i * 8); return r;
        case MMX_PADDUSB: for (int i = 0; i < 8; i++) r |= (quint64)msatU8((qint32)gB(a, i) + (qint32)gB(b, i)) << (i * 8); return r;
        case MMX_PSUBUSB: for (int i = 0; i < 8; i++) r |= (quint64)msatU8((qint32)gB(a, i) - (qint32)gB(b, i)) << (i * 8); return r;
        case MMX_PCMPEQB: for (int i = 0; i < 8; i++) r |= (quint64)(gB(a, i) == gB(b, i) ? 0xFF : 0x00) << (i * 8); return r;
        case MMX_PCMPGTB: for (int i = 0; i < 8; i++) r |= (quint64)((qint8)gB(a, i) > (qint8)gB(b, i) ? 0xFF : 0x00) << (i * 8); return r;
        case MMX_PMINUB: for (int i = 0; i < 8; i++) r |= (quint64)(gB(a, i) < gB(b, i) ? gB(a, i) : gB(b, i)) << (i * 8); return r;
        case MMX_PMAXUB: for (int i = 0; i < 8; i++) r |= (quint64)(gB(a, i) > gB(b, i) ? gB(a, i) : gB(b, i)) << (i * 8); return r;
        case MMX_PAVGB: for (int i = 0; i < 8; i++) r |= (quint64)(quint8)(((qint32)gB(a, i) + gB(b, i) + 1) >> 1) << (i * 8); return r;

        // ---- word lanes (4) ----
        case MMX_PADDW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(gW(a, i) + gW(b, i)) << (i * 16); return r;
        case MMX_PSUBW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(gW(a, i) - gW(b, i)) << (i * 16); return r;
        case MMX_PADDSW: for (int i = 0; i < 4; i++) r |= (quint64)msatS16((qint16)gW(a, i) + (qint16)gW(b, i)) << (i * 16); return r;
        case MMX_PSUBSW: for (int i = 0; i < 4; i++) r |= (quint64)msatS16((qint16)gW(a, i) - (qint16)gW(b, i)) << (i * 16); return r;
        case MMX_PADDUSW: for (int i = 0; i < 4; i++) r |= (quint64)msatU16((qint32)gW(a, i) + (qint32)gW(b, i)) << (i * 16); return r;
        case MMX_PSUBUSW: for (int i = 0; i < 4; i++) r |= (quint64)msatU16((qint32)gW(a, i) - (qint32)gW(b, i)) << (i * 16); return r;
        case MMX_PCMPEQW: for (int i = 0; i < 4; i++) r |= (quint64)(gW(a, i) == gW(b, i) ? 0xFFFF : 0x0000) << (i * 16); return r;
        case MMX_PCMPGTW: for (int i = 0; i < 4; i++) r |= (quint64)((qint16)gW(a, i) > (qint16)gW(b, i) ? 0xFFFF : 0x0000) << (i * 16); return r;
        case MMX_PMINSW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)((qint16)gW(a, i) < (qint16)gW(b, i) ? (qint16)gW(a, i) : (qint16)gW(b, i)) << (i * 16); return r;
        case MMX_PMAXSW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)((qint16)gW(a, i) > (qint16)gW(b, i) ? (qint16)gW(a, i) : (qint16)gW(b, i)) << (i * 16); return r;
        case MMX_PAVGW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(((qint32)gW(a, i) + gW(b, i) + 1) >> 1) << (i * 16); return r;
        case MMX_PMULLW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)((qint16)gW(a, i) * (qint16)gW(b, i)) << (i * 16); return r;
        case MMX_PMULHW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(((qint32)(qint16)gW(a, i) * (qint16)gW(b, i)) >> 16) << (i * 16); return r;
        case MMX_PMULHUW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(((quint32)gW(a, i) * gW(b, i)) >> 16) << (i * 16); return r;

        // ---- dword lanes (2) ----
        case MMX_PADDD: for (int i = 0; i < 2; i++) r |= (quint64)(quint32)(gD(a, i) + gD(b, i)) << (i * 32); return r;
        case MMX_PSUBD: for (int i = 0; i < 2; i++) r |= (quint64)(quint32)(gD(a, i) - gD(b, i)) << (i * 32); return r;
        case MMX_PCMPEQD: for (int i = 0; i < 2; i++) r |= (quint64)(gD(a, i) == gD(b, i) ? 0xFFFFFFFFu : 0u) << (i * 32); return r;
        case MMX_PCMPGTD: for (int i = 0; i < 2; i++) r |= (quint64)((qint32)gD(a, i) > (qint32)gD(b, i) ? 0xFFFFFFFFu : 0u) << (i * 32); return r;

        // ---- qword lane (1) ----
        case MMX_PADDQ: return a + b;
        case MMX_PSUBQ: return a - b;

        // ---- multiply-add: 2 dwords, each the signed sum of two 16x16 products ----
        case MMX_PMADDWD:
            for (int i = 0; i < 2; i++) {
                qint32 nLo = (qint32)(qint16)gW(a, i * 2) * (qint16)gW(b, i * 2);
                qint32 nHi = (qint32)(qint16)gW(a, i * 2 + 1) * (qint16)gW(b, i * 2 + 1);
                r |= (quint64)(quint32)(nLo + nHi) << (i * 32);
            }
            return r;

        // ---- pack (dst lanes low, src lanes high) ----
        case MMX_PACKSSWB:
            for (int i = 0; i < 4; i++) r |= (quint64)msatS8((qint16)gW(a, i)) << (i * 8);
            for (int i = 0; i < 4; i++) r |= (quint64)msatS8((qint16)gW(b, i)) << ((i + 4) * 8);
            return r;
        case MMX_PACKUSWB:
            for (int i = 0; i < 4; i++) r |= (quint64)msatU8((qint16)gW(a, i)) << (i * 8);
            for (int i = 0; i < 4; i++) r |= (quint64)msatU8((qint16)gW(b, i)) << ((i + 4) * 8);
            return r;
        case MMX_PACKSSDW:
            for (int i = 0; i < 2; i++) r |= (quint64)msatS16((qint32)gD(a, i)) << (i * 16);
            for (int i = 0; i < 2; i++) r |= (quint64)msatS16((qint32)gD(b, i)) << ((i + 2) * 16);
            return r;

        // ---- unpack (interleave) ----
        case MMX_PUNPCKLBW:
            for (int i = 0; i < 4; i++) { r |= (quint64)gB(a, i) << (i * 16); r |= (quint64)gB(b, i) << (i * 16 + 8); }
            return r;
        case MMX_PUNPCKHBW:
            for (int i = 0; i < 4; i++) { r |= (quint64)gB(a, i + 4) << (i * 16); r |= (quint64)gB(b, i + 4) << (i * 16 + 8); }
            return r;
        case MMX_PUNPCKLWD:
            for (int i = 0; i < 2; i++) { r |= (quint64)gW(a, i) << (i * 32); r |= (quint64)gW(b, i) << (i * 32 + 16); }
            return r;
        case MMX_PUNPCKHWD:
            for (int i = 0; i < 2; i++) { r |= (quint64)gW(a, i + 2) << (i * 32); r |= (quint64)gW(b, i + 2) << (i * 32 + 16); }
            return r;
        case MMX_PUNPCKLDQ:
            return (quint64)gD(a, 0) | ((quint64)gD(b, 0) << 32);
        case MMX_PUNPCKHDQ:
            return (quint64)gD(a, 1) | ((quint64)gD(b, 1) << 32);

        // ---- sum of absolute differences (result in low word) ----
        case MMX_PSADBW: {
            quint32 nSum = 0;
            for (int i = 0; i < 8; i++) {
                int d = (int)gB(a, i) - (int)gB(b, i);
                nSum += (quint32)(d < 0 ? -d : d);
            }
            return (quint64)(nSum & 0xFFFF);
        }

        default:
            return 0;
    }
}

quint64 XEmuX86::_mmxShift(int nOp, quint64 a, quint64 nCount)
{
    quint64 r = 0;
    const quint64 n = nCount;  // full count; shifts >= lane width clear (or sign-fill) the lane

    switch (nOp) {
        case MMX_PSLLW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(n >= 16 ? 0 : (quint16)(gW(a, i) << n)) << (i * 16); return r;
        case MMX_PSRLW: for (int i = 0; i < 4; i++) r |= (quint64)(quint16)(n >= 16 ? 0 : (gW(a, i) >> n)) << (i * 16); return r;
        case MMX_PSRAW: for (int i = 0; i < 4; i++) { qint16 v = (qint16)gW(a, i); quint16 s = (quint16)(n >= 16 ? (v < 0 ? 0xFFFF : 0) : (v >> n)); r |= (quint64)s << (i * 16); } return r;
        case MMX_PSLLD: for (int i = 0; i < 2; i++) r |= (quint64)(quint32)(n >= 32 ? 0 : (gD(a, i) << n)) << (i * 32); return r;
        case MMX_PSRLD: for (int i = 0; i < 2; i++) r |= (quint64)(quint32)(n >= 32 ? 0 : (gD(a, i) >> n)) << (i * 32); return r;
        case MMX_PSRAD: for (int i = 0; i < 2; i++) { qint32 v = (qint32)gD(a, i); quint32 s = (quint32)(n >= 32 ? (v < 0 ? 0xFFFFFFFFu : 0u) : (v >> n)); r |= (quint64)s << (i * 32); } return r;
        case MMX_PSLLQ: return (n >= 64) ? 0 : (a << n);
        case MMX_PSRLQ: return (n >= 64) ? 0 : (a >> n);
        default: return a;
    }
}

bool XEmuX86::decodeMicroOpSnapshot(
    XADDR nAddress, XEmuMicroOp *pResult)
{
    if (!pResult) return false;
    XEmuMicroOp op;
    if (!_decodeInsn(nAddress, op)) return false;
    *pResult = op;
    return true;
}

bool XEmuX86::_decodeInsn(XADDR nAddress, XEmuMicroOp &op)
{
    DEC dec;
    dec.nStart = nAddress;
    dec.nFetch = nAddress;
    dec.nAddrSize = (m_nBits == 16) ? 2 : ((m_nBits == 64) ? 8 : 4);

    op = XEmuMicroOp();
    op.nAddress = nAddress;

    // Prefixes.
    quint8 nOpcode = 0;
    while (true) {
        nOpcode = _fetch8(dec);
        if (dec.bFault) {
            return false;
        }

        if (nOpcode == 0x66) {
            dec.bOpSize16 = true;
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if (nOpcode == 0x67) {
            dec.nAddrSize = (m_nBits == 16) ? 4 : ((m_nBits == 64) ? 4 : (m_nBits == 32 ? 2 : 8));
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if ((nOpcode == 0xF0) || (nOpcode == 0xF2) || (nOpcode == 0xF3)) {
            if (nOpcode == 0xF3) {
                dec.nRep = 1;  // rep / repe
            } else if (nOpcode == 0xF2) {
                dec.nRep = 2;  // repne
            }
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if ((nOpcode == 0x2E) || (nOpcode == 0x36) || (nOpcode == 0x3E) || (nOpcode == 0x26)) {
            // Segment override (ES/CS/SS/DS). In real mode these pick the segment base for
            // the memory operand; in protected/long mode ES/CS/SS/DS are flat (base 0).
            dec.nSegSource = (nOpcode == 0x26) ? 3 : (nOpcode == 0x2E) ? 4 : (nOpcode == 0x36) ? 5 : 6;  // ES / CS / SS / DS
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if (nOpcode == 0x64) {
            dec.nSegSource = 1;
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if (nOpcode == 0x65) {
            dec.nSegSource = 2;
            dec.bRexW = dec.bRexR = dec.bRexX = dec.bRexB = dec.bHasRex = false;
        } else if ((m_nBits == 64) && (nOpcode >= 0x40) && (nOpcode <= 0x4F)) {
            dec.bHasRex = true;
            dec.bRexW = (nOpcode & 8) != 0;
            dec.bRexR = (nOpcode & 4) != 0;
            dec.bRexX = (nOpcode & 2) != 0;
            dec.bRexB = (nOpcode & 1) != 0;
        } else {
            break;
        }
    }

    // Default operand size: 16-bit in real mode, otherwise 32-bit; the 0x66 prefix
    // toggles it, and REX.W forces 64-bit.
    {
        int nDefaultOpSize = (m_nBits == 16) ? 2 : 4;
        dec.nOpSize = dec.bRexW ? 8 : (dec.bOpSize16 ? (6 - nDefaultOpSize) : nDefaultOpSize);
    }

    if ((nOpcode < 0x40) && ((nOpcode & 7) < 6)) {
        int nAluOp = nOpcode >> 3;
        int nVariant = nOpcode & 7;
        int nSize = ((nVariant == 0) || (nVariant == 2) || (nVariant == 4)) ? 1 : dec.nOpSize;
        op.nSize = nSize;
        op.nAluOp = nAluOp;
        op.sText = QString::fromLatin1(g_pszAluNames[nAluOp]);

        if (nVariant <= 3) {
            int nRegField = 0;
            XEmuOperand rm;
            _decodeModRM(dec, nRegField, rm);
            if (nVariant <= 1) {
                op.kind = MOP_ALU_RM_R;
                op.dst = rm;
                op.src = XEmuOperand::reg(nRegField);
            } else {
                op.kind = MOP_ALU_R_RM;
                op.dst = XEmuOperand::reg(nRegField);
                op.src = rm;
            }
        } else {
            op.kind = MOP_ALU_RAX_IMM;
            if (nVariant == 4) {
                op.nImm = _fetch8(dec);
            } else if (nSize == 2) {
                op.nImm = _fetch16(dec);
            } else {
                op.nImm = (quint64)_signExtend(_fetch32(dec), 4);
            }
        }
    } else if ((m_nBits != 64) && (nOpcode >= 0x40) && (nOpcode <= 0x4F)) {
        // Single-byte inc/dec reg (these encodings are REX prefixes in 64-bit mode,
        // which is handled earlier in the prefix loop).
        op.kind = MOP_INCDEC;
        op.dst = XEmuOperand::reg(nOpcode & 7);
        op.nSize = dec.nOpSize;
        op.nAluOp = (nOpcode < 0x48) ? 0 : 1;
        op.sText = (nOpcode < 0x48) ? QStringLiteral("inc") : QStringLiteral("dec");
    } else if ((nOpcode >= 0x50) && (nOpcode <= 0x57)) {
        op.kind = MOP_PUSH;
        op.src = XEmuOperand::reg((nOpcode - 0x50) + (dec.bRexB ? 8 : 0));
        op.nSize = _stackSize(dec);
        op.sText = QStringLiteral("push");
    } else if ((nOpcode >= 0x58) && (nOpcode <= 0x5F)) {
        op.kind = MOP_POP;
        op.dst = XEmuOperand::reg((nOpcode - 0x58) + (dec.bRexB ? 8 : 0));
        op.nSize = _stackSize(dec);
        op.sText = QStringLiteral("pop");
    } else if (nOpcode == 0x68) {
        // push imm: the immediate follows the operand size (imm16 in 16-bit mode, imm32
        // otherwise) -- reading it as fixed 32-bit desynchronises 16-bit instruction streams.
        op.kind = MOP_PUSH;
        if (dec.nOpSize == 2) {
            op.nImm = (quint64)_signExtend(_fetch16(dec), 2);
        } else {
            op.nImm = (quint64)_signExtend(_fetch32(dec), 4);
        }
        op.nSize = _stackSize(dec);
        op.sText = QStringLiteral("push");
    } else if (nOpcode == 0x6A) {
        op.kind = MOP_PUSH;
        op.nImm = (quint64)_signExtend(_fetch8(dec), 1);
        op.nSize = _stackSize(dec);
        op.sText = QStringLiteral("push");
    } else if ((nOpcode == 0x69) || (nOpcode == 0x6B)) {
        // imul r, r/m, imm  (three-operand): dst = src * sign-extended imm
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_IMUL2;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.nSrcSize = -1;  // signals the three-operand (immediate) form to the executor
        if (nOpcode == 0x6B) {
            op.nImm = (quint64)_signExtend(_fetch8(dec), 1);
        } else if (dec.nOpSize == 2) {
            op.nImm = (quint64)_signExtend(_fetch16(dec), 2);
        } else {
            op.nImm = (quint64)_signExtend(_fetch32(dec), 4);
        }
        op.sText = QStringLiteral("imul");
    } else if ((nOpcode == 0x88) || (nOpcode == 0x89) || (nOpcode == 0x8A) || (nOpcode == 0x8B)) {
        int nSize = ((nOpcode == 0x88) || (nOpcode == 0x8A)) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_MOV;
        op.nSize = nSize;
        if ((nOpcode == 0x88) || (nOpcode == 0x89)) {
            op.dst = rm;
            op.src = XEmuOperand::reg(nRegField);
        } else {
            op.dst = XEmuOperand::reg(nRegField);
            op.src = rm;
        }
        op.sText = QStringLiteral("mov");
    } else if (nOpcode == 0x8D) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_LEA;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("lea");
    } else if ((nOpcode == 0x8C) || (nOpcode == 0x8E)) {
        // mov r/m16, Sreg (0x8C) / mov Sreg, r/m16 (0x8E). Segment operands are 16-bit.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_MOVSEG;
        op.nAluOp = nRegField & 7;  // 0 ES,1 CS,2 SS,3 DS,4 FS,5 GS
        op.nSize = 2;
        if (nOpcode == 0x8E) {
            op.nCond = 0;  // to segment
            op.src = rm;
        } else {
            op.nCond = 1;  // from segment
            op.dst = rm;
        }
        op.sText = QStringLiteral("mov");
    } else if ((m_nBits == 64) && (nOpcode == 0x63)) {
        // movsxd r64, r/m32 (sign-extend dword to the operand size, usually 64-bit).
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_MOVSX;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSrcSize = 4;
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("movsxd");
    } else if ((nOpcode >= 0xB0) && (nOpcode <= 0xB7)) {
        op.kind = MOP_MOV_IMM;
        op.dst = XEmuOperand::reg8(nOpcode - 0xB0, dec.bHasRex, dec.bRexB);  // AH/CH/DH/BH when no REX
        op.nSize = 1;
        op.nImm = _fetch8(dec);
        op.sText = QStringLiteral("mov");
    } else if ((nOpcode >= 0xB8) && (nOpcode <= 0xBF)) {
        op.kind = MOP_MOV_IMM;
        op.dst = XEmuOperand::reg((nOpcode - 0xB8) + (dec.bRexB ? 8 : 0));
        op.nSize = dec.nOpSize;
        if (dec.nOpSize == 8) {
            op.nImm = _fetch64(dec);
        } else if (dec.nOpSize == 2) {
            op.nImm = _fetch16(dec);
        } else {
            op.nImm = _fetch32(dec);
        }
        op.sText = QStringLiteral("mov");
    } else if ((nOpcode >= 0xA0) && (nOpcode <= 0xA3)) {
        // MOV accumulator <-> moffs (direct memory offset). A0/A1 load AL/eAX from the
        // offset, A2/A3 store it; A0/A2 are byte-sized, A1/A3 use the operand size. The
        // offset is address-size wide and uses the default data segment (or an override).
        int nSize = ((nOpcode == 0xA0) || (nOpcode == 0xA2)) ? 1 : dec.nOpSize;
        XEmuOperand mem;
        mem.bIsMem = true;
        mem.nBaseReg = -1;
        mem.nIndexReg = -1;
        mem.nSegSource = dec.nSegSource;
        if (dec.nAddrSize == 2) {
            mem.nDisp = _fetch16(dec);
        } else if (dec.nAddrSize == 8) {
            mem.nDisp = (qint64)_fetch64(dec);
        } else {
            mem.nDisp = _fetch32(dec);
        }
        op.kind = MOP_MOV;
        op.nSize = nSize;
        if ((nOpcode == 0xA0) || (nOpcode == 0xA1)) {
            op.dst = XEmuOperand::reg(0);  // AL / AX / eAX / rAX
            op.src = mem;
        } else {
            op.dst = mem;
            op.src = XEmuOperand::reg(0);
        }
        op.sText = QStringLiteral("mov");
    } else if ((nOpcode == 0xC6) || (nOpcode == 0xC7)) {
        int nSize = (nOpcode == 0xC6) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_MOV_IMM;
        op.dst = rm;
        op.nSize = nSize;
        if (nOpcode == 0xC6) {
            op.nImm = _fetch8(dec);
        } else if (nSize == 2) {
            op.nImm = _fetch16(dec);
        } else {
            op.nImm = (quint64)_signExtend(_fetch32(dec), 4) & _mask(nSize);
        }
        op.sText = QStringLiteral("mov");
    } else if ((nOpcode == 0x80) || (nOpcode == 0x82) || (nOpcode == 0x81) || (nOpcode == 0x83)) {
        // 0x82 is the undocumented alias of 0x80 (group-1 r/m8, imm8); some old packers use it.
        int nSize = ((nOpcode == 0x80) || (nOpcode == 0x82)) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_ALU_RM_IMM;
        op.dst = rm;
        op.nSize = nSize;
        op.nAluOp = nRegField & 7;
        if ((nOpcode == 0x80) || (nOpcode == 0x82)) {
            op.nImm = _fetch8(dec);
        } else if (nOpcode == 0x83) {
            op.nImm = (quint64)_signExtend(_fetch8(dec), 1) & _mask(nSize);
        } else if (nSize == 2) {
            op.nImm = _fetch16(dec);
        } else {
            op.nImm = (quint64)_signExtend(_fetch32(dec), 4) & _mask(nSize);
        }
        op.sText = QString::fromLatin1(g_pszAluNames[op.nAluOp]);
    } else if ((nOpcode == 0x84) || (nOpcode == 0x85)) {
        int nSize = (nOpcode == 0x84) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_TEST;
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = nSize;
        op.sText = QStringLiteral("test");
    } else if ((nOpcode == 0xA8) || (nOpcode == 0xA9)) {
        int nSize = (nOpcode == 0xA8) ? 1 : dec.nOpSize;
        op.kind = MOP_TEST_IMM;
        op.dst = XEmuOperand::reg(XEmuRegisters::GPR_RAX);
        op.nSize = nSize;
        if (nOpcode == 0xA8) {
            op.nImm = _fetch8(dec);
        } else if (nSize == 2) {
            op.nImm = _fetch16(dec);
        } else {
            op.nImm = _fetch32(dec);
        }
        op.sText = QStringLiteral("test");
    } else if (nOpcode == 0x8F) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_POP;
        op.dst = rm;
        op.nSize = _stackSize(dec);
        op.sText = QStringLiteral("pop");
    } else if ((nOpcode == 0xFE) || (nOpcode == 0xFF)) {
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        int nExt = nRegField & 7;

        if ((nOpcode == 0xFE) || (nExt == 0) || (nExt == 1)) {
            op.kind = MOP_INCDEC;
            op.dst = rm;
            op.nSize = (nOpcode == 0xFE) ? 1 : dec.nOpSize;
            op.nAluOp = (nExt == 0) ? 0 : 1;
            op.sText = (nExt == 0) ? QStringLiteral("inc") : QStringLiteral("dec");
        } else if (nExt == 2) {
            op.kind = MOP_CALL_IND;
            op.src = rm;
            op.nSize = (m_nBits == 64) ? 8 : dec.nOpSize;  // near indirect: 16-bit target in 16-bit mode (32 only with 0x66)
            op.sText = QStringLiteral("call");
        } else if (nExt == 3) {
            op.kind = MOP_CALL_FAR_IND;  // call far m16:16
            op.src = rm;
            op.nSize = dec.nOpSize;
            op.sText = QStringLiteral("callf");
        } else if (nExt == 4) {
            op.kind = MOP_JMP_IND;
            op.src = rm;
            op.nSize = (m_nBits == 64) ? 8 : dec.nOpSize;  // near indirect: 16-bit target in 16-bit mode (32 only with 0x66)
            op.sText = QStringLiteral("jmp");
        } else if (nExt == 5) {
            op.kind = MOP_JMP_FAR_IND;  // jmp far m16:16
            op.src = rm;
            op.nSize = dec.nOpSize;
            op.sText = QStringLiteral("jmpf");
        } else if (nExt == 6) {
            op.kind = MOP_PUSH;
            op.src = rm;
            op.nSize = _stackSize(dec);
            op.sText = QStringLiteral("push");
        } else {
            op.kind = MOP_UNIMPL;
            op.sText = QStringLiteral("ff /?");
        }
    } else if (nOpcode == 0xE8) {
        // Near call: rel16 with a 16-bit operand size, rel32 otherwise.
        qint32 nRel = (dec.nOpSize == 2) ? (qint32)(qint16)_fetch16(dec) : (qint32)_fetch32(dec);
        op.kind = MOP_CALL;
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = QStringLiteral("call");
    } else if (nOpcode == 0xE9) {
        // Near jmp: rel16 with a 16-bit operand size, rel32 otherwise.
        qint32 nRel = (dec.nOpSize == 2) ? (qint32)(qint16)_fetch16(dec) : (qint32)_fetch32(dec);
        op.kind = MOP_JMP;
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = QStringLiteral("jmp");
    } else if (nOpcode == 0xEB) {
        qint8 nRel = (qint8)_fetch8(dec);
        op.kind = MOP_JMP;
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = QStringLiteral("jmp");
    } else if ((nOpcode == 0xEA) || (nOpcode == 0x9A)) {
        // Far direct jmp (0xEA) / call (0x9A) ptr16:16 -- the offset (operand-size wide) then a
        // 16-bit segment. Real-mode self-extractors use this to jump into their relocated payload.
        quint32 nOff = (dec.nOpSize == 2) ? _fetch16(dec) : _fetch32(dec);
        quint16 nSeg = _fetch16(dec);
        op.kind = (nOpcode == 0xEA) ? MOP_JMP_FAR : MOP_CALL_FAR;
        op.nBranchTarget = nOff;
        op.nImm = nSeg;
        op.sText = (nOpcode == 0xEA) ? QStringLiteral("jmpf") : QStringLiteral("callf");
    } else if ((nOpcode == 0xE4) || (nOpcode == 0xE5) || (nOpcode == 0xE6) || (nOpcode == 0xE7) || (nOpcode == 0xEC) || (nOpcode == 0xED) ||
               (nOpcode == 0xEE) || (nOpcode == 0xEF)) {
        // Port I/O. Even/odd low bit selects byte vs word/dword; 0xE4-0xE7 take an imm8
        // port, 0xEC-0xEF take the port in DX. IN -> AL/AX/eAX, OUT <- AL/AX/eAX.
        bool bOut = (nOpcode == 0xE6) || (nOpcode == 0xE7) || (nOpcode == 0xEE) || (nOpcode == 0xEF);
        bool bByte = (nOpcode == 0xE4) || (nOpcode == 0xE6) || (nOpcode == 0xEC) || (nOpcode == 0xEE);
        bool bImmPort = (nOpcode >= 0xE4) && (nOpcode <= 0xE7);
        op.kind = bOut ? MOP_OUT : MOP_IN;
        op.nSize = bByte ? 1 : dec.nOpSize;
        op.nCond = bImmPort ? 0 : 1;  // 0 = imm8 port, 1 = DX port
        if (bImmPort) {
            op.nImm = _fetch8(dec);
        }
        op.sText = bOut ? QStringLiteral("out") : QStringLiteral("in");
    } else if ((nOpcode >= 0xE0) && (nOpcode <= 0xE3)) {
        qint8 nRel = (qint8)_fetch8(dec);
        op.kind = MOP_LOOP;
        op.nAluOp = nOpcode - 0xE0;  // 0 loopne, 1 loope, 2 loop, 3 jecxz
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = (nOpcode == 0xE3) ? QStringLiteral("jecxz") : QStringLiteral("loop");
    } else if ((nOpcode >= 0x70) && (nOpcode <= 0x7F)) {
        qint8 nRel = (qint8)_fetch8(dec);
        op.kind = MOP_JCC;
        op.nCond = nOpcode - 0x70;
        op.nBranchTarget = dec.nFetch + nRel;
        op.sText = QStringLiteral("jcc");
    } else if (nOpcode == 0xC3) {
        op.kind = MOP_RET;
        op.sText = QStringLiteral("ret");
    } else if (nOpcode == 0xC2) {
        op.kind = MOP_RET;
        op.nImm = _fetch16(dec);
        op.sText = QStringLiteral("ret");
    } else if ((nOpcode == 0xC4) || (nOpcode == 0xC5)) {
        // les/lds reg, m16:16 -- load a far pointer: the register gets the offset, ES/DS the segment.
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_LOADFAR;
        op.dst = XEmuOperand::reg(nRegField);
        op.src = rm;
        op.nSize = dec.nOpSize;
        op.nCond = (nOpcode == 0xC4) ? 0 : 1;  // 0 = ES (les), 1 = DS (lds)
        op.sText = (nOpcode == 0xC4) ? QStringLiteral("les") : QStringLiteral("lds");
    } else if (nOpcode == 0xCB) {
        op.kind = MOP_RETF;
        op.nSize = dec.nOpSize;  // protected-mode far-return pop width (2 with 0x66, 8 with REX.W)
        op.sText = QStringLiteral("retf");
    } else if (nOpcode == 0xCA) {
        op.kind = MOP_RETF;
        op.nSize = dec.nOpSize;
        op.nImm = _fetch16(dec);
        op.sText = QStringLiteral("retf");
    } else if (nOpcode == 0xCF) {
        op.kind = MOP_IRET;
        op.sText = QStringLiteral("iret");
    } else if ((nOpcode == 0xF5) || (nOpcode == 0xF8) || (nOpcode == 0xF9) || (nOpcode == 0xFA) || (nOpcode == 0xFB) || (nOpcode == 0xFC) ||
               (nOpcode == 0xFD)) {
        op.kind = MOP_FLAGOP;
        switch (nOpcode) {
            case 0xF8: op.nAluOp = 0; op.sText = QStringLiteral("clc"); break;
            case 0xF9: op.nAluOp = 1; op.sText = QStringLiteral("stc"); break;
            case 0xF5: op.nAluOp = 2; op.sText = QStringLiteral("cmc"); break;
            case 0xFC: op.nAluOp = 3; op.sText = QStringLiteral("cld"); break;
            case 0xFD: op.nAluOp = 4; op.sText = QStringLiteral("std"); break;
            case 0xFA: op.nAluOp = 5; op.sText = QStringLiteral("cli"); break;
            default: op.nAluOp = 6; op.sText = QStringLiteral("sti"); break;  // 0xFB
        }
    } else if (nOpcode == 0x90) {
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("nop");
    } else if (nOpcode == 0x9B) {
        // fwait/wait: synchronize with pending x87 exceptions. With no asynchronous FPU
        // exception model it is a no-op. (When it prefixes a D8-DF opcode the FPU op is
        // decoded as the next instruction, which is equivalent.)
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("fwait");
    } else if (nOpcode == 0x9C) {
        op.kind = MOP_PUSHF;
        op.nSize = (m_nBits == 64) ? 8 : dec.nOpSize;  // pushfq default 64-bit; pushfd/pushf per operand size
        op.sText = (op.nSize == 2) ? QStringLiteral("pushf") : ((op.nSize == 8) ? QStringLiteral("pushfq") : QStringLiteral("pushfd"));
    } else if (nOpcode == 0x9D) {
        op.kind = MOP_POPF;
        op.nSize = (m_nBits == 64) ? 8 : dec.nOpSize;
        op.sText = (op.nSize == 2) ? QStringLiteral("popf") : ((op.nSize == 8) ? QStringLiteral("popfq") : QStringLiteral("popfd"));
    } else if (nOpcode == 0x9E) {
        op.kind = MOP_SAHF;
        op.sText = QStringLiteral("sahf");
    } else if (nOpcode == 0x9F) {
        op.kind = MOP_LAHF;
        op.sText = QStringLiteral("lahf");
    } else if (nOpcode == 0xC8) {
        op.kind = MOP_ENTER;
        op.nImm = _fetch16(dec);   // frame size (bytes)
        op.nAluOp = _fetch8(dec);  // nesting level
        op.sText = QStringLiteral("enter");
    } else if (nOpcode == 0xC9) {
        op.kind = MOP_LEAVE;
        op.sText = QStringLiteral("leave");
    } else if (nOpcode == 0xD6) {
        // salc / setalc (undocumented): AL = CF ? 0xFF : 0x00. Used by compact packers
        // (kkrunchy, ...). No operands, affects no flags.
        op.kind = MOP_SALC;
        op.sText = QStringLiteral("salc");
    } else if (nOpcode == 0xD7) {
        op.kind = MOP_XLAT;
        op.nSize = dec.nAddrSize;  // (r)BX width: 2 in real mode, 4/8 otherwise
        op.src.nSegSource = dec.nSegSource;  // honor a segment override (e.g. es:xlat)
        op.sText = QStringLiteral("xlat");
    } else if ((nOpcode == 0x06) || (nOpcode == 0x0E) || (nOpcode == 0x16) || (nOpcode == 0x1E)) {
        op.kind = MOP_PUSHSEG;
        op.nAluOp = (nOpcode == 0x06) ? 0 : (nOpcode == 0x0E) ? 1 : (nOpcode == 0x16) ? 2 : 3;  // ES / CS / SS / DS
        op.sText = QStringLiteral("push");
    } else if ((nOpcode == 0x07) || (nOpcode == 0x17) || (nOpcode == 0x1F)) {
        op.kind = MOP_POPSEG;
        op.nAluOp = (nOpcode == 0x07) ? 0 : (nOpcode == 0x17) ? 2 : 3;  // ES / SS / DS
        op.sText = QStringLiteral("pop");
    } else if (nOpcode == 0x62) {
        // bound r, m: array range check. Consume the ModRM and skip the check (never trap).
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_NOP;
        op.sText = QStringLiteral("bound");
    } else if ((nOpcode == 0x27) || (nOpcode == 0x2F) || (nOpcode == 0x37) || (nOpcode == 0x3F)) {
        op.kind = MOP_BCD;
        op.nAluOp = (nOpcode == 0x27) ? 0 : (nOpcode == 0x2F) ? 1 : (nOpcode == 0x37) ? 2 : 3;  // DAA/DAS/AAA/AAS
        op.sText = QStringLiteral("bcd");
    } else if ((nOpcode == 0xD4) || (nOpcode == 0xD5)) {
        op.kind = MOP_BCD;
        op.nAluOp = (nOpcode == 0xD4) ? 4 : 5;  // AAM / AAD
        op.nImm = _fetch8(dec);                 // base (10 for the usual ASCII form)
        op.sText = (nOpcode == 0xD4) ? QStringLiteral("aam") : QStringLiteral("aad");
    } else if (nOpcode == 0xCC) {
        // int3 (breakpoint): route through the software-interrupt path with vector 3 so the
        // OS personality can dispatch STATUS_BREAKPOINT via SEH. Packers (PeX, REVProt, ...)
        // execute int3 on purpose and catch it with their own handler as an anti-debug /
        // control-flow trick. PC advances past the 1-byte opcode (int3 is a trap).
        op.kind = MOP_SYSCALL;
        op.nImm = 3;
        op.nAluOp = 2;  // general software interrupt
        op.sText = QStringLiteral("int3");
    } else if (nOpcode == 0xF4) {
        op.kind = MOP_HALT;
        op.sText = QStringLiteral("hlt");
    } else if (nOpcode == 0xCD) {
        // Software interrupt. All vectors are handed to the OS personality (int 0x80 is the
        // Linux ABI; 0x20/0x21/0x10/0x16/... are DOS/BIOS). The vector rides in nImm.
        quint8 nVector = _fetch8(dec);
        op.kind = MOP_SYSCALL;
        op.nImm = nVector;
        op.nAluOp = (nVector == 0x80) ? 1 : 2;  // 1 = int 0x80, 2 = general software interrupt
        op.sText = QString("int 0x%1").arg(nVector, 2, 16, QChar('0'));
    } else if (nOpcode == 0xCE) {
        // into: interrupt 4 if OF is set, otherwise a no-op. Packers/protectors put `into` in
        // decryptor stubs (usually right after an xor/sub that clears OF), where it must fall
        // through; a genuine overflow vectors software interrupt 4.
        op.kind = MOP_INTO;
        op.sText = QStringLiteral("into");
    } else if (nOpcode == 0xF1) {
        // icebp / int1 (undocumented 0xF1): single-step trap. Anti-debug stubs execute it to
        // detect an in-circuit emulator; with no debugger it is a plain software interrupt 1.
        op.kind = MOP_SYSCALL;
        op.nImm = 1;
        op.nAluOp = 2;  // general software interrupt
        op.sText = QStringLiteral("icebp");
    } else if ((nOpcode == 0x63) && (m_nBits != 64)) {
        // arpl r/m16, r16 (16/32-bit modes): adjust the RPL field. Old DOS protectors use it
        // (it executes on a 386 even in real mode). In 64-bit mode 0x63 is MOVSXD (left unhandled).
        int nReg = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nReg, rm);
        op.kind = MOP_ARPL;
        op.dst = rm;
        op.src = XEmuOperand::reg(nReg);
        op.nSize = 2;
        op.sText = QStringLiteral("arpl");
    } else if (nOpcode == 0x60) {
        op.kind = MOP_PUSHA;
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("pushad");
    } else if (nOpcode == 0x61) {
        op.kind = MOP_POPA;
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("popad");
    } else if ((nOpcode == 0xC0) || (nOpcode == 0xC1) || (nOpcode == 0xD0) || (nOpcode == 0xD1) || (nOpcode == 0xD2) || (nOpcode == 0xD3)) {
        int nSize = ((nOpcode == 0xC0) || (nOpcode == 0xD0) || (nOpcode == 0xD2)) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_SHIFT;
        op.dst = rm;
        op.nSize = nSize;
        op.nAluOp = nRegField & 7;  // 0 rol,1 ror,2 rcl,3 rcr,4 shl,5 shr,6 sal,7 sar
        if ((nOpcode == 0xC0) || (nOpcode == 0xC1)) {
            op.nCond = 0;
            op.nImm = _fetch8(dec);
        } else if ((nOpcode == 0xD0) || (nOpcode == 0xD1)) {
            op.nCond = 0;
            op.nImm = 1;
        } else {
            op.nCond = 1;  // count comes from CL
        }
        op.sText = QStringLiteral("shift");
    } else if ((nOpcode == 0xF6) || (nOpcode == 0xF7)) {
        int nSize = (nOpcode == 0xF6) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        int nExt = nRegField & 7;
        op.nSize = nSize;
        op.dst = rm;
        if ((nExt == 0) || (nExt == 1)) {  // test rm, imm
            op.kind = MOP_TEST_IMM;
            if (nOpcode == 0xF6) {
                op.nImm = _fetch8(dec);
            } else if (nSize == 2) {
                op.nImm = _fetch16(dec);
            } else {
                op.nImm = _fetch32(dec);
            }
            op.sText = QStringLiteral("test");
        } else {  // not/neg/mul/imul/div/idiv
            op.kind = MOP_MULDIV;
            op.nAluOp = nExt;
            op.sText = QStringLiteral("grp3");
        }
    } else if ((nOpcode == 0x86) || (nOpcode == 0x87)) {
        int nSize = (nOpcode == 0x86) ? 1 : dec.nOpSize;
        int nRegField = 0;
        XEmuOperand rm;
        _decodeModRM(dec, nRegField, rm);
        op.kind = MOP_XCHG;
        op.dst = rm;
        op.src = XEmuOperand::reg(nRegField);
        op.nSize = nSize;
        op.sText = QStringLiteral("xchg");
    } else if ((nOpcode >= 0x91) && (nOpcode <= 0x97)) {
        op.kind = MOP_XCHG;
        op.dst = XEmuOperand::reg(XEmuRegisters::GPR_RAX);
        op.src = XEmuOperand::reg((nOpcode - 0x90) + (dec.bRexB ? 8 : 0));
        op.nSize = dec.nOpSize;
        op.sText = QStringLiteral("xchg");
    } else if ((nOpcode == 0x98) || (nOpcode == 0x99)) {
        op.kind = MOP_CDQ;
        op.nAluOp = (nOpcode == 0x98) ? 0 : 1;
        op.nSize = dec.nOpSize;
        op.sText = (nOpcode == 0x98) ? QStringLiteral("cwde") : QStringLiteral("cdq");
    } else if ((nOpcode == 0xA4) || (nOpcode == 0xA5) || (nOpcode == 0xAA) || (nOpcode == 0xAB) || (nOpcode == 0xAC) || (nOpcode == 0xAD) ||
               (nOpcode == 0xAE) || (nOpcode == 0xAF) || (nOpcode == 0xA6) || (nOpcode == 0xA7)) {
        bool bByte = ((nOpcode & 1) == 0);
        op.kind = MOP_STRING;
        op.nSize = bByte ? 1 : dec.nOpSize;
        op.nCond = dec.nRep;  // 0 none, 1 rep/repe, 2 repne
        op.src.nSegSource = dec.nSegSource;  // segment override applies to the SOURCE (movs/lods/cmps)
        if ((nOpcode == 0xA4) || (nOpcode == 0xA5)) {
            op.nAluOp = 0;  // movs
            op.sText = QStringLiteral("movs");
        } else if ((nOpcode == 0xAA) || (nOpcode == 0xAB)) {
            op.nAluOp = 1;  // stos
            op.sText = QStringLiteral("stos");
        } else if ((nOpcode == 0xAC) || (nOpcode == 0xAD)) {
            op.nAluOp = 2;  // lods
            op.sText = QStringLiteral("lods");
        } else if ((nOpcode == 0xAE) || (nOpcode == 0xAF)) {
            op.nAluOp = 3;  // scas
            op.sText = QStringLiteral("scas");
        } else {
            op.nAluOp = 4;  // cmps
            op.sText = QStringLiteral("cmps");
        }
    } else if ((nOpcode == 0x6C) || (nOpcode == 0x6D) || (nOpcode == 0x6E) || (nOpcode == 0x6F)) {
        // String port I/O: ins (6C/6D) reads DX into ES:DI; outs (6E/6F) writes DS:SI to DX.
        bool bByte = ((nOpcode & 1) == 0);
        op.kind = MOP_STRING;
        op.nSize = bByte ? 1 : dec.nOpSize;
        op.nCond = dec.nRep;
        op.src.nSegSource = dec.nSegSource;  // override applies to the outs source (DS:SI)
        op.nAluOp = (nOpcode <= 0x6D) ? 5 : 6;  // 5 ins, 6 outs
        op.sText = (nOpcode <= 0x6D) ? QStringLiteral("ins") : QStringLiteral("outs");
    } else if ((nOpcode >= 0xD8) && (nOpcode <= 0xDF)) {
        _decodeFpu(dec, op, nOpcode);
    } else if (nOpcode == 0x0F) {
        _decodeTwoByte(dec, op);
    } else {
        op.kind = MOP_UNIMPL;
        op.sText = QString("db %1").arg(nOpcode, 2, 16, QChar('0'));
    }

    if (dec.bFault) {
        return false;
    }

    // Legacy high-byte registers: a byte-sized register operand encoded 4..7 without a REX
    // prefix names AH/CH/DH/BH (bits 8..15 of AX/CX/DX/BX), not SPL/BPL/SIL/DIL. The generic
    // ModRM decode can't know the operand width, so fix such operands up here now that the
    // width is known. (The 0xB0..0xB7 short form is already handled at decode via reg8.)
    if (!dec.bHasRex) {
        x86FixHigh8(op.dst, op.nSize);
        x86FixHigh8(op.src, op.nSize);
        // MOVZX/MOVSX read a byte source into a wider destination.
        if ((op.kind == MOP_MOVZX) || (op.kind == MOP_MOVSX)) {
            x86FixHigh8(op.src, op.nSrcSize);
        }
    }

    op.nAddrSize = dec.nAddrSize;
    op.nLength = (quint32)(dec.nFetch - dec.nStart);
    return true;
}

XEmuTB *XEmuX86::_translateBlock(XADDR nAddress)
{
    XEmuTB *pBlock = new XEmuTB();
    pBlock->nStartAddress = nAddress;

    XADDR nCurrent = nAddress;

    for (int i = 0; i < N_MAX_BLOCK_INSNS; i++) {
        XEmuMicroOp op;

        if (!_decodeInsn(nCurrent, op)) {
            // Guest code is unreadable here; terminate the block with a fault marker.
            op = XEmuMicroOp();
            op.kind = MOP_UNIMPL;
            op.nAddress = nCurrent;
            op.nLength = 0;
            op.sText = QStringLiteral("(unreadable)");
            pBlock->listOps.append(op);
            break;
        }

        pBlock->listOps.append(op);
        nCurrent = op.nAddress + op.nLength;

        if (op.isBlockTerminator()) {
            break;
        }
    }

    pBlock->nEndAddress = nCurrent;
    return pBlock;
}

// --- Interpreter backend -----------------------------------------------------

XADDR XEmuX86::_resolveAddr(const XEmuMicroOp &op, const XEmuOperand &opnd, bool bOffsetOnly)
{
    XADDR nAddress;
    const int nAddrSize = op.nAddrSize;

    if (opnd.bRipRel) {
        nAddress = op.nAddress + op.nLength + opnd.nDisp;
    } else {
        qint64 nValue = opnd.nDisp;
        if (opnd.nBaseReg >= 0) {
            nValue += (qint64)m_pExecRegs->getGPR(opnd.nBaseReg, nAddrSize);
        }
        if (opnd.nIndexReg >= 0) {
            nValue += (qint64)m_pExecRegs->getGPR(opnd.nIndexReg, nAddrSize) * opnd.nScale;
        }
        nAddress = (quint64)nValue;
        if (nAddrSize == 2) {
            nAddress &= 0xFFFF;
        } else if (nAddrSize == 4) {
            nAddress &= 0xFFFFFFFF;
        }
    }

    // bOffsetOnly (for LEA): return the effective-address OFFSET within the segment, NOT the
    // linear address -- LEA never adds the segment base. In 16-bit addressing the offset wraps
    // at 0xFFFF. This is invisible in a .COM (segment<<4 is a multiple of 0x10000, low word 0)
    // but corrupts every .EXE whose segment isn't 0x1000-aligned.
    if (bOffsetOnly) {
        return nAddress;
    }

    if (opnd.nSegSource == 1) {
        nAddress += m_bProtectedMode ? selectorBase(m_pExecRegs->nFS) : m_pExecRegs->nFSBase;
    } else if (opnd.nSegSource == 2) {
        nAddress += m_bProtectedMode ? selectorBase(m_pExecRegs->nGS) : m_pExecRegs->nGSBase;
    } else if (m_nBits == 16 || m_bProtectedMode) {
        quint16 nSeg;
        switch (opnd.nSegSource) {
            case 3: nSeg = m_pExecRegs->nES; break;
            case 4: nSeg = m_pExecRegs->nCS; break;
            case 5: nSeg = m_pExecRegs->nSS; break;
            case 6: nSeg = m_pExecRegs->nDS; break;
            default:
                nSeg = ((opnd.nBaseReg == XEmuRegisters::GPR_RBP) || (opnd.nBaseReg == XEmuRegisters::GPR_RSP)) ? m_pExecRegs->nSS : m_pExecRegs->nDS;
                break;
        }
        nAddress += selectorBase(nSeg);
    }

    // Real mode addresses wrap at 1 MiB (no A20 gate): FFFF:0010 aliases 0000:0000. Wrapping here
    // covers EVERY operand access at once. It used to be applied only in _memReadSized/_memWriteSized,
    // which the string ops use -- so `rep movsb` across the top of memory behaved correctly (that is
    // what AVPack needed) while a plain `mov al,[es:si]` at the same address silently read the
    // unmapped-but-backed HMA and returned zero. Verified against DOSBox with tests/tracediff/dosconf.asm.
    return _wrapA20(nAddress);
}

quint64 XEmuX86::_readOpnd(const XEmuMicroOp &op, const XEmuOperand &opnd, int nSize)
{
    if (opnd.bIsReg) {
        if (opnd.bHigh8) {
            return (m_pExecRegs->getGPR(opnd.nReg, 2) >> 8) & 0xFF;  // AH/CH/DH/BH
        }
        return m_pExecRegs->getGPR(opnd.nReg, nSize);
    }

    XADDR nAddress = _resolveAddr(op, opnd);
    bool bOk = false;
    quint64 nValue = 0;

    switch (nSize) {
        case 1: nValue = m_pMemoryManager->readByte(nAddress, &bOk); break;
        case 2: nValue = m_pMemoryManager->readWord(nAddress, &bOk); break;
        case 4: nValue = m_pMemoryManager->readDword(nAddress, &bOk); break;
        default: nValue = m_pMemoryManager->readQword(nAddress, &bOk); break;
    }

    if (!bOk) {
        m_bExecFault = true;
        m_nFaultAddr = nAddress;
    }

    return nValue;
}

void XEmuX86::_writeOpnd(const XEmuMicroOp &op, const XEmuOperand &opnd, int nSize, quint64 nValue)
{
    if (opnd.bIsReg) {
        if (opnd.bHigh8) {
            quint64 nCur = m_pExecRegs->getGPR(opnd.nReg, 2);  // AH/CH/DH/BH: bits 8..15
            m_pExecRegs->setGPR(opnd.nReg, 2, (nCur & 0x00FF) | ((nValue & 0xFF) << 8));
            return;
        }
        m_pExecRegs->setGPR(opnd.nReg, nSize, nValue);
        return;
    }

    XADDR nAddress = _resolveAddr(op, opnd);
    bool bOk = false;
    _noteWrite(nAddress, nSize);  // this IS the mainline store path (mov [mem],reg / ALU stores)

    switch (nSize) {
        case 1: bOk = m_pMemoryManager->writeByte(nAddress, (quint8)nValue); break;
        case 2: bOk = m_pMemoryManager->writeWord(nAddress, (quint16)nValue); break;
        case 4: bOk = m_pMemoryManager->writeDword(nAddress, (quint32)nValue); break;
        default: bOk = m_pMemoryManager->writeQword(nAddress, nValue); break;
    }

    if (!bOk) {
        m_bExecFault = true;
        m_nFaultAddr = nAddress;
    }
}

void XEmuX86::_push(quint64 nValue, int nSize)
{
    int nSpSize = (m_nBits == 64) ? 8
                  : m_bProtectedMode ? (selectorDefault32(m_pExecRegs->nSS) ? 4 : 2)
                                     : ((m_nBits == 16) ? 2 : 4);
    m_pExecRegs->setGPR(XEmuRegisters::GPR_RSP, nSpSize, m_pExecRegs->getGPR(XEmuRegisters::GPR_RSP, nSpSize) - nSize);

    // Re-read the stack pointer masked to its width -- when SP wraps (a push with SP <
    // nSize) the raw subtraction underflows to a huge value; the real-mode segment add must
    // use the wrapped 16-bit SP so the write lands at SS:SP inside the stack segment.
    quint64 nSp = m_pExecRegs->getGPR(XEmuRegisters::GPR_RSP, nSpSize);
    if (m_nBits == 16 || m_bProtectedMode) {
        nSp += selectorBase(m_pExecRegs->nSS);
    }

    bool bOk = false;
    _noteWrite(nSp, nSize);  // a stack that overlaps code is unusual but entirely legal
    switch (nSize) {
        case 2: bOk = m_pMemoryManager->writeWord(nSp, (quint16)nValue); break;
        case 4: bOk = m_pMemoryManager->writeDword(nSp, (quint32)nValue); break;
        default: bOk = m_pMemoryManager->writeQword(nSp, nValue); break;
    }

    if (!bOk) {
        m_bExecFault = true;
        m_nFaultAddr = nSp;
    }
}

quint64 XEmuX86::_pop(int nSize)
{
    int nSpSize = (m_nBits == 64) ? 8
                  : m_bProtectedMode ? (selectorDefault32(m_pExecRegs->nSS) ? 4 : 2)
                                     : ((m_nBits == 16) ? 2 : 4);
    quint64 nSpOffset = m_pExecRegs->getGPR(XEmuRegisters::GPR_RSP, nSpSize);

    quint64 nSp = nSpOffset;
    if (m_nBits == 16 || m_bProtectedMode) {
        nSp += selectorBase(m_pExecRegs->nSS);
    }

    bool bOk = false;
    quint64 nValue = 0;
    switch (nSize) {
        case 2: nValue = m_pMemoryManager->readWord(nSp, &bOk); break;
        case 4: nValue = m_pMemoryManager->readDword(nSp, &bOk); break;
        default: nValue = m_pMemoryManager->readQword(nSp, &bOk); break;
    }

    if (!bOk) {
        m_bExecFault = true;
        m_nFaultAddr = nSp;
    }

    m_pExecRegs->setGPR(XEmuRegisters::GPR_RSP, nSpSize, nSpOffset + nSize);
    return nValue;
}

// Sized memory element read/write used by the string ops (movs/stos/lods/scas/cmps).
quint64 XEmuX86::_memReadSized(XADDR nAddress, int nSize)
{
    nAddress = _wrapA20(nAddress);
    bool bRead = false;
    quint64 nValue = 0;
    switch (nSize) {
        case 1: nValue = m_pMemoryManager->readByte(nAddress, &bRead); break;
        case 2: nValue = m_pMemoryManager->readWord(nAddress, &bRead); break;
        case 4: nValue = m_pMemoryManager->readDword(nAddress, &bRead); break;
        default: nValue = m_pMemoryManager->readQword(nAddress, &bRead); break;
    }
    if (!bRead) {
        m_bExecFault = true;
        m_nFaultAddr = nAddress;
    }
    return nValue;
}

void XEmuX86::_smcMark(XADDR nFrom, XADDR nTo)
{
    if (nFrom >= (XADDR)N_SMC_LIMIT) {
        return;
    }
    if (nTo > (XADDR)N_SMC_LIMIT) {
        nTo = N_SMC_LIMIT;
    }
    for (XADDR a = nFrom / N_SMC_GRAN; a <= (nTo - 1) / N_SMC_GRAN; a++) {
        m_smcMap[a >> 3] |= (quint8)(1u << (a & 7));
    }
}

bool XEmuX86::_smcHit(XADDR nFrom, XADDR nTo) const
{
    if (nFrom >= (XADDR)N_SMC_LIMIT) {
        return false;
    }
    if (nTo > (XADDR)N_SMC_LIMIT) {
        nTo = N_SMC_LIMIT;
    }
    for (XADDR a = nFrom / N_SMC_GRAN; a <= (nTo - 1) / N_SMC_GRAN; a++) {
        if (m_smcMap[a >> 3] & (quint8)(1u << (a & 7))) {
            return true;
        }
    }
    return false;
}

void XEmuX86::_memWriteSized(XADDR nAddress, quint64 nValue, int nSize)
{
    nAddress = _wrapA20(nAddress);
    // A write that lands on already-translated code must drop those translations, or the stale
    // decode would be re-executed (self-modifying / self-decrypting code). _noteWrite handles every
    // width -- the old check here was gated on m_nBits == 16, so 32-bit self-decrypting code (i.e.
    // essentially every PE packer) executed stale blocks.
    _noteWrite(nAddress, nSize);

    bool bWrite = false;
    switch (nSize) {
        case 1: bWrite = m_pMemoryManager->writeByte(nAddress, (quint8)nValue); break;
        case 2: bWrite = m_pMemoryManager->writeWord(nAddress, (quint16)nValue); break;
        case 4: bWrite = m_pMemoryManager->writeDword(nAddress, (quint32)nValue); break;
        default: bWrite = m_pMemoryManager->writeQword(nAddress, nValue); break;
    }
    if (!bWrite) {
        m_bExecFault = true;
        m_nFaultAddr = nAddress;
    }
}

// ================= x87 FPU ================================================
//
// The eight registers form a stack: ST(i) is the physical register m_fpuReg[(TOP+i)&7].
// Values are held as C doubles -- 80-bit extended precision is approximated, which is
// exact for the integer-valued and ordinary arithmetic real code (and packers) rely on.

void XEmuX86::_fpuInit()
{
    for (int i = 0; i < 8; i++) {
        m_fpuReg[i] = 0.0;
        m_fpuInt[i] = 0;
        m_fpuIsInt[i] = false;
        m_fpuTag[i] = 3;  // empty
    }
    m_fpuTop = 0;
    m_fpuControl = 0x037F;  // all exceptions masked, round-to-nearest, 64-bit precision
    m_fpuStatusCC = 0;
    m_bFpuInit = true;
}

double XEmuX86::_fpuGet(int i) const
{
    return m_fpuReg[(m_fpuTop + i) & 7];
}

void XEmuX86::_fpuSet(int i, double v)
{
    int nPhys = (m_fpuTop + i) & 7;
    m_fpuReg[nPhys] = v;
    m_fpuIsInt[nPhys] = false;  // a computed double is no longer an exact-integer accumulator
    m_fpuTag[nPhys] = (v == 0.0) ? 1 : 0;
}

void XEmuX86::_fpuPush(double v)
{
    m_fpuTop = (m_fpuTop - 1) & 7;
    m_fpuReg[m_fpuTop] = v;
    m_fpuIsInt[m_fpuTop] = false;
    m_fpuTag[m_fpuTop] = (v == 0.0) ? 1 : 0;
}

void XEmuX86::_fpuPushInt(qint64 v)
{
    // FILD: keep the exact 64-bit integer alongside the double so a later FIST/FISTP can
    // store it losslessly (the double alone loses the bits above 2^53).
    m_fpuTop = (m_fpuTop - 1) & 7;
    m_fpuReg[m_fpuTop] = (double)v;
    m_fpuInt[m_fpuTop] = v;
    m_fpuIsInt[m_fpuTop] = true;
    m_fpuTag[m_fpuTop] = (v == 0) ? 1 : 0;
}

void XEmuX86::_fpuPop()
{
    m_fpuTag[m_fpuTop] = 3;  // ST(0) becomes empty
    m_fpuIsInt[m_fpuTop] = false;  // drop the exact-int shadow so a re-exposed empty slot never reads stale
    m_fpuTop = (m_fpuTop + 1) & 7;
}

bool XEmuX86::_fpuEmpty(int i) const
{
    return m_fpuTag[(m_fpuTop + i) & 7] == 3;
}

// C3 C2 C0 encode the compare result in the status word (bits 14/10/8); C1 (bit 9) is 0.
void XEmuX86::_fpuCompare(double a, double b, bool bUnordered)
{
    Q_UNUSED(bUnordered)
    m_fpuStatusCC &= ~((1u << 14) | (1u << 10) | (1u << 9) | (1u << 8));
    if (std::isnan(a) || std::isnan(b)) {
        m_fpuStatusCC |= (1u << 14) | (1u << 10) | (1u << 8);  // C3=C2=C0=1 (unordered)
    } else if (a > b) {
        // C3=C2=C0=0
    } else if (a < b) {
        m_fpuStatusCC |= (1u << 8);  // C0=1
    } else {
        m_fpuStatusCC |= (1u << 14);  // C3=1 (equal)
    }
}

quint16 XEmuX86::_fpuStatusWord() const
{
    return (quint16)((m_fpuStatusCC & ((1u << 14) | (1u << 10) | (1u << 9) | (1u << 8))) | ((quint32)(m_fpuTop & 7) << 11));
}

void XEmuX86::_decodeFpu(DEC &dec, XEmuMicroOp &op, quint8 nOpcode)
{
    bool bOk = false;
    quint8 nModRM = m_pMemoryManager->fetchByte(dec.nFetch, &bOk);  // peek (do not consume yet)
    int nMod = nModRM >> 6;
    int nReg = (nModRM >> 3) & 7;

    op.kind = MOP_FPU;
    op.nAluOp = nOpcode;
    op.nImm = nModRM;
    op.nSize = 0;
    op.nSrcSize = 0;  // memory type: 0 none, 1 f32, 2 f64, 3 f80, 4 i16, 5 i32, 6 i64
    op.sText = QStringLiteral("fpu");

    if (nMod != 3) {
        int nType = 0, nBytes = 0;
        switch (nOpcode) {
            case 0xD8: nType = 1; nBytes = 4; break;  // m32real
            case 0xDC: nType = 2; nBytes = 8; break;  // m64real
            case 0xDA: nType = 5; nBytes = 4; break;  // m32int
            case 0xDE: nType = 4; nBytes = 2; break;  // m16int
            case 0xD9: (nReg == 5 || nReg == 7) ? (nType = 4, nBytes = 2) : (nType = 1, nBytes = 4); break;   // FLDCW/FNSTCW : FLD/FST m32
            case 0xDB: (nReg == 5 || nReg == 7) ? (nType = 3, nBytes = 10) : (nType = 5, nBytes = 4); break;  // FLD/FSTP m80 : FILD/FISTP m32
            case 0xDD: (nReg == 7) ? (nType = 4, nBytes = 2) : (nType = 2, nBytes = 8); break;                // FNSTSW m16 : FLD/FST m64
            case 0xDF:
                if (nReg == 5 || nReg == 7) {
                    nType = 6;
                    nBytes = 8;  // FILD/FISTP m64int
                } else if (nReg == 4 || nReg == 6) {
                    nType = 3;
                    nBytes = 10;  // FBLD/FBSTP m80 (BCD approximated as extended)
                } else {
                    nType = 4;
                    nBytes = 2;  // FILD/FISTP m16int
                }
                break;
        }
        op.nSrcSize = nType;
        op.nSize = nBytes;
        int nRegField = 0;
        _decodeModRM(dec, nRegField, op.dst);  // consumes ModRM + displacement; builds the memory operand
    } else {
        _fetch8(dec);  // register form / no-operand: just consume the ModRM byte
    }
}

void XEmuX86::_execFpu(const XEmuMicroOp &op)
{
    if (!m_bFpuInit) {
        _fpuInit();
    }

    const quint8 nOpcode = (quint8)op.nAluOp;
    const quint8 nModRM = (quint8)op.nImm;
    const int nMod = nModRM >> 6;
    const int nReg = (nModRM >> 3) & 7;
    const int nRM = nModRM & 7;
    const bool bMem = (nMod != 3);

    XADDR nAddr = bMem ? _resolveAddr(op, op.dst) : 0;

    struct FPU_MEMORY_ACCESS {
        XEmuX86 *pOwner;
        const XEmuMicroOp *pOperation;
        XADDR nAddress;

        double readReal() const
        {
            switch (pOperation->nSrcSize) {
            case 1: {
                quint32 b = (quint32)pOwner->_memReadSized(nAddress, 4);
                float f;
                memcpy(&f, &b, 4);
                return (double)f;
            }
            case 2: {
                quint64 b = pOwner->_memReadSized(nAddress, 8);
                double d;
                memcpy(&d, &b, 8);
                return d;
            }
            case 3: return readF80Value(pOwner->m_pMemoryManager, nAddress);
            case 4: return (double)(qint16)(quint16)pOwner->_memReadSized(nAddress, 2);
            case 5: return (double)(qint32)(quint32)pOwner->_memReadSized(nAddress, 4);
            case 6: return (double)(qint64)pOwner->_memReadSized(nAddress, 8);
            }
            return 0.0;
        }

        void writeReal(double v) const
        {
            switch (pOperation->nSrcSize) {
            case 1: {
                float f = (float)v;
                quint32 b;
                memcpy(&b, &f, 4);
                pOwner->_memWriteSized(nAddress, b, 4);
                break;
            }
            case 2: {
                quint64 b;
                memcpy(&b, &v, 8);
                pOwner->_memWriteSized(nAddress, b, 8);
                break;
            }
            case 3: writeF80Value(pOwner->m_pMemoryManager, nAddress, v); break;
            case 4: pOwner->_memWriteSized(nAddress, (quint64)(qint16)std::llround(v), 2); break;
            case 5: pOwner->_memWriteSized(nAddress, (quint64)(qint32)std::llround(v), 4); break;
            case 6: pOwner->_memWriteSized(nAddress, (quint64)(qint64)std::llround(v), 8); break;
            }
        }

        qint64 readInteger() const
        {
            switch (pOperation->nSrcSize) {
            case 4: return (qint64)(qint16)(quint16)pOwner->_memReadSized(nAddress, 2);
            case 5: return (qint64)(qint32)(quint32)pOwner->_memReadSized(nAddress, 4);
            case 6: return (qint64)pOwner->_memReadSized(nAddress, 8);
            }
            return 0;
        }

        void storeTopInteger() const
        {
            // Keep exact FILD values lossless across FIST/FISTP stores. The double model
            // would otherwise corrupt integer values above 2^53.
            const qint64 iv = pOwner->m_fpuIsInt[pOwner->m_fpuTop]
                                  ? pOwner->m_fpuInt[pOwner->m_fpuTop]
                                  : (qint64)std::llround(pOwner->_fpuGet(0));
            switch (pOperation->nSrcSize) {
            case 4: pOwner->_memWriteSized(nAddress, (quint64)(quint16)(qint16)iv, 2); break;
            case 5: pOwner->_memWriteSized(nAddress, (quint64)(quint32)(qint32)iv, 4); break;
            case 6: pOwner->_memWriteSized(nAddress, (quint64)iv, 8); break;
            }
        }
    };
    const FPU_MEMORY_ACCESS fpuMemoryAccess = {this, &op, nAddr};

    if (bMem) {
        switch (nOpcode) {
            case 0xD8:  // arith ST(0), m32real  (reg selects op; 2/3 are FCOM/FCOMP)
            case 0xDC:  // arith ST(0), m64real
            case 0xDA:  // arith ST(0), m32int
            case 0xDE: {  // arith ST(0), m16int
                double m = fpuMemoryAccess.readReal();
                if (nReg == 2 || nReg == 3) {  // FCOM / FCOMP
                    _fpuCompare(_fpuGet(0), m, false);
                    if (nReg == 3) _fpuPop();
                } else {
                    _fpuSet(0, fpuArithmetic(nReg, _fpuGet(0), m));
                }
                break;
            }
            case 0xD9:  // FLD m32 / FST/FSTP m32 / FLDCW / FNSTCW / FLDENV / FNSTENV
                if (nReg == 0) {
                    _fpuPush(fpuMemoryAccess.readReal());
                } else if (nReg == 2 || nReg == 3) {
                    fpuMemoryAccess.writeReal(_fpuGet(0));
                    if (nReg == 3) _fpuPop();
                } else if (nReg == 5) {  // FLDCW
                    m_fpuControl = (quint16)_memReadSized(nAddr, 2);
                } else if (nReg == 7) {  // FNSTCW
                    _memWriteSized(nAddr, m_fpuControl, 2);
                }
                // FLDENV(4)/FNSTENV(6): environment save/restore not modelled (no-op).
                break;
            case 0xDB:  // FILD m32 / FISTP m32 / FLD m80 / FSTP m80
                if (nReg == 0) {
                    _fpuPushInt(fpuMemoryAccess.readInteger());  // FILD m32int (exact)
                } else if (nReg == 2 || nReg == 3) {
                    fpuMemoryAccess.storeTopInteger();  // FIST/FISTP m32int (exact when integer-valued)
                    if (nReg == 3) _fpuPop();
                } else if (nReg == 5) {
                    _fpuPush(fpuMemoryAccess.readReal());  // FLD m80real
                } else if (nReg == 7) {
                    fpuMemoryAccess.writeReal(_fpuGet(0));  // FSTP m80real
                    _fpuPop();
                }
                break;
            case 0xDD:  // FLD m64 / FST/FSTP m64 / FNSTSW m16 / FRSTOR / FNSAVE
                if (nReg == 0) {
                    _fpuPush(fpuMemoryAccess.readReal());
                } else if (nReg == 2 || nReg == 3) {
                    fpuMemoryAccess.writeReal(_fpuGet(0));
                    if (nReg == 3) _fpuPop();
                } else if (nReg == 7) {  // FNSTSW m16
                    _memWriteSized(nAddr, _fpuStatusWord(), 2);
                }
                break;
            case 0xDF:  // FILD m16/m64 / FISTP m16/m64
                if (nReg == 0 || nReg == 5) {
                    _fpuPushInt(fpuMemoryAccess.readInteger());  // FILD m16int / m64int (exact)
                } else if (nReg == 2 || nReg == 3) {
                    fpuMemoryAccess.storeTopInteger();  // FIST/FISTP m16int (exact when integer-valued)
                    if (nReg == 3) _fpuPop();
                } else if (nReg == 7) {
                    fpuMemoryAccess.storeTopInteger();  // FISTP m64int (exact when integer-valued)
                    _fpuPop();
                }
                break;
        }
        return;
    }

    // ---- register form (mod == 3) --------------------------------------------
    const int i = nRM;  // ST(i)
    switch (nOpcode) {
        case 0xD8:  // FADD/FMUL/FCOM/FCOMP/FSUB/FSUBR/FDIV/FDIVR ST(0), ST(i)
            if (nReg == 2 || nReg == 3) {
                _fpuCompare(_fpuGet(0), _fpuGet(i), false);
                if (nReg == 3) _fpuPop();
            } else {
                _fpuSet(0, fpuArithmetic(nReg, _fpuGet(0), _fpuGet(i)));
            }
            break;
        case 0xDC:  // arith ST(i), ST(0)  (reversed operand order for SUB/DIV)
            if (nReg == 0) {
                _fpuSet(i, _fpuGet(i) + _fpuGet(0));
            } else if (nReg == 1) {
                _fpuSet(i, _fpuGet(i) * _fpuGet(0));
            } else if (nReg == 4) {
                _fpuSet(i, _fpuGet(0) - _fpuGet(i));  // FSUB (DC): ST(i) = ST(0) - ST(i)... encoded reversed
            } else if (nReg == 5) {
                _fpuSet(i, _fpuGet(i) - _fpuGet(0));
            } else if (nReg == 6) {
                _fpuSet(i, _fpuGet(0) / _fpuGet(i));
            } else if (nReg == 7) {
                _fpuSet(i, _fpuGet(i) / _fpuGet(0));
            }
            break;
        case 0xDE:  // FADDP/FMULP/.../FDIVRP ST(i), ST(0) then pop  (0xDED9 = FCOMPP)
            if (nModRM == 0xD9) {  // FCOMPP
                _fpuCompare(_fpuGet(0), _fpuGet(1), false);
                _fpuPop();
                _fpuPop();
            } else {
                double r = _fpuGet(i);
                if (nReg == 0) {
                    r = _fpuGet(i) + _fpuGet(0);
                } else if (nReg == 1) {
                    r = _fpuGet(i) * _fpuGet(0);
                } else if (nReg == 4) {
                    r = _fpuGet(0) - _fpuGet(i);
                } else if (nReg == 5) {
                    r = _fpuGet(i) - _fpuGet(0);
                } else if (nReg == 6) {
                    r = _fpuGet(0) / _fpuGet(i);
                } else if (nReg == 7) {
                    r = _fpuGet(i) / _fpuGet(0);
                }
                _fpuSet(i, r);
                _fpuPop();
            }
            break;
        case 0xD9:  // FLD ST(i) / FXCH / constants / unary / transcendental
            if (nReg == 0) {  // FLD ST(i)
                double v = _fpuGet(i);
                _fpuPush(v);
            } else if (nReg == 1) {  // FXCH ST(i)
                double t = _fpuGet(0);
                _fpuSet(0, _fpuGet(i));
                _fpuSet(i, t);
            } else if (nReg == 4) {  // FCHS/FABS/FTST/FXAM (rm selects)
                if (nRM == 0) _fpuSet(0, -_fpuGet(0));       // FCHS
                else if (nRM == 1) _fpuSet(0, std::fabs(_fpuGet(0)));  // FABS
                else if (nRM == 4) _fpuCompare(_fpuGet(0), 0.0, false);  // FTST
                else if (nRM == 5) {  // FXAM
                    double v = _fpuGet(0);
                    m_fpuStatusCC &= ~((1u << 14) | (1u << 10) | (1u << 9) | (1u << 8));
                    if (std::signbit(v)) m_fpuStatusCC |= (1u << 9);       // C1 = sign
                    if (_fpuEmpty(0)) m_fpuStatusCC |= (1u << 14) | (1u << 8);
                    else if (std::isnan(v)) m_fpuStatusCC |= (1u << 8);
                    else if (std::isinf(v)) m_fpuStatusCC |= (1u << 10) | (1u << 8);
                    else if (v == 0.0) m_fpuStatusCC |= (1u << 14);
                    else m_fpuStatusCC |= (1u << 10);
                }
            } else if (nReg == 5) {  // load constants
                static const double c[8] = {1.0, 3.321928094887362, 1.4426950408889634, 3.141592653589793, 0.3010299956639812, 0.6931471805599453, 0.0, 0.0};
                if (nRM <= 6) _fpuPush(c[nRM]);  // FLD1/FLDL2T/FLDL2E/FLDPI/FLDLG2/FLDLN2/FLDZ
            } else if (nReg == 6) {  // F2XM1/FYL2X/FPTAN/FPATAN/FXTRACT/FPREM1/FDECSTP/FINCSTP
                if (nRM == 0) _fpuSet(0, std::exp2(_fpuGet(0)) - 1.0);      // F2XM1
                else if (nRM == 1) { _fpuSet(1, _fpuGet(1) * std::log2(_fpuGet(0))); _fpuPop(); }  // FYL2X
                else if (nRM == 2) { double t = std::tan(_fpuGet(0)); _fpuSet(0, t); _fpuPush(1.0); }  // FPTAN
                else if (nRM == 3) { double r = std::atan2(_fpuGet(1), _fpuGet(0)); _fpuSet(1, r); _fpuPop(); }  // FPATAN
                else if (nRM == 6) m_fpuTop = (m_fpuTop - 1) & 7;  // FDECSTP
                else if (nRM == 7) m_fpuTop = (m_fpuTop + 1) & 7;  // FINCSTP
            } else if (nReg == 7) {  // FPREM/FYL2XP1/FSQRT/FSINCOS/FRNDINT/FSCALE/FSIN/FCOS
                if (nRM == 0) _fpuSet(0, std::fmod(_fpuGet(0), _fpuGet(1)));          // FPREM
                else if (nRM == 1) { _fpuSet(1, _fpuGet(1) * std::log2(_fpuGet(0) + 1.0)); _fpuPop(); }  // FYL2XP1
                else if (nRM == 2) _fpuSet(0, std::sqrt(_fpuGet(0)));                // FSQRT
                else if (nRM == 3) { double s = std::sin(_fpuGet(0)); double c2 = std::cos(_fpuGet(0)); _fpuSet(0, s); _fpuPush(c2); }  // FSINCOS
                else if (nRM == 4) _fpuSet(0, std::nearbyint(_fpuGet(0)));           // FRNDINT
                else if (nRM == 5) { _fpuSet(0, std::ldexp(_fpuGet(0), (int)_fpuGet(1))); }  // FSCALE
                else if (nRM == 6) _fpuSet(0, std::sin(_fpuGet(0)));                 // FSIN
                else if (nRM == 7) _fpuSet(0, std::cos(_fpuGet(0)));                 // FCOS
            }
            // nReg==2 FNOP / nReg==3 (FSTP1) : no-op
            break;
        case 0xDA:  // FCMOVcc ST(0), ST(i)  (0xDAE9 = FUCOMPP)
            if (nModRM == 0xE9) {
                _fpuCompare(_fpuGet(0), _fpuGet(1), true);
                _fpuPop();
                _fpuPop();
            } else {
                bool bCC = (nReg == 0) ? m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF) : (nReg == 1) ? m_pExecRegs->getFlag(XEmuRegisters::FLAG_ZF) : (nReg == 2) ? (m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF) || m_pExecRegs->getFlag(XEmuRegisters::FLAG_ZF)) : !m_pExecRegs->getFlag(XEmuRegisters::FLAG_PF);
                if (bCC) _fpuSet(0, _fpuGet(i));
            }
            break;
        case 0xDB:  // FCMOVcc / FCLEX / FINIT / FUCOMI / FCOMI
            if (nModRM == 0xE2) {
                m_fpuStatusCC = 0;  // FNCLEX
            } else if (nModRM == 0xE3) {
                _fpuInit();  // FNINIT
            } else if (nReg == 5 || nReg == 6) {  // FUCOMI/FCOMI ST(0),ST(i): set EFLAGS ZF/PF/CF
                double a = _fpuGet(0), b = _fpuGet(i);
                bool bU = std::isnan(a) || std::isnan(b);
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, bU || (a == b));
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, bU);
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bU || (a < b));
            } else if (nReg <= 3) {  // FCMOVcc (NB / NE / NBE / NU)
                bool bCC = (nReg == 0) ? !m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF) : (nReg == 1) ? !m_pExecRegs->getFlag(XEmuRegisters::FLAG_ZF) : (nReg == 2) ? !(m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF) || m_pExecRegs->getFlag(XEmuRegisters::FLAG_ZF)) : m_pExecRegs->getFlag(XEmuRegisters::FLAG_PF);
                if (bCC) _fpuSet(0, _fpuGet(i));
            }
            break;
        case 0xDD:  // FFREE / FST/FSTP ST(i) / FUCOM/FUCOMP ST(i)
            if (nReg == 0) {
                m_fpuTag[(m_fpuTop + i) & 7] = 3;  // FFREE
                m_fpuIsInt[(m_fpuTop + i) & 7] = false;
            } else if (nReg == 2 || nReg == 3) {
                _fpuSet(i, _fpuGet(0));  // FST/FSTP ST(i)
                if (nReg == 3) _fpuPop();
            } else if (nReg == 4 || nReg == 5) {
                _fpuCompare(_fpuGet(0), _fpuGet(i), true);  // FUCOM/FUCOMP
                if (nReg == 5) _fpuPop();
            }
            break;
        case 0xDF:  // FNSTSW AX / FUCOMIP / FCOMIP
            if (nModRM == 0xE0) {
                m_pExecRegs->setGPR(XEmuRegisters::GPR_RAX, 2, _fpuStatusWord());  // FNSTSW AX
            } else if (nReg == 5 || nReg == 6) {  // FUCOMIP/FCOMIP ST(0),ST(i)
                double a = _fpuGet(0), b = _fpuGet(i);
                bool bU = std::isnan(a) || std::isnan(b);
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, bU || (a == b));
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, bU);
                m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bU || (a < b));
                _fpuPop();
            }
            break;
    }
}

void XEmuX86::_setFlagsAdd(quint64 a, quint64 b, quint64 res, int nSize)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    quint64 A = a & nMask;
    quint64 B = b & nMask;
    quint64 R = res & nMask;

    bool bCF = (nSize < 8) ? (((A + B) >> (nSize * 8)) & 1) != 0 : (R < A);
    bool bOF = ((~(A ^ B)) & (A ^ R) & nSign) != 0;
    bool bAF = ((A ^ B ^ R) & 0x10) != 0;

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bCF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, bOF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, bAF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

void XEmuX86::_setFlagsSub(quint64 a, quint64 b, quint64 res, int nSize)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    quint64 A = a & nMask;
    quint64 B = b & nMask;
    quint64 R = res & nMask;

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, A < B);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, ((A ^ B) & (A ^ R) & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, ((A ^ B ^ R) & 0x10) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

void XEmuX86::_setFlagsAdc(quint64 a, quint64 b, quint64 carry, quint64 res, int nSize)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    quint64 A = a & nMask;
    quint64 B = b & nMask;
    quint64 R = res & nMask;

    // True carry-out of a + b + carry, computed without folding the carry into an
    // operand (which would lose the carry when b + carry wraps the operand width).
    bool bCF;
    if (nSize < 8) {
        bCF = (((A + B + carry) >> (nSize * 8)) & 1) != 0;
    } else {
        quint64 nLow = A + B;
        bCF = (nLow < A) || ((nLow + carry) < nLow);
    }

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bCF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, ((~(A ^ B)) & (A ^ R) & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, (((A & 0xF) + (B & 0xF) + carry) & 0x10) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

void XEmuX86::_setFlagsSbb(quint64 a, quint64 b, quint64 borrow, quint64 res, int nSize)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    quint64 A = a & nMask;
    quint64 B = b & nMask;
    quint64 R = res & nMask;

    // a - b - borrow underflows iff a < b + borrow (infinite precision). Expressed
    // width-safely: with borrow it is a <= b, without it is a < b.
    bool bCF = borrow ? (A <= B) : (A < B);

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bCF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, ((A ^ B) & (A ^ R) & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, (((A & 0xF) - (B & 0xF) - borrow) & 0x10) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

void XEmuX86::_setFlagsLogic(quint64 res, int nSize)
{
    quint64 R = res & _mask(nSize);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, false);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, false);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, false);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & _signBit(nSize)) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

void XEmuX86::_setFlagsIncDec(quint64 a, quint64 res, int nSize, bool bInc)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    quint64 A = a & nMask;
    quint64 R = res & nMask;

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, (((bInc ? ~(A ^ 1) : (A ^ 1))) & (A ^ R) & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, ((A ^ 1 ^ R) & 0x10) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, R == 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (R & nSign) != 0);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)R));
}

quint64 XEmuX86::_aluCompute(int nAluOp, quint64 a, quint64 b, int nSize, bool &bWriteBack)
{
    bWriteBack = true;
    quint64 nResult = 0;
    quint64 nCarry = m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF) ? 1 : 0;

    switch (nAluOp) {
        case 0: nResult = a + b; _setFlagsAdd(a, b, nResult, nSize); break;                    // ADD
        case 1: nResult = a | b; _setFlagsLogic(nResult, nSize); break;                        // OR
        case 2: nResult = a + b + nCarry; _setFlagsAdc(a, b, nCarry, nResult, nSize); break;  // ADC
        case 3: nResult = a - b - nCarry; _setFlagsSbb(a, b, nCarry, nResult, nSize); break;  // SBB
        case 4: nResult = a & b; _setFlagsLogic(nResult, nSize); break;                        // AND
        case 5: nResult = a - b; _setFlagsSub(a, b, nResult, nSize); break;                    // SUB
        case 6: nResult = a ^ b; _setFlagsLogic(nResult, nSize); break;                        // XOR
        case 7: nResult = a - b; _setFlagsSub(a, b, nResult, nSize); bWriteBack = false; break;  // CMP
    }

    return nResult & _mask(nSize);
}

quint64 XEmuX86::_doShift(int nShiftOp, quint64 nValue, int nSize, quint8 nCount)
{
    quint64 nMask = _mask(nSize);
    quint64 nSign = _signBit(nSize);
    int nBits = nSize * 8;
    quint64 v = nValue & nMask;

    // x86 masks the count to 5 bits (6 for a 64-bit operand).
    quint8 nCnt = (nSize == 8) ? (nCount & 0x3F) : (nCount & 0x1F);

    if (nCnt == 0) {
        return v;  // no operation, flags unaffected
    }

#if defined(_M_X64) && defined(_WIN32)
    // Undefined region: a real shift (SHL/SHR/SAR, not a rotate) whose masked count is
    // >= the operand width. Only 8/16-bit operands reach it; execute on the host CPU to
    // reproduce its exact (microarchitecture-specific) result and flags.
    if ((nShiftOp >= 4) && (nSize <= 2) && (nCnt >= (quint8)nBits)) {
        quint8 insn[6];
        const int ilen = buildShiftInsn(insn, nShiftOp, nSize);
        quint32 f = (quint32)m_pExecRegs->nRFLAGS;
        quint32 res = 0;
        if (hostShiftExec(insn, ilen, (quint32)v, 0, nCnt, &f, &res)) {
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, (f & 0x001) != 0);
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, (f & 0x004) != 0);
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, (f & 0x010) != 0);
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, (f & 0x040) != 0);
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (f & 0x080) != 0);
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, (f & 0x800) != 0);
            return (quint64)res & nMask;
        }
    }
#endif

    bool bCF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF);
    bool bOF = false;

    switch (nShiftOp) {
        case 0:  // ROL
            for (quint8 i = 0; i < nCnt; i++) {
                bool bMsb = (v & nSign) != 0;
                v = ((v << 1) | (bMsb ? 1 : 0)) & nMask;
                bCF = bMsb;
            }
            bOF = (((v & nSign) != 0) != bCF);
            break;
        case 1:  // ROR
            for (quint8 i = 0; i < nCnt; i++) {
                bool bLsb = (v & 1) != 0;
                v = ((v >> 1) | (bLsb ? nSign : 0)) & nMask;
                bCF = bLsb;
            }
            bOF = (((v & nSign) != 0) != (((v << 1) & nSign) != 0));
            break;
        case 2:  // RCL (rotate through carry)
            for (quint8 i = 0; i < nCnt; i++) {
                bool bMsb = (v & nSign) != 0;
                v = ((v << 1) | (bCF ? 1 : 0)) & nMask;
                bCF = bMsb;
            }
            bOF = (((v & nSign) != 0) != bCF);
            break;
        case 3:  // RCR
            for (quint8 i = 0; i < nCnt; i++) {
                bool bLsb = (v & 1) != 0;
                bool bOldCF = bCF;
                bCF = bLsb;
                v = ((v >> 1) | (bOldCF ? nSign : 0)) & nMask;
            }
            bOF = (((v & nSign) != 0) != (((v << 1) & nSign) != 0));
            break;
        case 4:  // SHL
        case 6:  // SAL (== SHL)
            bCF = (nCnt <= (quint8)nBits) ? (((v >> (nBits - nCnt)) & 1) != 0) : false;
            v = (v << nCnt) & nMask;
            bOF = (((v & nSign) != 0) != bCF);
            break;
        case 5:  // SHR (logical)
            bCF = ((v >> (nCnt - 1)) & 1) != 0;
            bOF = (nValue & nSign) != 0;  // OF (count 1) = MSB of original
            v = (v >> nCnt) & nMask;
            break;
        case 7: {  // SAR (arithmetic)
            // Once the count reaches the operand width, every further bit shifted out is
            // the sign bit, so CF settles on the sign (v>>(nCnt-1) would read past the
            // operand and wrongly yield 0).
            quint8 nEff = (nCnt < (quint8)nBits) ? nCnt : (quint8)nBits;
            bCF = ((v >> (nEff - 1)) & 1) != 0;
            v = (quint64)(_signExtend(v, nSize) >> nCnt) & nMask;
            bOF = false;
            break;
        }
    }

    // OF for multi-bit shifts is "undefined", but real x86 is consistent and
    // type-specific (conformance-verified): SHL keeps OF = MSB(result) XOR CF for every
    // count; SHR clears OF for count > 1; SAR's OF is already 0. Only SHR needs the
    // override here (rotates, handled above, keep their computed OF).
    if (nShiftOp == 5 && nCnt > 1) {  // SHR
        bOF = false;
    }

    m_pExecRegs->setFlag(XEmuRegisters::FLAG_CF, bCF);
    m_pExecRegs->setFlag(XEmuRegisters::FLAG_OF, bOF);

    if (nShiftOp >= 4) {  // shifts (not rotates) also set SF/ZF/PF from the result
        m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, (v & nMask) == 0);
        m_pExecRegs->setFlag(XEmuRegisters::FLAG_SF, (v & nSign) != 0);
        m_pExecRegs->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)v));
        // AF is architecturally "undefined" for shifts, but real x86 SETS it. VMProtect
        // folds even the undefined flags (pushfd after a shift) into its VM rolling key
        // as an anti-emulation trap, so matching hardware here is required to stay in
        // lock-step. (No correct program depends on this, so it cannot regress others.)
        m_pExecRegs->setFlag(XEmuRegisters::FLAG_AF, true);
    }

    return v & nMask;
}

bool XEmuX86::_evalCond(quint8 nCond)
{
    bool bCF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_CF);
    bool bZF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_ZF);
    bool bSF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_SF);
    bool bOF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_OF);
    bool bPF = m_pExecRegs->getFlag(XEmuRegisters::FLAG_PF);

    bool bBase = false;
    switch (nCond >> 1) {
        case 0: bBase = bOF; break;
        case 1: bBase = bCF; break;
        case 2: bBase = bZF; break;
        case 3: bBase = bCF || bZF; break;
        case 4: bBase = bSF; break;
        case 5: bBase = bPF; break;
        case 6: bBase = (bSF != bOF); break;
        case 7: bBase = bZF || (bSF != bOF); break;
    }

    return (nCond & 1) ? !bBase : bBase;
}

void XEmuX86::_execOp(const XEmuMicroOp &op, XEmuRegisters *pRegisters, STEP_INFO &info)
{
    m_pExecRegs = pRegisters;
    m_bExecFault = false;
    m_nInsnCount++;  // a physical time base for modeling the video retrace timing (port 0x3DA)
    const bool bTfBefore = pRegisters->getFlag(XEmuRegisters::FLAG_TF);  // for the single-step trap below

    m_pMemoryManager->fireCodeHook(op.nAddress, op.nLength);  // code hook: once per instruction

    info.result = STEP_OK;
    info.nAddress = op.nAddress;
    info.nLength = op.nLength;
    info.sText = op.sText;

    // Opt-in instruction ring buffer (XEMU_FAULTDUMP): record each step's PC, mnemonic
    // and the resolved memory operand so a fault can be traced back to the instruction
    // that produced the bad value. Near-zero cost when the env var is unset.
    static const bool s_bFaultDump = qEnvironmentVariableIsSet("XEMU_FAULTDUMP");
    static XADDR s_ringPc[256];
    static XADDR s_ringMem[256];
    static char s_ringOp[256][20];
    static int s_ringN = 0;
    if (s_bFaultDump) {
        const int i = s_ringN & 255;
        s_ringPc[i] = op.nAddress;
        s_ringMem[i] = op.src.bIsMem ? _resolveAddr(op, op.src) : (op.dst.bIsMem ? _resolveAddr(op, op.dst) : 0);
        const QByteArray t = op.sText.toLatin1();
        const int m = qMin(19, t.size());
        memcpy(s_ringOp[i], t.constData(), m);
        s_ringOp[i][m] = 0;
        s_ringN++;
    }

    XADDR nFall = op.nAddress + op.nLength;
    bool bBranch = false;
    int nPtrSize = (m_nBits == 64) ? 8 : ((m_nBits == 16) ? 2 : 4);

    // Real mode keeps a linear PC, but a near ret / indirect near jmp|call recovers only
    // the 16-bit IP (offset). Re-form the linear address as (CS << 4) + IP for those.
    const quint64 nCodeSegBase = (m_nBits == 16 || m_bProtectedMode) ? selectorBase(pRegisters->nCS) : 0;
    auto setFarPC = [&](quint16 selector, quint64 offset) {
        pRegisters->nCS = selector;
        pRegisters->nRIP = selectorBase(selector) + offset;
        if (m_bProtectedMode) {
            setBits(selectorDefault32(selector) ? 32 : 16);
        }
    };

    // In 16-bit real mode a near relative branch wraps within the 64 KiB code segment: the
    // target offset is taken modulo 0x10000 before the segment base is re-applied, so a large
    // negative displacement can't underflow below the segment (crossing into unmapped memory).
    switch (op.kind) {
        case MOP_NOP:
            break;
        case MOP_ALU_RM_R:
        case MOP_ALU_R_RM: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 b = _readOpnd(op, op.src, op.nSize);
            bool bWriteBack = false;
            quint64 r = _aluCompute(op.nAluOp, a, b, op.nSize, bWriteBack);
            if (bWriteBack) {
                _writeOpnd(op, op.dst, op.nSize, r);
            }
            break;
        }
        case MOP_ALU_RAX_IMM: {
            quint64 a = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize);
            bool bWriteBack = false;
            quint64 r = _aluCompute(op.nAluOp, a, op.nImm & _mask(op.nSize), op.nSize, bWriteBack);
            if (bWriteBack) {
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, r);
            }
            break;
        }
        case MOP_ALU_RM_IMM: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            bool bWriteBack = false;
            quint64 r = _aluCompute(op.nAluOp, a, op.nImm, op.nSize, bWriteBack);
            if (bWriteBack) {
                _writeOpnd(op, op.dst, op.nSize, r);
            }
            break;
        }
        case MOP_MOV:
            _writeOpnd(op, op.dst, op.nSize, _readOpnd(op, op.src, op.nSize));
            break;
        case MOP_MOV_IMM:
            _writeOpnd(op, op.dst, op.nSize, op.nImm);
            break;
        case MOP_LEA:
            pRegisters->setGPR(op.dst.nReg, op.nSize, _resolveAddr(op, op.src, /*bOffsetOnly=*/true) & _mask(op.nSize));
            break;
        case MOP_MOVZX:
            pRegisters->setGPR(op.dst.nReg, op.nSize, _readOpnd(op, op.src, op.nSrcSize) & _mask(op.nSrcSize));
            break;
        case MOP_MOVSX:
            pRegisters->setGPR(op.dst.nReg, op.nSize, (quint64)_signExtend(_readOpnd(op, op.src, op.nSrcSize), op.nSrcSize) & _mask(op.nSize));
            break;
        case MOP_TEST: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 b = _readOpnd(op, op.src, op.nSize);
            _setFlagsLogic(a & b, op.nSize);
            break;
        }
        case MOP_TEST_IMM:
            _setFlagsLogic(_readOpnd(op, op.dst, op.nSize) & op.nImm, op.nSize);
            break;
        case MOP_PUSH: {
            quint64 nValue = (op.src.bIsReg || op.src.bIsMem) ? _readOpnd(op, op.src, op.nSize) : op.nImm;
            _push(nValue, op.nSize);
            break;
        }
        case MOP_POP:
            _writeOpnd(op, op.dst, op.nSize, _pop(op.nSize));
            break;
        case MOP_INCDEC: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 r = (op.nAluOp == 0) ? (a + 1) : (a - 1);
            _setFlagsIncDec(a, r, op.nSize, op.nAluOp == 0);
            _writeOpnd(op, op.dst, op.nSize, r);
            break;
        }
        case MOP_SETCC:
            _writeOpnd(op, op.dst, 1, _evalCond(op.nCond) ? 1 : 0);
            break;
        case MOP_CMOVCC:
            // Only writes (and, for a 32-bit operand, zero-extends) when taken.
            if (_evalCond(op.nCond)) {
                pRegisters->setGPR(op.dst.nReg, op.nSize, _readOpnd(op, op.src, op.nSize));
            }
            break;
        case MOP_JMP:
            pRegisters->nRIP = wrapNearBranch(m_nBits, nCodeSegBase, op.nBranchTarget);
            bBranch = true;
            break;
        case MOP_JMP_IND:
            pRegisters->nRIP = wrapNearBranch(m_nBits, nCodeSegBase, nCodeSegBase + _readOpnd(op, op.src, op.nSize));
            bBranch = true;
            break;
        case MOP_JCC:
            pRegisters->nRIP = _evalCond(op.nCond) ? wrapNearBranch(m_nBits, nCodeSegBase, op.nBranchTarget) : nFall;
            bBranch = true;
            break;
        case MOP_CALL:
            // Real mode pushes the 16-bit return IP (offset within CS), which a near ret adds
            // back to (CS << 4). Pushing the full linear address only matches when the segment
            // base is a multiple of 64 KiB (CS a multiple of 0x1000) -- broken once code runs at
            // a relocated segment like 0x13E7, so push the segment-relative offset in 16-bit mode.
            _push((m_nBits == 16 || m_bProtectedMode) ? (nFall - nCodeSegBase) : nFall, nPtrSize);
            pRegisters->nRIP = wrapNearBranch(m_nBits, nCodeSegBase, op.nBranchTarget);
            bBranch = true;
            break;
        case MOP_CALL_IND: {
            quint64 nTarget = wrapNearBranch(m_nBits, nCodeSegBase, nCodeSegBase + _readOpnd(op, op.src, op.nSize));
            _push((m_nBits == 16 || m_bProtectedMode) ? (nFall - nCodeSegBase) : nFall, nPtrSize);
            pRegisters->nRIP = nTarget;
            bBranch = true;
            break;
        }
        case MOP_JMP_FAR: {
            quint16 nNewCS = (quint16)op.nImm;
            setFarPC(nNewCS, m_bProtectedMode ? op.nBranchTarget : (op.nBranchTarget & 0xFFFF));
            bBranch = true;
            break;
        }
        case MOP_CALL_FAR: {
            quint16 nNewCS = (quint16)op.nImm;
            const int nFarSize = m_bProtectedMode ? nPtrSize : 2;
            _push(pRegisters->nCS, nFarSize);
            _push(nFall - nCodeSegBase, nFarSize);
            setFarPC(nNewCS, m_bProtectedMode ? op.nBranchTarget : (op.nBranchTarget & 0xFFFF));
            bBranch = true;
            break;
        }
        case MOP_JMP_FAR_IND:
        case MOP_CALL_FAR_IND: {
            XADDR nPtr = _resolveAddr(op, op.src);
            bool bOk1 = false, bOk2 = false;
            quint64 nNewIP = _memReadSized(nPtr, op.nSize);
            bOk1 = !m_bExecFault;
            quint16 nNewCS = m_pMemoryManager->readWord(nPtr + op.nSize, &bOk2);
            if (!bOk1 || !bOk2) {
                m_bExecFault = true;
                m_nFaultAddr = nPtr;
                break;
            }
            if (op.kind == MOP_CALL_FAR_IND) {
                const int nFarSize = m_bProtectedMode ? op.nSize : 2;
                _push(pRegisters->nCS, nFarSize);
                _push(nFall - nCodeSegBase, nFarSize);
            }
            setFarPC(nNewCS, nNewIP);
            bBranch = true;
            break;
        }
        case MOP_LOADFAR: {
            XADDR nPtr = _resolveAddr(op, op.src);
            quint64 nOff = _memReadSized(nPtr, op.nSize);
            quint16 nSeg = (quint16)_memReadSized(nPtr + op.nSize, 2);
            if (m_bExecFault) {
                break;
            }
            pRegisters->setGPR(op.dst.nReg, op.nSize, nOff);
            if (op.nCond == 0) {
                pRegisters->nES = nSeg;
            } else if (op.nCond == 1) {
                pRegisters->nDS = nSeg;
            } else if (op.nCond == 2) {
                pRegisters->nSS = nSeg;
                m_bSsBlock = true;  // LSS: an SS load inhibits the trap for one instruction
            } else if (op.nCond == 3) {
                pRegisters->nFS = nSeg;
                pRegisters->nFSBase = selectorBase(nSeg);
            } else {
                pRegisters->nGS = nSeg;
                pRegisters->nGSBase = selectorBase(nSeg);
            }
            break;
        }
        case MOP_RETF: {
            if (!m_bProtectedMode && m_nBits == 16) {
                // Real-mode far return: pop 2-byte IP then 2-byte CS; target = CS*16 + IP.
                quint16 nNewIP = (quint16)_pop(2);
                quint16 nNewCS = (quint16)_pop(2);
                setFarPC(nNewCS, nNewIP);
            } else {
                // Protected-mode far return: pop the operand-size-wide EIP/RIP then the
                // zero-extended CS selector. CS base is 0 in the flat user model, so the
                // target is the flat offset. Packers (PeX, ...) use `push seg; push off;
                // retf` as an obfuscated jump/mode-confirm; popping only 2 bytes here would
                // read the low half of a 4-byte offset and land on garbage. op.nSize is the
                // operand size (4 default, 2 under 0x66, 8 under REX.W) -- NOT nPtrSize,
                // which would over-pop a 66-prefixed o16 far return.
                const int nOp = (op.nSize > 0) ? op.nSize : nPtrSize;
                quint64 nNewIP = _pop(nOp);
                quint64 nNewCS = _pop(nOp);
                setFarPC((quint16)nNewCS, nNewIP);
            }
            if (op.nImm) {
                int nSpSize = m_bProtectedMode ? (selectorDefault32(pRegisters->nSS) ? 4 : 2)
                                                : ((m_nBits == 16) ? 2 : 4);
                pRegisters->setGPR(XEmuRegisters::GPR_RSP, nSpSize, pRegisters->getGPR(XEmuRegisters::GPR_RSP, nSpSize) + op.nImm);
            }
            bBranch = true;
            break;
        }
        case MOP_IRET: {
            const int nOpSize = m_bProtectedMode ? nPtrSize : 2;
            quint64 nNewIP = _pop(nOpSize);
            quint16 nNewCS = (quint16)_pop(nOpSize);
            quint64 nFlags = _pop(nOpSize);
            setFarPC(nNewCS, nNewIP);
            pRegisters->nRFLAGS = (pRegisters->nRFLAGS & ~_mask(nOpSize)) | (nFlags & _mask(nOpSize));
            pRegisters->nRFLAGS |= 0x2ull;
            pRegisters->nRFLAGS &= ~0x8028ull;  // reserved bits 3, 5, 15 always 0
            bBranch = true;
            break;
        }
        case MOP_RET: {
            quint64 nTarget = nCodeSegBase + _pop(nPtrSize);
            if (op.nImm) {
                int nSpSize = (m_nBits == 64) ? 8
                              : m_bProtectedMode ? (selectorDefault32(pRegisters->nSS) ? 4 : 2)
                                                 : ((m_nBits == 16) ? 2 : 4);
                pRegisters->setGPR(XEmuRegisters::GPR_RSP, nSpSize, pRegisters->getGPR(XEmuRegisters::GPR_RSP, nSpSize) + op.nImm);
            }
            pRegisters->nRIP = nTarget;
            bBranch = true;
            break;
        }
        case MOP_HALT:
            info.result = STEP_HALT;
            pRegisters->nRIP = nFall;
            return;
        case MOP_RDTSC:
            m_nTsc += 0x100;
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 4, m_nTsc & 0xffffffff);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 4, (m_nTsc >> 32) & 0xffffffff);
            break;
        case MOP_CPUID: {
            quint32 nLeaf = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 4);
            quint32 a = 0, b = 0, c = 0, d = 0;
            if (nLeaf == 0) {
                a = 1;
                b = 0x756e6547;  // "Genu"
                d = 0x49656e69;  // "ineI"
                c = 0x6c65746e;  // "ntel"
            } else if (nLeaf == 1) {
                a = 0x00000601;
                d = 0x078bfbff;  // common feature bits (FPU, TSC, CMOV, ...)
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 4, a);
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, 4, b);
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, 4, c);
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, 4, d);
            break;
        }
        case MOP_PUSHA: {
            int nSz = op.nSize;
            quint64 nOrigSp = pRegisters->getGPR(XEmuRegisters::GPR_RSP, nPtrSize);
            static const int s_order[8] = {XEmuRegisters::GPR_RAX, XEmuRegisters::GPR_RCX, XEmuRegisters::GPR_RDX, XEmuRegisters::GPR_RBX,
                                           -1 /*orig ESP*/,        XEmuRegisters::GPR_RBP, XEmuRegisters::GPR_RSI, XEmuRegisters::GPR_RDI};
            for (int i = 0; i < 8; i++) {
                quint64 nValue = (s_order[i] < 0) ? nOrigSp : pRegisters->getGPR(s_order[i], nSz);
                _push(nValue, nSz);
            }
            break;
        }
        case MOP_POPA: {
            int nSz = op.nSize;
            pRegisters->setGPR(XEmuRegisters::GPR_RDI, nSz, _pop(nSz));
            pRegisters->setGPR(XEmuRegisters::GPR_RSI, nSz, _pop(nSz));
            pRegisters->setGPR(XEmuRegisters::GPR_RBP, nSz, _pop(nSz));
            _pop(nSz);  // discard the saved ESP slot
            pRegisters->setGPR(XEmuRegisters::GPR_RBX, nSz, _pop(nSz));
            pRegisters->setGPR(XEmuRegisters::GPR_RDX, nSz, _pop(nSz));
            pRegisters->setGPR(XEmuRegisters::GPR_RCX, nSz, _pop(nSz));
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, nSz, _pop(nSz));
            break;
        }
        case MOP_PUSHF:
            // pushf/pushfd/pushfq: store EFLAGS/RFLAGS. Reserved bit 15 reads 0, as do VM/RF (16/17)
            // and AC (18). AC is masked because these DOS packers run on a 386 (our DOSBox reference
            // has cputype=386, where AC cannot be set) and detect the CPU by trying to toggle it.
            // 16-bit real mode mirrors the DOSBox reference: AC (18) IS settable while ID (21) is not.
            // Packers toggle exactly these bits to identify the CPU (EXELOCK 666: `pushfd / xor ax,0024 /
            // popfd / pushfd / test al,04`), so the pair must match the reference or they take the wrong
            // branch. The 32/64-bit path keeps masking AC -- VMProtect folds it into its anti-emulation.
            _push(pRegisters->nRFLAGS & ~(m_nBits == 16 ? 0x238000ull : 0x78000ull), op.nSize);
            break;
        case MOP_POPF: {
            quint64 nVal = _pop(op.nSize);
            quint64 nMask = (op.nSize == 2) ? 0xFFFFull : ((op.nSize == 8) ? ~0ull : 0xFFFFFFFFull);
            pRegisters->nRFLAGS = (pRegisters->nRFLAGS & ~nMask) | (nVal & nMask);
            pRegisters->nRFLAGS |= 0x2ull;       // reserved bit 1 always reads 1
            // reserved bits 3, 5, 15 always read 0; see MOP_PUSHF for the AC/ID split by mode
            pRegisters->nRFLAGS &= ~(m_nBits == 16 ? 0x208028ull : 0x48028ull);
            break;
        }
        case MOP_SAHF: {
            // EFLAGS[SF ZF 0 AF 0 PF 1 CF] <- AH (mask 0xD5 = CF|PF|AF|ZF|SF).
            int nRaxSize = (m_nBits == 64) ? 8 : 4;
            quint64 nAh = (pRegisters->getGPR(XEmuRegisters::GPR_RAX, nRaxSize) >> 8) & 0xFF;
            pRegisters->nRFLAGS = (pRegisters->nRFLAGS & ~0xD5ull) | (nAh & 0xD5ull);
            break;
        }
        case MOP_LAHF: {
            int nRaxSize = (m_nBits == 64) ? 8 : 4;
            quint64 nAh = (pRegisters->nRFLAGS & 0xD5ull) | 0x02ull;  // bits 1=1, 3=0, 5=0
            quint64 nRax = pRegisters->getGPR(XEmuRegisters::GPR_RAX, nRaxSize);
            nRax = (nRax & ~0xFF00ull) | (nAh << 8);
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, nRaxSize, nRax);
            break;
        }
        case MOP_ENTER: {
            // enter size, level: push rBP; frame = rSP; [nest level-1 saved frames]; rBP =
            // frame; rSP -= size.
            int nLevel = (int)(op.nAluOp & 0x1F);
            _push(pRegisters->getGPR(XEmuRegisters::GPR_RBP, nPtrSize), nPtrSize);
            quint64 nFrame = pRegisters->getGPR(XEmuRegisters::GPR_RSP, nPtrSize);
            for (int i = 1; i < nLevel; i++) {
                quint64 nBp = pRegisters->getGPR(XEmuRegisters::GPR_RBP, nPtrSize);
                pRegisters->setGPR(XEmuRegisters::GPR_RBP, nPtrSize, nBp - nPtrSize);
                _push(_memReadSized((m_nBits == 16 || m_bProtectedMode ? selectorBase(pRegisters->nSS) : 0)
                                           + ((nBp - nPtrSize) & _mask(nPtrSize)), nPtrSize), nPtrSize);
            }
            if (nLevel > 0) {
                _push(nFrame, nPtrSize);
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RBP, nPtrSize, nFrame);
            pRegisters->setGPR(XEmuRegisters::GPR_RSP, nPtrSize, pRegisters->getGPR(XEmuRegisters::GPR_RSP, nPtrSize) - op.nImm);
            break;
        }
        case MOP_LEAVE: {
            // rSP = rBP; rBP = pop() -- undo a standard frame prologue.
            quint64 nBp = pRegisters->getGPR(XEmuRegisters::GPR_RBP, nPtrSize);
            pRegisters->setGPR(XEmuRegisters::GPR_RSP, nPtrSize, nBp);
            pRegisters->setGPR(XEmuRegisters::GPR_RBP, nPtrSize, _pop(nPtrSize));
            break;
        }
        case MOP_IN: {
            // Read from the modeled low-ISA ports (PIC/PIT/keyboard); everything else is open-bus
            // all-ones. op.nCond: 0 = imm8 port, 1 = port in DX.
            quint16 nPort = (op.nCond == 0) ? (quint16)op.nImm : (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2);
            quint64 nVal = _mask(op.nSize);
            if ((nPort >= 0x40) && (nPort <= 0x42)) {
                // 8253/8254 PIT counters. Programs read them for a high-resolution time source or as
                // an entropy source -- EXEGUARD sums samples until they cross a threshold, which never
                // happens if the port reads back a constant. Model channel N as counting down from
                // 0xFFFF off the instruction counter (the PIT ticks ~1.19 MHz, far faster than the BIOS
                // tick), returning low byte then high byte on alternate reads as the usual lo/hi
                // access mode does.
                const quint16 nCount = (quint16)(0xFFFF - ((m_nInsnCount >> 2) & 0xFFFF));
                m_bPitHiByte = !m_bPitHiByte;
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize,
                                   (m_bPitHiByte ? (nCount & 0xFF) : ((nCount >> 8) & 0xFF)) & _mask(op.nSize));
                break;
            }
            if ((nPort == 0x3DA) || (nPort == 0x3BA)) {
                // CGA/VGA Input Status Register #1. Programs busy-wait on bit0 (display enable /
                // blanking) and bit3 (vertical retrace) to sync to the video frame (LZEXE), and some
                // packers measure the retrace timing as an anti-emulation check (PACK derails if it
                // looks unphysical). Model it off the INSTRUCTION COUNT, not the read count: a frame is
                // a fixed span of instructions, so (a) two adjacent reads land in the same frame phase
                // and return the same value, and (b) the retrace repeats at a realistic rate relative
                // to the BIOS tick (~3 frames per tick) -- both of which the real hardware guarantees.
                const quint32 nFrame = 3072;                 // instructions per video frame
                quint32 nPhase = (quint32)(m_nInsnCount % nFrame);
                quint8 nStat = 0;
                if (nPhase >= (nFrame - 768)) nStat |= 0x01;  // display disabled (blanking): last 25% of frame
                if (nPhase >= (nFrame - 256)) nStat |= 0x08;  // vertical retrace: last ~8% of frame
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, nStat & _mask(op.nSize));
                break;
            }
            if (nPort < 0x400) {
                nVal = m_ioPorts[nPort];
                if (op.nSize >= 2) nVal |= (quint64)m_ioPorts[(nPort + 1) & 0x3FF] << 8;
                if (op.nSize == 4) nVal |= ((quint64)m_ioPorts[(nPort + 2) & 0x3FF] << 16) | ((quint64)m_ioPorts[(nPort + 3) & 0x3FF] << 24);
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, nVal & _mask(op.nSize));
            break;
        }
        case MOP_OUT: {
            // Latch writes to the modeled ports so a later IN reads them back (the anti-debug
            // "save mask / mask IRQs / restore" idiom). Writes elsewhere are discarded.
            quint16 nPort = (op.nCond == 0) ? (quint16)op.nImm : (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 2);
            quint64 nVal = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize);
            if (nPort < 0x400) {
                m_ioPorts[nPort] = (quint8)nVal;
                if (op.nSize >= 2) m_ioPorts[(nPort + 1) & 0x3FF] = (quint8)(nVal >> 8);
                if (op.nSize == 4) { m_ioPorts[(nPort + 2) & 0x3FF] = (quint8)(nVal >> 16); m_ioPorts[(nPort + 3) & 0x3FF] = (quint8)(nVal >> 24); }
            }
            break;
        }
        case MOP_SALC: {
            // AL = CF ? 0xFF : 0x00 (flags unaffected).
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, pRegisters->getFlag(XEmuRegisters::FLAG_CF) ? 0xFF : 0x00);
            break;
        }
        case MOP_SMSW:
            // Machine status word = CR0 low bits. In real mode on a 386 with an FPU this reads
            // 0x0010 (ET set, PE clear) -- matching the reference; packers test the PE bit (0).
            _writeOpnd(op, op.dst, op.nSize, 0x0010 & _mask(op.nSize));
            break;
        case MOP_LSL:
            // lar/lsl: return the flat selector value (op.nImm) and set ZF -- the selector is valid.
            _writeOpnd(op, op.dst, op.nSize, op.nImm & _mask(op.nSize));
            m_pExecRegs->setFlag(XEmuRegisters::FLAG_ZF, true);
            break;
        case MOP_MOVDR: {
            // Debug registers really are readable and writable, and the reserved-bit masks the CPU
            // applies on write are the whole point: an anti-debug stub writes two different values
            // and compares the read-backs, so a register that always reads 0 announces "not a real
            // CPU". The masks are DOSBox 0.74's (cpu.cpp): DR6 keeps only the status bits it can
            // report, DR7 forces bit 10 and clears the reserved ones. DR4/DR5 alias DR6/DR7.
            const int nDr = (op.nAluOp == 4) ? 6 : (op.nAluOp == 5) ? 7 : op.nAluOp;
            if (op.nCond == 0) {  // mov r32, DRn
                _writeOpnd(op, op.dst, 4, m_dr[nDr]);
            } else {              // mov DRn, r32
                quint32 nValue = (quint32)_readOpnd(op, op.src, 4);
                if (nDr == 6) {
                    nValue = (nValue | 0xFFFF0FF0u) & 0xFFFFEFFFu;
                } else if (nDr == 7) {
                    nValue = (nValue | 0x00000400u) & 0xFFFF2FFFu;
                }
                m_dr[nDr] = nValue;
            }
            break;
        }
        case MOP_MOVFROMCR:
            // CR0 in real mode on a 386+FPU = 0x00000010 (ET set); CR2/CR3/CR4 read as 0.
            _writeOpnd(op, op.dst, 4, (op.nAluOp == 0) ? 0x00000010u : 0u);
            break;
        case MOP_XLAT: {
            // AL = [seg:(BX + AL)]. Default segment is DS, but a segment-override prefix
            // (e.g. es:xlat) replaces it. Real mode folds in the segment base and wraps the
            // offset in the segment; flat modes use the (zero-based) linear (R)BX + AL.
            quint64 nBx = pRegisters->getGPR(XEmuRegisters::GPR_RBX, op.nSize);
            quint64 nAl = pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1);
            quint64 nOff = (nBx + nAl) & _mask(op.nSize);
            quint64 nSegBase = 0;
            if (op.src.nSegSource == 1) {
                nSegBase = m_bProtectedMode ? selectorBase(pRegisters->nFS) : pRegisters->nFSBase;
            } else if (op.src.nSegSource == 2) {
                nSegBase = m_bProtectedMode ? selectorBase(pRegisters->nGS) : pRegisters->nGSBase;
            } else if (m_nBits == 16 || m_bProtectedMode) {
                quint16 nSeg;
                switch (op.src.nSegSource) {
                    case 3: nSeg = pRegisters->nES; break;
                    case 4: nSeg = pRegisters->nCS; break;
                    case 5: nSeg = pRegisters->nSS; break;
                    default: nSeg = pRegisters->nDS; break;  // 0 (none) or 6 (explicit ds) -> DS
                }
                nSegBase = selectorBase(nSeg);
            }
            pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, _memReadSized(nSegBase + nOff, 1));
            break;
        }
        case MOP_PUSHSEG: {
            quint16 nSeg = (op.nAluOp == 0)   ? pRegisters->nES
                           : (op.nAluOp == 1) ? pRegisters->nCS
                           : (op.nAluOp == 2) ? pRegisters->nSS
                           : (op.nAluOp == 4) ? pRegisters->nFS
                           : (op.nAluOp == 5) ? pRegisters->nGS
                                              : pRegisters->nDS;
            _push(nSeg, nPtrSize);
            break;
        }
        case MOP_POPSEG: {
            quint16 nSeg = (quint16)_pop(nPtrSize);
            if (op.nAluOp == 0) {
                pRegisters->nES = nSeg;
            } else if (op.nAluOp == 2) {
                pRegisters->nSS = nSeg;
                m_bSsBlock = true;  // POP SS: ditto -- this is the one ALEC 1.6 counts on
            } else if (op.nAluOp == 4) {
                pRegisters->nFS = nSeg;
                pRegisters->nFSBase = selectorBase(nSeg);
            } else if (op.nAluOp == 5) {
                pRegisters->nGS = nSeg;
                pRegisters->nGSBase = selectorBase(nSeg);
            } else {
                pRegisters->nDS = nSeg;
            }
            break;
        }
        case MOP_INTO:
            // into: vector software interrupt 4 only if OF is set; otherwise fall through.
            if (pRegisters->getFlag(XEmuRegisters::FLAG_OF)) {
                pRegisters->nRIP = nFall;
                info.result = STEP_SYSCALL;
                info.nVector = 4;
                info.sComment = QStringLiteral("into");
                return;
            }
            break;  // OF clear -> no-op (RIP advanced by the !bBranch tail)
        case MOP_ARPL: {
            quint16 nDst = (quint16)_readOpnd(op, op.dst, 2);
            quint16 nSrc = (quint16)_readOpnd(op, op.src, 2);
            if ((nDst & 3) < (nSrc & 3)) {
                _writeOpnd(op, op.dst, 2, (quint16)((nDst & ~3) | (nSrc & 3)));
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, true);
            } else {
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, false);
            }
            break;
        }
        case MOP_BCD: {
            quint8 nAL = (quint8)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 1);
            quint8 nAH = (quint8)((pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2) >> 8) & 0xFF);
            bool bCF = pRegisters->getFlag(XEmuRegisters::FLAG_CF);
            bool bAF = pRegisters->getFlag(XEmuRegisters::FLAG_AF);
            switch (op.nAluOp) {
                case 0:    // DAA
                case 1: {  // DAS
                    quint8 nOldAL = nAL;
                    bool bOldCF = bCF;
                    bool bNewCF = false;
                    if (((nAL & 0x0F) > 9) || bAF) {
                        int r = (op.nAluOp == 0) ? (nAL + 6) : (nAL - 6);
                        nAL = (quint8)r;
                        bNewCF = bOldCF || (r & 0x100);
                        bAF = true;
                    } else {
                        bAF = false;
                    }
                    if ((nOldAL > 0x99) || bOldCF) {
                        nAL = (op.nAluOp == 0) ? (quint8)(nAL + 0x60) : (quint8)(nAL - 0x60);
                        bNewCF = true;
                    }
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 1, nAL);
                    _setFlagsLogic(nAL, 1);  // SF/ZF/PF from result (also clears CF/OF/AF)
                    pRegisters->setFlag(XEmuRegisters::FLAG_CF, bNewCF);  // restore the BCD-adjusted CF
                    pRegisters->setFlag(XEmuRegisters::FLAG_AF, bAF);     // and AF (DAA/DAS both define AF)
                    break;
                }
                case 2:    // AAA
                case 3: {  // AAS
                    // Real hardware adjusts the whole AX by 0x106 (AL+/-6 with the nibble
                    // carry/borrow propagating into AH), not AL and AH independently.
                    quint16 nAX = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
                    if (((nAX & 0x0F) > 9) || bAF) {
                        nAX = (op.nAluOp == 2) ? (quint16)(nAX + 0x106) : (quint16)(nAX - 0x106);
                        bAF = true;
                        bCF = true;
                    } else {
                        bAF = false;
                        bCF = false;
                    }
                    nAX &= 0xFF0F;  // AL &= 0x0F, AH kept
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, nAX);
                    pRegisters->setFlag(XEmuRegisters::FLAG_AF, bAF);
                    pRegisters->setFlag(XEmuRegisters::FLAG_CF, bCF);
                    break;
                }
                case 4: {  // AAM: AH = AL / base, AL = AL % base
                    quint8 nBase = (quint8)op.nImm ? (quint8)op.nImm : 10;
                    setAxBytes(pRegisters, static_cast<quint8>(nAL % nBase), static_cast<quint8>(nAL / nBase));
                    _setFlagsLogic((quint8)(nAL % nBase), 1);
                    break;
                }
                case 5: {  // AAD: AL = (AL + AH*base) & 0xFF, AH = 0
                    quint8 nBase = (quint8)op.nImm ? (quint8)op.nImm : 10;
                    quint8 nRes = (quint8)(nAL + nAH * nBase);
                    setAxBytes(pRegisters, nRes, 0);
                    _setFlagsLogic(nRes, 1);
                    break;
                }
            }
            break;
        }
        case MOP_MOVSEG: {
            quint16 *pSeg = (op.nAluOp == 0)   ? &pRegisters->nES
                            : (op.nAluOp == 1) ? &pRegisters->nCS
                            : (op.nAluOp == 2) ? &pRegisters->nSS
                            : (op.nAluOp == 3) ? &pRegisters->nDS
                            : (op.nAluOp == 4) ? &pRegisters->nFS
                                               : &pRegisters->nGS;
            if (op.nCond == 0) {  // mov Sreg, r/m16
                quint16 nVal = (quint16)_readOpnd(op, op.src, 2);
                *pSeg = nVal;
                if (op.nAluOp == 2) {
                    m_bSsBlock = true;  // MOV SS,r/m: ditto
                }
                // Keep the FS/GS cached bases coherent with the selector table.
                if (op.nAluOp == 4) {
                    pRegisters->nFSBase = selectorBase(nVal);
                } else if (op.nAluOp == 5) {
                    pRegisters->nGSBase = selectorBase(nVal);
                }
            } else {  // mov r/m16, Sreg
                _writeOpnd(op, op.dst, 2, *pSeg);
            }
            break;
        }
        case MOP_FPU:
            _execFpu(op);
            break;
        case MOP_SHIFT: {
            quint8 nCount = (op.nCond == 1) ? (quint8)pRegisters->getGPR(XEmuRegisters::GPR_RCX, 1) : (quint8)op.nImm;
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 r = _doShift(op.nAluOp, a, op.nSize, nCount);
            _writeOpnd(op, op.dst, op.nSize, r);
            break;
        }
        case MOP_SHIFTD: {
            // SHLD/SHRD dst, src, count. count masked to 5 bits (6 for 64-bit); count 0 is
            // a no-op with flags unaffected. CF = last bit shifted out of dst; SF/ZF/PF from
            // the result; OF defined only for a count of 1; AF undefined (left as-is).
            const int nBits = op.nSize * 8;
            quint8 nCount = (op.nCond == 1) ? (quint8)pRegisters->getGPR(XEmuRegisters::GPR_RCX, 1) : (quint8)op.nImm;
            nCount &= (op.nSize == 8) ? 0x3F : 0x1F;
            if (nCount == 0) {
                break;
            }
            const quint64 nMask = _mask(op.nSize);
            const quint64 nSign = _signBit(op.nSize);
            const quint64 nDst = _readOpnd(op, op.dst, op.nSize) & nMask;
            const quint64 nSrc = _readOpnd(op, op.src, op.nSize) & nMask;

#if defined(_M_X64) && defined(_WIN32)
            // Undefined region: a 16-bit SHLD/SHRD whose count exceeds the 16-bit width
            // (a VMProtect anti-emulation trap). Reproduce the host CPU exactly.
            if ((op.nSize == 2) && (nCount >= (quint8)nBits)) {
                quint8 insn[6];
                const int ilen = buildShiftInsn(insn, (op.nAluOp == 0) ? 100 : 101, 2);
                quint32 f = (quint32)pRegisters->nRFLAGS;
                quint32 res = 0;
                if (hostShiftExec(insn, ilen, (quint32)nDst, (quint32)nSrc, nCount, &f, &res)) {
                    _writeOpnd(op, op.dst, op.nSize, res);
                    if (!m_bExecFault) {
                        pRegisters->setFlag(XEmuRegisters::FLAG_CF, (f & 0x001) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_PF, (f & 0x004) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_AF, (f & 0x010) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_ZF, (f & 0x040) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_SF, (f & 0x080) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_OF, (f & 0x800) != 0);
                    }
                    break;
                }
            }
#endif

            quint64 v;
            bool bCF;
            if (op.nAluOp == 0) {  // SHLD: dst <<= count, filling low bits from src's high end
                bCF = (nCount <= (quint8)nBits) ? (((nDst >> (nBits - nCount)) & 1) != 0) : false;
                const quint64 nFill = (nCount < nBits) ? (nSrc >> (nBits - nCount)) : 0;
                v = ((nDst << nCount) | nFill) & nMask;
            } else {  // SHRD: dst >>= count, filling high bits from src's low end
                bCF = (((nDst >> (nCount - 1)) & 1) != 0);
                const quint64 nFill = (nCount < nBits) ? (nSrc << (nBits - nCount)) : 0;
                v = ((nDst >> nCount) | nFill) & nMask;
            }

            // OF is architecturally defined only for a 1-bit shift, but real x86 produces
            // a consistent value for count > 1 too: the sign change on the FINAL 1-bit
            // step, i.e. MSB(result) XOR MSB(result-after-(count-1)-shifts). At count==1
            // this reduces to the documented MSB(v)^MSB(dst). VMProtect folds this OF into
            // its VM key (found via the per-instruction real-CPU lockstep on a `shrd`).
            quint64 vPrev;
            const quint8 nPrev = (quint8)(nCount - 1);
            if (nPrev == 0) {
                vPrev = nDst;
            } else if (op.nAluOp == 0) {  // SHLD
                vPrev = ((nDst << nPrev) | (nSrc >> (nBits - nPrev))) & nMask;
            } else {  // SHRD
                vPrev = ((nDst >> nPrev) | (nSrc << (nBits - nPrev))) & nMask;
            }
            const bool bOF = (((v & nSign) != 0) != ((vPrev & nSign) != 0));

            _writeOpnd(op, op.dst, op.nSize, v);
            if (!m_bExecFault) {
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, bCF);
                pRegisters->setFlag(XEmuRegisters::FLAG_OF, bOF);
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, (v & nMask) == 0);
                pRegisters->setFlag(XEmuRegisters::FLAG_SF, (v & nSign) != 0);
                pRegisters->setFlag(XEmuRegisters::FLAG_PF, _parity((quint8)v));
                pRegisters->setFlag(XEmuRegisters::FLAG_AF, true);  // undefined; real x86 sets it
            }
            break;
        }
        case MOP_SSE: {
            struct XmmValue { quint64 low = 0; quint64 high = 0; };
            const auto readXmm = [&](const XEmuOperand &operand, int size) {
                XmmValue value;
                if (operand.bIsReg) {
                    value.low = pRegisters->nXMM[operand.nReg & 15][0];
                    value.high = pRegisters->nXMM[operand.nReg & 15][1];
                } else {
                    const XADDR address = _resolveAddr(op, operand);
                    bool ok = false;
                    const QByteArray bytes = m_pMemoryManager->read(address, size, &ok);
                    if (!ok || bytes.size() != size) {
                        m_bExecFault = true;
                        m_nFaultAddr = address;
                    } else {
                        memcpy(&value.low, bytes.constData(), qMin(size, 8));
                        if (size == 16) memcpy(&value.high, bytes.constData() + 8, 8);
                    }
                }
                return value;
            };
            const auto writeXmm = [&](const XEmuOperand &operand, const XmmValue &value, int size, bool preserveUpper) {
                if (operand.bIsReg) {
                    quint64 &low = pRegisters->nXMM[operand.nReg & 15][0];
                    quint64 &high = pRegisters->nXMM[operand.nReg & 15][1];
                    if (size == 16) {
                        low = value.low;
                        high = value.high;
                    } else if (size == 8) {
                        low = value.low;
                        if (!preserveUpper) high = 0;
                    } else {
                        low = preserveUpper ? (low & Q_UINT64_C(0xffffffff00000000)) | (value.low & 0xffffffffu)
                                            : (value.low & 0xffffffffu);
                        if (!preserveUpper) high = 0;
                    }
                } else {
                    const XADDR address = _resolveAddr(op, operand);
                    char bytes[16] = {};
                    memcpy(bytes, &value.low, qMin(size, 8));
                    if (size == 16) memcpy(bytes + 8, &value.high, 8);
                    _noteWrite(address, size);
                    if (!m_pMemoryManager->write(address, QByteArray(bytes, size))) {
                        m_bExecFault = true;
                        m_nFaultAddr = address;
                    }
                }
            };
            const int kind = op.nAluOp;
            if (kind == SSE_MOV_GPR_TO_XMM) {
                const quint64 integer = _readOpnd(op, op.src, op.nSize);
                if (!m_bExecFault) {
                    XmmValue value;
                    value.low = integer;
                    writeXmm(op.dst, value, op.nSize, false);
                }
                break;
            }
            if (kind == SSE_MOV_XMM_TO_GPR) {
                const XmmValue value = readXmm(op.src, op.nSize);
                if (!m_bExecFault) _writeOpnd(op, op.dst, op.nSize, value.low);
                break;
            }
            if (kind == SSE_MOVQ_LOAD || kind == SSE_MOVQ_STORE) {
                const XmmValue value = readXmm(op.src, 8);
                if (!m_bExecFault) writeXmm(op.dst, value, 8, false);
                break;
            }
            if (kind == SSE_MOVHPS_LOAD) {
                XmmValue value = readXmm(op.dst, 16);
                const XmmValue source = readXmm(op.src, 8);
                if (!m_bExecFault) {
                    value.high = source.low;
                    writeXmm(op.dst, value, 16, false);
                }
                break;
            }
            if (kind == SSE_MOVHPS_STORE) {
                const XmmValue source = readXmm(op.src, 16);
                XmmValue value;
                value.low = source.high;
                if (!m_bExecFault) writeXmm(op.dst, value, 8, false);
                break;
            }
            if (kind == SSE_MOV128_LOAD || kind == SSE_MOV128_STORE ||
                kind == SSE_MOV_SCALAR_LOAD || kind == SSE_MOV_SCALAR_STORE) {
                const XmmValue value = readXmm(op.src, op.nSize);
                if (!m_bExecFault) {
                    const bool preserve = op.nSize != 16 && op.src.bIsReg;
                    writeXmm(op.dst, value, op.nSize, preserve);
                }
                break;
            }
            if (kind == SSE_CVTSI2FP) {
                const quint64 integer = _readOpnd(op, op.src, op.nSrcSize);
                if (m_bExecFault) break;
                const double number = op.nSrcSize == 8 ? (double)(qint64)integer : (double)(qint32)integer;
                XmmValue value;
                if (op.nSize == 8) {
                    const double converted = number;
                    memcpy(&value.low, &converted, 8);
                } else {
                    const float converted = static_cast<float>(number);
                    memcpy(&value.low, &converted, 4);
                }
                writeXmm(op.dst, value, op.nSize, true);
                break;
            }
            const XmmValue source = readXmm(op.src, op.nSize == 16 ? 16 : op.nSize);
            if (m_bExecFault) break;
            if (kind == SSE_CVTTFP2SI) {
                double number = 0;
                if (op.nSize == 8) memcpy(&number, &source.low, 8);
                else {
                    float single = 0;
                    memcpy(&single, &source.low, 4);
                    number = single;
                }
                const double limit = op.nSrcSize == 8 ? 9223372036854775808.0 : 2147483648.0;
                const quint64 result = !std::isfinite(number) || number < -limit || number >= limit
                                           ? (op.nSrcSize == 8 ? Q_UINT64_C(0x8000000000000000) : 0x80000000u)
                                           : (quint64)(qint64)std::trunc(number);
                _writeOpnd(op, op.dst, op.nSrcSize, result);
                break;
            }
            const XmmValue destination = readXmm(op.dst, 16);
            if (m_bExecFault) break;
            XmmValue result = destination;
            if (kind == SSE_PXOR) {
                result.low ^= source.low;
                result.high ^= source.high;
            } else if (kind == SSE_AND) {
                result.low &= source.low;
                result.high &= source.high;
            } else if (kind == SSE_PCMPEQD) {
                for (int i = 0; i < 2; ++i) {
                    quint64 a = i ? destination.high : destination.low;
                    quint64 b = i ? source.high : source.low;
                    quint64 equal = (quint32)a == (quint32)b ? 0xffffffffu : 0;
                    equal |= ((quint32)(a >> 32) == (quint32)(b >> 32) ? Q_UINT64_C(0xffffffff) : 0) << 32;
                    if (i) result.high = equal;
                    else result.low = equal;
                }
            } else if (kind == SSE_PUNPCKLQDQ) {
                result.high = source.low;
            } else if (kind == SSE_UCOMI) {
                double a = 0, b = 0;
                if (op.nSize == 8) {
                    memcpy(&a, &destination.low, 8);
                    memcpy(&b, &source.low, 8);
                } else {
                    float fa = 0, fb = 0;
                    memcpy(&fa, &destination.low, 4);
                    memcpy(&fb, &source.low, 4);
                    a = fa; b = fb;
                }
                const bool unordered = std::isnan(a) || std::isnan(b);
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, unordered || a == b);
                pRegisters->setFlag(XEmuRegisters::FLAG_PF, unordered);
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, unordered || a < b);
                pRegisters->setFlag(XEmuRegisters::FLAG_OF, false);
                pRegisters->setFlag(XEmuRegisters::FLAG_SF, false);
                pRegisters->setFlag(XEmuRegisters::FLAG_AF, false);
                break;
            } else if (kind == SSE_ADD || kind == SSE_MUL || kind == SSE_DIV) {
                if (op.nSize == 8) {
                    double a = 0, b = 0;
                    memcpy(&a, &destination.low, 8);
                    memcpy(&b, &source.low, 8);
                    const double value = kind == SSE_ADD ? a + b : kind == SSE_MUL ? a * b : a / b;
                    memcpy(&result.low, &value, 8);
                } else {
                    float a = 0, b = 0;
                    memcpy(&a, &destination.low, 4);
                    memcpy(&b, &source.low, 4);
                    const float value = kind == SSE_ADD ? a + b : kind == SSE_MUL ? a * b : a / b;
                    quint32 bits = 0;
                    memcpy(&bits, &value, 4);
                    result.low = (result.low & Q_UINT64_C(0xffffffff00000000)) | bits;
                }
            }
            writeXmm(op.dst, result, 16, false);
            break;
        }
        case MOP_MMX: {
            switch (op.nAluOp) {
                case MMX_EMMS:
                    break;  // empties the x87 tag word on real HW; nothing to model here
                case MMX_MOVD_TO:  // mm = zero_extend(r/m32), or (REX.W) mm = r/m64
                    _writeMMX(op, op.dst, (op.nSrcSize == 8) ? _readOpnd(op, op.src, 8) : (quint64)(quint32)_readOpnd(op, op.src, 4));
                    break;
                case MMX_MOVD_FROM:  // r/m32 = mm[31:0], or (REX.W) r/m64 = mm
                    _writeOpnd(op, op.dst, op.nSize, (op.nSize == 8) ? _readMMX(op, op.src) : (quint64)(quint32)_readMMX(op, op.src));
                    break;
                case MMX_MOVQ_TO:
                case MMX_MOVQ_FROM:
                    _writeMMX(op, op.dst, _readMMX(op, op.src));
                    break;
                case MMX_PSHUFW: {
                    const quint64 s = _readMMX(op, op.src);
                    const quint8 nCtrl = (quint8)op.nImm;
                    quint64 v = 0;
                    for (int i = 0; i < 4; i++) {
                        const int nSel = (nCtrl >> (i * 2)) & 3;
                        v |= (quint64)(quint16)(s >> (nSel * 16)) << (i * 16);
                    }
                    _writeMMX(op, op.dst, v);
                    break;
                }
                default:
                    if (mmxIsShift(op.nAluOp)) {
                        const quint64 a = _readMMX(op, op.dst);
                        const quint64 nCount = (op.nCond == 1) ? op.nImm : _readMMX(op, op.src);
                        _writeMMX(op, op.dst, _mmxShift(op.nAluOp, a, nCount));
                    } else {
                        const quint64 a = _readMMX(op, op.dst);
                        const quint64 b = _readMMX(op, op.src);
                        _writeMMX(op, op.dst, _mmxALU(op.nAluOp, a, b));
                    }
                    break;
            }
            break;
        }
        case MOP_BT: {
            // BT/BTS/BTR/BTC. CF = the tested bit; BTS/BTR/BTC then set/reset/complement it.
            // Only CF is defined; the other arithmetic flags are left unchanged (officially
            // undefined). nAluOp: 0 BT, 1 BTS, 2 BTR, 3 BTC.
            const int nBits = op.nSize * 8;
            qint64 nRawIndex = (op.nCond == 1) ? (qint64)_signExtend(_readOpnd(op, op.src, op.nSize), op.nSize) : (qint64)op.nImm;
            bool bBit;

            if (op.dst.bIsReg || (op.nCond == 0)) {
                // Register destination, or memory with an immediate offset: the bit index is
                // taken modulo the operand size and the whole operand is read/written.
                const quint64 nIndex = ((quint64)nRawIndex) & (quint64)(nBits - 1);
                const quint64 nMask = (quint64)1 << nIndex;
                const quint64 a = _readOpnd(op, op.dst, op.nSize);
                bBit = ((a & nMask) != 0);
                if (op.nAluOp != 0) {
                    const quint64 r = (op.nAluOp == 1) ? (a | nMask) : (op.nAluOp == 2) ? (a & ~nMask) : (a ^ nMask);
                    _writeOpnd(op, op.dst, op.nSize, r);
                }
            } else {
                // Memory destination with a register offset: the (signed) offset addresses a
                // bit relative to the operand's byte address; operate on the single byte.
                // Go through _memReadSized/_memWriteSized so an unmapped access raises the
                // execute-time fault (m_bExecFault), like every other memory accessor.
                const XADDR nAddr = _resolveAddr(op, op.dst);
                const XADDR nByteAddr = (XADDR)((qint64)nAddr + (nRawIndex >> 3));
                const quint32 nBitInByte = (quint32)(nRawIndex & 7);
                const quint8 nMask = (quint8)(1u << nBitInByte);
                const quint8 nByte = (quint8)_memReadSized(nByteAddr, 1);
                bBit = ((nByte & nMask) != 0);
                if (!m_bExecFault && (op.nAluOp != 0)) {
                    const quint8 nNew = (op.nAluOp == 1) ? (quint8)(nByte | nMask) : (op.nAluOp == 2) ? (quint8)(nByte & (quint8)~nMask) : (quint8)(nByte ^ nMask);
                    _memWriteSized(nByteAddr, nNew, 1);
                }
            }

            pRegisters->setFlag(XEmuRegisters::FLAG_CF, bBit);
            break;
        }
        case MOP_XCHG: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 b = _readOpnd(op, op.src, op.nSize);
            _writeOpnd(op, op.dst, op.nSize, b);
            _writeOpnd(op, op.src, op.nSize, a);
            break;
        }
        case MOP_XADD: {
            // TEMP = DEST + SRC (ADD flags); SRC = DEST; DEST = TEMP.
            const quint64 a = _readOpnd(op, op.dst, op.nSize);  // old dst
            const quint64 b = _readOpnd(op, op.src, op.nSize);  // old src (reg)
            bool bWriteBack = true;
            const quint64 r = _aluCompute(0, a, b, op.nSize, bWriteBack);  // ADD -> sets flags
            _writeOpnd(op, op.src, op.nSize, a & _mask(op.nSize));
            _writeOpnd(op, op.dst, op.nSize, r);
            break;
        }
        case MOP_CMPXCHG: {
            const quint64 oldDst = _readOpnd(op, op.dst, op.nSize);
            if (m_bExecFault) {
                break;
            }
            const quint64 accumulator = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize);
            _setFlagsSub(accumulator, oldDst, accumulator - oldDst, op.nSize);
            if (accumulator == oldDst) {
                _writeOpnd(op, op.dst, op.nSize, _readOpnd(op, op.src, op.nSize));
            } else {
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, oldDst);
            }
            break;
        }
        case MOP_CDQ: {
            if (op.nAluOp == 0) {  // cbw/cwde/cdqe: sign-extend the accumulator's lower half
                int nSrc = op.nSize / 2;
                quint64 v = pRegisters->getGPR(XEmuRegisters::GPR_RAX, nSrc);
                pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, (quint64)_signExtend(v, nSrc) & _mask(op.nSize));
            } else {  // cwd/cdq/cqo: replicate the accumulator's sign across rDX
                quint64 v = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize);
                bool bNeg = (v & _signBit(op.nSize)) != 0;
                pRegisters->setGPR(XEmuRegisters::GPR_RDX, op.nSize, bNeg ? _mask(op.nSize) : 0);
            }
            break;
        }
        case MOP_BSWAP: {
            quint64 v = _readOpnd(op, op.dst, op.nSize);
            quint64 r = 0;
            if (op.nSize == 8) {
                for (int i = 0; i < 8; i++) {
                    r = (r << 8) | ((v >> (i * 8)) & 0xFF);
                }
            } else {  // 4-byte form (bswap on a 16-bit register is officially undefined)
                r = ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
            }
            _writeOpnd(op, op.dst, op.nSize, r & _mask(op.nSize));
            break;
        }
        case MOP_BSF:
        case MOP_BSR: {
            // Bit scan: ZF=1 and dst left unchanged when src==0; otherwise dst = index of
            // the lowest (BSF) / highest (BSR) set bit. CF/OF/SF/AF/PF are undefined.
            const quint64 src = _readOpnd(op, op.src, op.nSize) & _mask(op.nSize);
            if (src == 0) {
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, true);
            } else {
                const int nBits = op.nSize * 8;
                int idx;
                if (op.kind == MOP_BSF) {
                    idx = 0;
                    while (((src >> idx) & 1) == 0) {
                        idx++;
                    }
                } else {
                    idx = nBits - 1;
                    while (((src >> idx) & 1) == 0) {
                        idx--;
                    }
                }
                pRegisters->setGPR(op.dst.nReg, op.nSize, (quint64)idx);
                pRegisters->setFlag(XEmuRegisters::FLAG_ZF, false);
            }
            break;
        }
        case MOP_IMUL2: {
            // Two-operand (0F AF): dst = dst * src. Three-operand (0x69/0x6B, nSrcSize<0):
            // dst = src * sign-extended immediate.
            qint64 a = _signExtend(_readOpnd(op, op.src, op.nSize), op.nSize);
            qint64 b = (op.nSrcSize < 0) ? (qint64)op.nImm : _signExtend(_readOpnd(op, op.dst, op.nSize), op.nSize);
            quint64 r = 0;
            bool bOver = false;
            if (op.nSize == 8) {
                quint64 hi = 0;
                multiplySigned64(static_cast<quint64>(a), static_cast<quint64>(b), &r, &hi);
                bOver = hi != ((r >> 63) ? ~quint64(0) : quint64(0));
            } else {
                const qint64 nFull = a * b;
                r = static_cast<quint64>(nFull) & _mask(op.nSize);
                bOver = (_signExtend(r, op.nSize) != nFull);
            }
            pRegisters->setGPR(op.dst.nReg, op.nSize, r);
            pRegisters->setFlag(XEmuRegisters::FLAG_CF, bOver);
            pRegisters->setFlag(XEmuRegisters::FLAG_OF, bOver);
            break;
        }
        case MOP_MULDIV: {
            quint64 a = _readOpnd(op, op.dst, op.nSize);
            quint64 nSzMask = _mask(op.nSize);

            if (op.nAluOp == 2) {  // NOT (no flags)
                _writeOpnd(op, op.dst, op.nSize, ~a & nSzMask);
            } else if (op.nAluOp == 3) {  // NEG
                quint64 r = (quint64)(0 - a) & nSzMask;
                _setFlagsSub(0, a, r, op.nSize);
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, (a & nSzMask) != 0);
                _writeOpnd(op, op.dst, op.nSize, r);
            } else if ((op.nAluOp == 4) || (op.nAluOp == 5)) {  // MUL / IMUL (one-operand)
                quint64 nAcc = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize) & nSzMask;
                quint64 nLo = 0, nHi = 0;
                bool bOver = false;
                if (op.nAluOp == 4) {  // unsigned
                    if (op.nSize <= 4) {
                        quint64 nProd = nAcc * (a & nSzMask);
                        nLo = nProd & nSzMask;
                        nHi = (nProd >> (op.nSize * 8)) & nSzMask;
                    } else {
                        multiplyUnsigned64(nAcc, a, &nLo, &nHi);
                    }
                    bOver = (nHi != 0);
                } else {  // signed
                    if (op.nSize == 8) {
                        multiplySigned64(nAcc, a, &nLo, &nHi);
                        bOver = nHi != ((nLo >> 63) ? ~quint64(0) : quint64(0));
                    } else {
                        const qint64 nProd = _signExtend(nAcc, op.nSize) * _signExtend(a, op.nSize);
                        nLo = static_cast<quint64>(nProd) & nSzMask;
                        nHi = (static_cast<quint64>(nProd) >> (op.nSize * 8)) & nSzMask;
                        bOver = (_signExtend(nLo, op.nSize) != nProd);
                    }
                }
                if (op.nSize == 1) {
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, ((nHi & 0xFF) << 8) | (nLo & 0xFF));
                } else {
                    pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, nLo);
                    pRegisters->setGPR(XEmuRegisters::GPR_RDX, op.nSize, nHi);
                }
                pRegisters->setFlag(XEmuRegisters::FLAG_CF, bOver);
                pRegisters->setFlag(XEmuRegisters::FLAG_OF, bOver);
                // SF/ZF/PF/AF are undefined after MUL/IMUL, and the two hardware families
                // differ: 16-bit-era CPUs (and DOSBox, the reference for the DOS packer
                // corpus) materialise ZF from the low-half result ("mul; jz"), while modern
                // 32/64-bit hardware leaves SF/ZF/PF/AF UNCHANGED. VMProtect folds these
                // undefined flags into its VM rolling key as an anti-emulation trap, so the
                // 32/64-bit path MUST leave them alone. Match by mode.
                if (m_nBits == 16) {
                    pRegisters->setFlag(XEmuRegisters::FLAG_ZF, (nLo & nSzMask) == 0);
                }
            } else {  // DIV (6) / IDIV (7)
#if defined(_M_X64) && defined(_WIN32)
                const quint32 nDivEax = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 4);
                const quint32 nDivEdx = (quint32)pRegisters->getGPR(XEmuRegisters::GPR_RDX, 4);
#endif
                if ((a & nSzMask) == 0) {
                    // Divide error (#DE): x86 vectors this through INT 0. Anti-debug crypters
                    // divide by zero on purpose and catch it with their own INT 0 handler, so
                    // dispatch to a guest handler in the resident IVT (0000:0000) if installed;
                    // otherwise stop with a fault.
                    quint16 nHOff = (quint16)_memReadSized(0, 2);
                    quint16 nHSeg = (quint16)_memReadSized(2, 2);
                    // Only vector to a real GUEST handler (in low/program memory). The BIOS default
                    // (segment 0xF000) and an unset vector mean "no handler" -> stop, rather than
                    // looping forever on an IRET stub.
                    if (!m_bExecFault && (nHSeg != 0) && (nHSeg != 0xF000)) {
                        quint16 nRetIP = (quint16)((op.nAddress - nCodeSegBase) & 0xFFFF);  // #DE pushes the faulting IP
                        _push(pRegisters->nRFLAGS & 0xFFFF, 2);
                        _push(pRegisters->nCS, 2);
                        _push(nRetIP, 2);
                        pRegisters->setFlag(XEmuRegisters::FLAG_IF, false);
                        pRegisters->setFlag(XEmuRegisters::FLAG_TF, false);
                        pRegisters->nCS = nHSeg;
                        pRegisters->nRIP = ((quint64)nHSeg << 4) + nHOff;
                        bBranch = true;
                        break;  // vectored to the handler; skip the undefined division result
                    }
                    m_bExecFault = false;
                    info.result = STEP_FAULT;
                    info.sComment = QStringLiteral("divide by zero");
                    return;
                }
                if (op.nSize == 1) {
                    quint16 nNum = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RAX, 2);
                    if (op.nAluOp == 6) {
                        quint8 d = (quint8)a;
                        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, (quint16)(((nNum % d) << 8) | (nNum / d)));
                    } else {
                        qint16 sNum = (qint16)nNum;
                        qint8 d = (qint8)a;
                        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 2, (quint16)((((quint8)(sNum % d)) << 8) | (quint8)(sNum / d)));
                    }
                } else {
                    quint64 nHi = pRegisters->getGPR(XEmuRegisters::GPR_RDX, op.nSize) & nSzMask;
                    quint64 nLo = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize) & nSzMask;
                    if (op.nSize <= 4) {
                        if (op.nAluOp == 6) {  // unsigned
                            quint64 nNum = (nHi << (op.nSize * 8)) | nLo;
                            quint64 d = a & nSzMask;
                            pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, (nNum / d) & nSzMask);
                            pRegisters->setGPR(XEmuRegisters::GPR_RDX, op.nSize, (nNum % d) & nSzMask);
                        } else {  // signed
                            qint64 nNum = (qint64)((nHi << (op.nSize * 8)) | nLo);
                            if (op.nSize == 2) {
                                nNum = (qint64)(qint32)((quint32)nNum);
                            }
                            qint64 d = _signExtend(a, op.nSize);
                            pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, (quint64)(nNum / d) & nSzMask);
                            pRegisters->setGPR(XEmuRegisters::GPR_RDX, op.nSize, (quint64)(nNum % d) & nSzMask);
                        }
                    } else {
                        quint64 quotient = 0, remainder = 0;
                        const bool valid = op.nAluOp == 6
                            ? divideUnsigned128(nHi, nLo, a, &quotient, &remainder)
                            : divideSigned128(nHi, nLo, a, &quotient, &remainder);
                        if (!valid) {
                            info.result = STEP_FAULT;
                            info.sComment = QStringLiteral("divide overflow");
                            return;
                        }
                        pRegisters->setGPR(XEmuRegisters::GPR_RAX, 8, quotient);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDX, 8, remainder);
                    }
                }
#if defined(_M_X64) && defined(_WIN32)
                // DIV/IDIV leave all arithmetic flags undefined; real silicon materialises
                // them in a microarchitecture-specific way that VMProtect folds into its VM
                // key. Reproduce exactly by re-running the division on the host (the result
                // is already committed above; only the flags are taken from the host).
                if (op.nSize == 1 || op.nSize == 2 || op.nSize == 4) {
                    quint32 f = (quint32)pRegisters->nRFLAGS;
                    if (hostExecDiv(op.nAluOp == 7, op.nSize, nDivEax, nDivEdx, (quint32)(a & nSzMask), &f)) {
                        pRegisters->setFlag(XEmuRegisters::FLAG_CF, (f & 0x001) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_PF, (f & 0x004) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_AF, (f & 0x010) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_ZF, (f & 0x040) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_SF, (f & 0x080) != 0);
                        pRegisters->setFlag(XEmuRegisters::FLAG_OF, (f & 0x800) != 0);
                    }
                }
#endif
            }
            break;
        }
        case MOP_STRING: {
            int nAddr = (m_nBits == 64) ? 8 : ((m_nBits == 16) ? 2 : 4);
            int nDelta = m_pExecRegs->getFlag(XEmuRegisters::FLAG_DF) ? -op.nSize : op.nSize;
            bool bRep = (op.nCond != 0);
            quint64 nCount = bRep ? pRegisters->getGPR(XEmuRegisters::GPR_RCX, nAddr) : 1;
            quint32 nHostIterations = 0;
            const quint32 nMaxHostIterationsPerStep = 65536;

            // Real mode: the source element is at DS:SI (a segment override redirects it to
            // ES/CS/SS/FS/GS -- matters once the segments differ, i.e. in an .EXE), the
            // destination is always ES:DI (not overridable). Flat mode: bases 0 except FS/GS.
            quint64 nSrcSegBase, nDstSegBase;
            if (m_nBits == 16 || m_bProtectedMode) {
                quint16 nSrcSeg = m_pExecRegs->nDS;
                switch (op.src.nSegSource) {
                    case 3: nSrcSeg = m_pExecRegs->nES; break;
                    case 4: nSrcSeg = m_pExecRegs->nCS; break;
                    case 5: nSrcSeg = m_pExecRegs->nSS; break;
                    case 6: nSrcSeg = m_pExecRegs->nDS; break;
                    default: break;  // 0 = default DS
                }
                nSrcSegBase = selectorBase(nSrcSeg);
                nDstSegBase = selectorBase(m_pExecRegs->nES);
            } else {
                nSrcSegBase = 0;
                nDstSegBase = 0;
            }
            if (op.src.nSegSource == 1) {
                nSrcSegBase = m_bProtectedMode ? selectorBase(m_pExecRegs->nFS) : m_pExecRegs->nFSBase;
            } else if (op.src.nSegSource == 2) {
                nSrcSegBase = m_bProtectedMode ? selectorBase(m_pExecRegs->nGS) : m_pExecRegs->nGSBase;
            }

            while (nCount > 0) {
                quint64 nEsi = pRegisters->getGPR(XEmuRegisters::GPR_RSI, nAddr);
                quint64 nEdi = pRegisters->getGPR(XEmuRegisters::GPR_RDI, nAddr);
                quint64 nSrc = nSrcSegBase + nEsi;
                quint64 nDst = nDstSegBase + nEdi;

                switch (op.nAluOp) {
                    case 0:  // movs
                        _memWriteSized(nDst, _memReadSized(nSrc, op.nSize), op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RSI, nAddr, nEsi + nDelta);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDI, nAddr, nEdi + nDelta);
                        break;
                    case 1:  // stos
                        _memWriteSized(nDst, pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize), op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDI, nAddr, nEdi + nDelta);
                        break;
                    case 2:  // lods
                        pRegisters->setGPR(XEmuRegisters::GPR_RAX, op.nSize, _memReadSized(nSrc, op.nSize));
                        pRegisters->setGPR(XEmuRegisters::GPR_RSI, nAddr, nEsi + nDelta);
                        break;
                    case 3: {  // scas: cmp accumulator, [ES:DI]
                        quint64 nAcc = pRegisters->getGPR(XEmuRegisters::GPR_RAX, op.nSize);
                        quint64 nMem = _memReadSized(nDst, op.nSize);
                        _setFlagsSub(nAcc, nMem, nAcc - nMem, op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDI, nAddr, nEdi + nDelta);
                        break;
                    }
                    case 4: {  // cmps: cmp [DS:SI], [ES:DI]
                        quint64 v1 = _memReadSized(nSrc, op.nSize);
                        quint64 v2 = _memReadSized(nDst, op.nSize);
                        _setFlagsSub(v1, v2, v1 - v2, op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RSI, nAddr, nEsi + nDelta);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDI, nAddr, nEdi + nDelta);
                        break;
                    }
                    case 5:  // ins: [ES:DI] = port(DX); an unmodelled port reads as all-ones
                        _memWriteSized(nDst, _mask(op.nSize), op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RDI, nAddr, nEdi + nDelta);
                        break;
                    case 6:  // outs: port(DX) <- [DS:SI] (write is a no-op); SI advances
                        (void)_memReadSized(nSrc, op.nSize);
                        pRegisters->setGPR(XEmuRegisters::GPR_RSI, nAddr, nEsi + nDelta);
                        break;
                }

                if (m_bExecFault) {
                    break;
                }

                if (!bRep) {
                    break;
                }

                nCount--;
                pRegisters->setGPR(XEmuRegisters::GPR_RCX, nAddr, nCount);

                // repe (F3) stops when ZF=0; repne (F2) stops when ZF=1 (scas/cmps only).
                if ((op.nAluOp == 3) || (op.nAluOp == 4)) {
                    bool bZF = pRegisters->getFlag(XEmuRegisters::FLAG_ZF);
                    if ((op.nCond == 1) && !bZF) {
                        break;
                    }
                    if ((op.nCond == 2) && bZF) {
                        break;
                    }
                }
                ++nHostIterations;
                if (nCount > 0
                    && nHostIterations >= nMaxHostIterationsPerStep) {
                    // Preserve architectural progress but keep one emu.step()
                    // from hiding an attacker-sized REP loop. The next step
                    // resumes the same instruction with the reduced RCX.
                    pRegisters->nRIP = op.nAddress;
                    bBranch = true;
                    break;
                }
            }
            break;
        }
        case MOP_LOOP: {
            int nAddr = (m_nBits == 64) ? 8 : ((m_nBits == 16) ? 2 : 4);
            bool bJump;
            if (op.nAluOp == 3) {  // jecxz: branch when (E)CX == 0, no decrement
                bJump = (pRegisters->getGPR(XEmuRegisters::GPR_RCX, nAddr) == 0);
            } else {
                quint64 nCount = (pRegisters->getGPR(XEmuRegisters::GPR_RCX, nAddr) - 1) & _mask(nAddr);
                pRegisters->setGPR(XEmuRegisters::GPR_RCX, nAddr, nCount);
                bool bZF = pRegisters->getFlag(XEmuRegisters::FLAG_ZF);
                if (op.nAluOp == 0) {
                    bJump = (nCount != 0) && !bZF;  // loopne/loopnz
                } else if (op.nAluOp == 1) {
                    bJump = (nCount != 0) && bZF;  // loope/loopz
                } else {
                    bJump = (nCount != 0);  // loop
                }
            }
            pRegisters->nRIP = bJump ? wrapNearBranch(m_nBits, nCodeSegBase, op.nBranchTarget) : nFall;
            bBranch = true;
            break;
        }
        case MOP_SYSCALL:
            // Real-mode software interrupt: leave the FLAGS/CS/IP frame in memory below SP. A real INT
            // pushes it and the handler's IRET pops it, so SP is unchanged afterwards but the words
            // REMAIN in stack memory -- and programs read them to discover the caller/DOS entry
            // (DaRKSToP does `mov bp,sp / mov ax,[bp-06] / add ax,0Ch / jmp near ax`). Servicing the
            // interrupt natively without writing them left stale data there and sent it to a wrong
            // address. Write the frame without moving SP: that reproduces the observable side effect.
            if (!m_bProtectedMode && (m_nBits == 16) && (op.nAluOp == 2)) {
                const quint64 nSsBase = (quint64)pRegisters->nSS << 4;
                const quint16 nSp = (quint16)pRegisters->getGPR(XEmuRegisters::GPR_RSP, 2);
                const quint16 nRetIp = (quint16)((nFall - nCodeSegBase) & 0xFFFF);
                _memWriteSized(nSsBase + (quint16)(nSp - 2), pRegisters->nRFLAGS & 0xFFFF, 2);
                _memWriteSized(nSsBase + (quint16)(nSp - 4), pRegisters->nCS, 2);
                _memWriteSized(nSsBase + (quint16)(nSp - 6), nRetIp, 2);
            }
            // Advance past the instruction, then hand control to the OS layer,
            // which reads the syscall number/arguments from the registers and sets
            // the return value. (syscall stores the return address in RCX on real
            // hardware; the emulated OS does not depend on that.)
            pRegisters->nRIP = nFall;
            info.result = STEP_SYSCALL;
            info.nVector = (op.nAluOp >= 1) ? (int)(op.nImm & 0xFF) : -1;  // -1 = bare 0F05 syscall
            info.sComment = (op.nAluOp == 1) ? QStringLiteral("int 0x80") : (op.nAluOp == 2) ? QStringLiteral("int") : QStringLiteral("syscall");
            return;
        case MOP_FLAGOP:
            switch (op.nAluOp) {
                case 0: pRegisters->setFlag(XEmuRegisters::FLAG_CF, false); break;
                case 1: pRegisters->setFlag(XEmuRegisters::FLAG_CF, true); break;
                case 2: pRegisters->setFlag(XEmuRegisters::FLAG_CF, !pRegisters->getFlag(XEmuRegisters::FLAG_CF)); break;
                case 3: pRegisters->setFlag(XEmuRegisters::FLAG_DF, false); break;
                case 4: pRegisters->setFlag(XEmuRegisters::FLAG_DF, true); break;
                case 5: pRegisters->setFlag(XEmuRegisters::FLAG_IF, false); break;
                default: pRegisters->setFlag(XEmuRegisters::FLAG_IF, true); break;  // sti
            }
            break;
        case MOP_UNIMPL:
            info.result = STEP_UNIMPLEMENTED;
            info.sComment = QStringLiteral("opcode not implemented");
            return;  // leave RIP at the faulting instruction
    }

    if (m_bExecFault) {
        // Diagnostic (opt-in via XEMU_FAULTDUMP): dump the faulting instruction, the
        // memory operand that computed the bad address, and the register file so the
        // cause of a null/derailed dereference can be pinned down.
        if (qEnvironmentVariableIsSet("XEMU_FAULTDUMP")) {
            fprintf(stderr, "[faultdump] EIP=%08llx op='%s' faultLinear=%08llx\n",
                    (unsigned long long)pRegisters->nRIP,
                    op.sText.toLatin1().constData(),
                    (unsigned long long)m_nFaultAddr);
            dumpMemoryOperand("dst", op.dst);
            dumpMemoryOperand("src", op.src);
            static const char *asName[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
            for (int i = 0; i < 8; i++) {
                fprintf(stderr, "  %s=%08llx", asName[i], (unsigned long long)pRegisters->getGPR(i, 4));
            }
            fprintf(stderr, "\n  --- last %d instructions (oldest first) ---\n", 32);
            for (int k = 32; k >= 1; k--) {
                const int i = (s_ringN - k) & 255;
                if (s_ringN - k < 0) {
                    continue;
                }
                fprintf(stderr, "    %08llx  %-19s  mem=%08llx\n",
                        (unsigned long long)s_ringPc[i], s_ringOp[i], (unsigned long long)s_ringMem[i]);
            }
        }
        info.result = STEP_FAULT;
        info.sComment = QStringLiteral("memory access violation @linear 0x%1").arg(m_nFaultAddr, 0, 16);
        return;  // leave RIP at the faulting instruction
    }

    if (!bBranch) {
        pRegisters->nRIP = nFall;
    }

    // --- single-step trap (TF) ---
    // With TF set the CPU takes interrupt 1 after each instruction. DOS protectors rely on this:
    // they set TF and put a decryptor in their own INT 1 handler, so every instruction is decrypted
    // just before it runs (CRYPTEXE, $Pirit, Aluwain, Crypt, ... all do this). Without the trap the
    // code is never decrypted and execution derails into garbage.
    //
    // The trap decision is made from TF as sampled at the START of the instruction, and from nothing
    // else. That gives the architectural exception directly: a POPF/IRET that *sets* TF does not trap
    // after itself, because bTfBefore was false. It is NOT symmetric -- a POPF that *clears* TF must
    // still trap, and also testing TF afterwards swallowed exactly that trap. ALEC 1.6 counts its own
    // INT 1 traps and requires exactly 8; testing TF after gave 7 from this, and the missing MOV-SS
    // inhibition added 2 more, for 9.
    // An instruction that loaded SS suppresses the trap that would follow IT -- the point is that
    // SS:SP is only half-updated at that moment, so no handler may run on that stack. The trap after
    // the NEXT instruction happens normally. m_bSsBlock is set during this instruction's execution,
    // so testing it here (not a value captured beforehand) is what expresses "the trap after the SS
    // load is the one that is lost".
    // Steps that faulted or need the OS (syscall/halt) are left alone for the caller to service.
    const bool bSsBlocked = m_bSsBlock;
    m_bSsBlock = false;  // consumed: it covers exactly one trap
    if (bTfBefore && !bSsBlocked && (info.result == STEP_OK) && (m_nBits == 16) && !m_bProtectedMode) {
        const quint16 nHOff = m_pMemoryManager->readWord(1 * 4);
        const quint16 nHSeg = m_pMemoryManager->readWord(1 * 4 + 2);
        // Only vector to a real handler in the guest's own memory; the BIOS/DOS default stub is an
        // IRET, so trapping into it every instruction would just burn steps.
        // Any handler in conventional memory counts: a protector may relocate itself anywhere, even
        // below its own PSP (EXEGUARD runs at 03A9 with its PSP at 0435), so a fixed floor like 0x0800
        // silently swallowed the very trap it installs. Segment 0 (an unset vector) and the video/ROM
        // area above A000 are the only things that cannot be a guest single-step handler.
        if ((nHSeg != 0) && (nHSeg < 0xA000)) {
            const quint16 nRetIP = (quint16)((pRegisters->nRIP - ((quint64)pRegisters->nCS << 4)) & 0xFFFF);
            _push(pRegisters->nRFLAGS & 0xFFFF, 2);
            _push(pRegisters->nCS, 2);
            _push(nRetIP, 2);
            pRegisters->setFlag(XEmuRegisters::FLAG_IF, false);
            pRegisters->setFlag(XEmuRegisters::FLAG_TF, false);  // the handler itself runs untraced
            pRegisters->nCS = nHSeg;
            pRegisters->nRIP = ((quint64)nHSeg << 4) + nHOff;
            m_bTrapTaken = true;  // tells run() to leave the current translated block
        }
    }
}

XEmuArch::STEP_INFO XEmuX86::step(XEmuRegisters *pRegisters)
{
    STEP_INFO info;

    XEmuMicroOp op;
    if (!_decodeInsn(pRegisters->nRIP, op)) {
        info.result = STEP_FAULT;
        info.nAddress = pRegisters->nRIP;
        info.sComment = QStringLiteral("cannot fetch instruction");
        return info;
    }

    _execOp(op, pRegisters, info);
    return info;
}

qint64 XEmuX86::run(XEmuRegisters *pRegisters, qint64 nMaxInsns, STEP_INFO *pStopInfo)
{
    qint64 nCount = 0;
    STEP_INFO lastInfo;

    while ((nMaxInsns <= 0) || (nCount < nMaxInsns)) {
        XADDR nPc = pRegisters->nRIP;

        XEmuTB *pBlock = m_tbCache.find(nPc);
        if (!pBlock) {
            pBlock = _translateBlock(nPc);
            m_tbCache.insert(pBlock);
            if (m_nBits == 16) {
                _smcMark(pBlock->nStartAddress, pBlock->nEndAddress);  // writes here must invalidate
            }
            for (quint64 nPage = pBlock->nStartAddress >> N_CODE_PAGE_SHIFT;
                 nPage <= ((pBlock->nEndAddress - 1) >> N_CODE_PAGE_SHIFT); nPage++) {
                m_codePages.insert(nPage);  // any width: _smcMark only covers the real-mode 1 MiB
            }
        }

        bool bStop = false;

        for (int i = 0; i < pBlock->listOps.size(); i++) {
            const XEmuMicroOp &op = pBlock->listOps.at(i);

            STEP_INFO info;
            _execOp(op, pRegisters, info);
            nCount++;
            lastInfo = info;

            if (info.result != STEP_OK) {
                bStop = true;
                break;
            }

            if (op.isBlockTerminator()) {
                break;  // control transfer already updated RIP
            }

            if (m_bTrapTaken) {
                m_bTrapTaken = false;
                break;  // the single-step trap vectored to INT 1: continue from the handler
            }

            if ((nMaxInsns > 0) && (nCount >= nMaxInsns)) {
                bStop = true;
                break;
            }
        }

        if (bStop) {
            break;
        }
    }

    if (pStopInfo) {
        *pStopInfo = lastInfo;
    }

    return nCount;
}

QString XEmuX86::getRegistersText(const XEmuRegisters *pRegisters) const
{
    QString sResult;

    if (m_nBits == 64) {
        static const char *const pszNames[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                                 "r8 ", "r9 ", "r10", "r11", "r12", "r13", "r14", "r15"};
        for (int i = 0; i < 16; i++) {
            sResult += QString("%1 = %2\n").arg(QString::fromLatin1(pszNames[i])).arg(pRegisters->nGPR[i], 16, 16, QChar('0'));
        }
        sResult += QString("rip = %1\n").arg(pRegisters->nRIP, 16, 16, QChar('0'));
    } else {
        static const char *const pszNames[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        for (int i = 0; i < 8; i++) {
            sResult += QString("%1 = %2\n").arg(QString::fromLatin1(pszNames[i])).arg((quint32)pRegisters->nGPR[i], 8, 16, QChar('0'));
        }
        sResult += QString("eip = %1\n").arg((quint32)pRegisters->nRIP, 8, 16, QChar('0'));
    }

    sResult += QString("eflags = %1\n").arg(pRegisters->nRFLAGS, 8, 16, QChar('0'));
    sResult += QString("cs=%1 ds=%2 es=%3 fs=%4 gs=%5 ss=%6\n")
                   .arg(pRegisters->nCS, 4, 16, QChar('0'))
                   .arg(pRegisters->nDS, 4, 16, QChar('0'))
                   .arg(pRegisters->nES, 4, 16, QChar('0'))
                   .arg(pRegisters->nFS, 4, 16, QChar('0'))
                   .arg(pRegisters->nGS, 4, 16, QChar('0'))
                   .arg(pRegisters->nSS, 4, 16, QChar('0'));
    sResult += QString("fs_base = %1  gs_base = %2\n").arg(pRegisters->nFSBase, 16, 16, QChar('0')).arg(pRegisters->nGSBase, 16, 16, QChar('0'));

    return sResult;
}
