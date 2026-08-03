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
#include "xemuregisters.h"

XEmuRegisters::XEmuRegisters()
{
    reset();
}

void XEmuRegisters::reset()
{
    for (int i = 0; i < 32; i++) {
        nGPR[i] = 0;
    }

    nSP = 0;
    nRIP = 0;
    nRFLAGS = 0x202;  // reserved bit 1 + IF

    nCS = 0;
    nDS = 0;
    nES = 0;
    nFS = 0;
    nGS = 0;
    nSS = 0;

    nFSBase = 0;
    nGSBase = 0;
    nTPIDR = 0;

    nCR0 = 0;
    nCR3 = 0;
    nCR4 = 0;

    for (int i = 0; i < 8; i++) {
        nMMX[i] = 0;
    }
}

quint64 XEmuRegisters::getGPR(qint32 nIndex, qint32 nSize) const
{
    if ((nIndex < 0) || (nIndex > 15)) {
        return 0;
    }

    quint64 nValue = nGPR[nIndex];

    switch (nSize) {
        case 1: return nValue & 0xFF;
        case 2: return nValue & 0xFFFF;
        case 4: return nValue & 0xFFFFFFFF;
        default: return nValue;
    }
}

void XEmuRegisters::setGPR(qint32 nIndex, qint32 nSize, quint64 nValue)
{
    if ((nIndex < 0) || (nIndex > 15)) {
        return;
    }

    switch (nSize) {
        case 1:
            // Low byte only (AL/CL/...); high-byte encodings are not handled here.
            nGPR[nIndex] = (nGPR[nIndex] & ~Q_UINT64_C(0xFF)) | (nValue & 0xFF);
            break;
        case 2:
            nGPR[nIndex] = (nGPR[nIndex] & ~Q_UINT64_C(0xFFFF)) | (nValue & 0xFFFF);
            break;
        case 4:
            // 32-bit writes zero-extend into the full 64-bit register.
            nGPR[nIndex] = nValue & 0xFFFFFFFF;
            break;
        default:
            nGPR[nIndex] = nValue;
            break;
    }
}

bool XEmuRegisters::getFlag(FLAG flag) const
{
    return (nRFLAGS & (quint64)flag) != 0;
}

void XEmuRegisters::setFlag(FLAG flag, bool bValue)
{
    if (bValue) {
        nRFLAGS |= (quint64)flag;
    } else {
        nRFLAGS &= ~(quint64)flag;
    }
}

const char *XEmuRegisters::getGPRName(qint32 nIndex, qint32 nSize)
{
    static const char *const pszNames64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    static const char *const pszNames32[16] = {"eax",  "ecx",  "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
                                               "r8d",  "r9d",  "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    static const char *const pszNames16[16] = {"ax",   "cx",   "dx",   "bx",   "sp",   "bp",   "si",   "di",
                                               "r8w",  "r9w",  "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    static const char *const pszNames8[16] = {"al",   "cl",   "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
                                              "r8b",  "r9b",  "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};

    if ((nIndex < 0) || (nIndex > 15)) {
        return "?";
    }

    switch (nSize) {
        case 1: return pszNames8[nIndex];
        case 2: return pszNames16[nIndex];
        case 4: return pszNames32[nIndex];
        default: return pszNames64[nIndex];
    }
}
