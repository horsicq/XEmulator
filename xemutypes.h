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
#ifndef XEMUTYPES_H
#define XEMUTYPES_H

#include <QString>

#include "xbinary.h"

// Architectures the emulator can model. XBinary::ARCH only covers x86, so the
// emulator carries its own enum (resolved from XBinary::getDisasmMode()).
enum XEmuArchType {
    XARCH_UNKNOWN = 0,
    XARCH_X86_16,  // 8086 / real mode (MS-DOS)
    XARCH_X86_32,
    XARCH_X86_64,
    XARCH_ARM,     // AArch32
    XARCH_ARM64    // AArch64
};

inline const char *xemuArchTypeName(XEmuArchType archType)
{
    switch (archType) {
        case XARCH_X86_16: return "x86-16";
        case XARCH_X86_32: return "x86";
        case XARCH_X86_64: return "x86-64";
        case XARCH_ARM: return "ARM";
        case XARCH_ARM64: return "ARM64";
        default: return "unknown";
    }
}

// Register width in bits.
inline int xemuArchBits(XEmuArchType archType)
{
    switch (archType) {
        case XARCH_X86_16: return 16;
        case XARCH_X86_32: return 32;
        case XARCH_ARM: return 32;
        case XARCH_X86_64: return 64;
        case XARCH_ARM64: return 64;
        default: return 0;
    }
}

// Map a XBinary disasm mode to an emulator architecture.
inline XEmuArchType xemuArchTypeFromDisasmMode(XBinary::DM disasmMode)
{
    switch (disasmMode) {
        case XBinary::DM_8086: return XARCH_X86_16;
        case XBinary::DM_X86_32: return XARCH_X86_32;
        case XBinary::DM_X86_64: return XARCH_X86_64;
        case XBinary::DM_ARM_LE:
        case XBinary::DM_ARM_BE:
        case XBinary::DM_CORTEXM:
        case XBinary::DM_THUMB_LE:
        case XBinary::DM_THUMB_BE: return XARCH_ARM;
        case XBinary::DM_AARCH64_LE:
        case XBinary::DM_AARCH64_BE: return XARCH_ARM64;
        default: return XARCH_UNKNOWN;
    }
}

#endif  // XEMUTYPES_H
