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
#include "xemuelf.h"

#include "xelf.h"

XEmuELF::XEmuELF(QObject *pParent) : XEmuGenericFormat(pParent)
{
}

XBinary *XEmuELF::createBinary(QIODevice *pDevice)
{
    XELF probe(pDevice);
    const quint16 type = probe.is64() ? probe.getHdr64_type() : probe.getHdr32_type();
    XADDR base = 0;
    if (type == XELF_DEF::S_ET_EXEC) {
        const QList<XELF_DEF::Elf_Phdr> headers = probe.getElf_PhdrList(128);
        for (const XELF_DEF::Elf_Phdr &header : headers) {
            if (header.p_type == XELF_DEF::S_PT_LOAD &&
                (base == 0 || header.p_vaddr < base)) {
                base = XEmuMemoryManager::alignDown(header.p_vaddr,
                                                    XEmuMemoryManager::N_PAGE_SIZE);
            }
        }
    }
    return new XELF(pDevice, false, base);
}
