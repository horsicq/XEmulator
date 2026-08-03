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
#include "xemufileformat.h"

#include <limits>

XEmuFileFormat::XEmuFileFormat(QObject *pParent) : QObject(pParent)
{
}

XEmuFileFormat::~XEmuFileFormat()
{
}

bool XEmuFileFormat::mapByMemoryMap(XBinary *pBinary, XEmuMemoryManager *pMemoryManager, XADDR nMapBase, const QString &sModuleName, MODULE *pModuleResult)
{
    if (!pBinary || !pMemoryManager || nMapBase == 0
        || nMapBase
               != XEmuMemoryManager::alignDown(
                   nMapBase, XEmuMemoryManager::N_PAGE_SIZE)) {
        return false;
    }
    XBinary::_MEMORY_MAP memoryMap = pBinary->getMemoryMap();
    XADDR nPreferredBase = memoryMap.nModuleAddress;

    // Determine the span of the image from the memory-map records.
    XADDR nMaxEnd = nPreferredBase;
    for (int i = 0; i < memoryMap.listRecords.count(); i++) {
        const XBinary::_MEMORY_RECORD &record = memoryMap.listRecords.at(i);
        if (record.nSize <= 0 || record.nAddress < nPreferredBase) {
            continue;
        }
        const quint64 nRecordSize =
            static_cast<quint64>(record.nSize);
        if (record.nAddress
                > (std::numeric_limits<quint64>::max)()
                      - nRecordSize) {
            return false;
        }
        nMaxEnd =
            qMax<XADDR>(nMaxEnd, record.nAddress + nRecordSize);
    }

    const quint64 nRecordSpan = nMaxEnd - nPreferredBase;
    quint64 nImageSize =
        XEmuMemoryManager::alignUp(
            nRecordSpan, XEmuMemoryManager::N_PAGE_SIZE);
    if (nRecordSpan != 0 && nImageSize == 0) {
        return false;
    }
    if (memoryMap.nImageSize > 0
        && static_cast<quint64>(memoryMap.nImageSize)
               > nImageSize) {
        nImageSize = XEmuMemoryManager::alignUp(
            static_cast<quint64>(memoryMap.nImageSize),
            XEmuMemoryManager::N_PAGE_SIZE);
        if (nImageSize == 0) {
            return false;
        }
    }
    if (nImageSize == 0) {
        nImageSize = XEmuMemoryManager::N_PAGE_SIZE;
    }
    if (nImageSize > XEmuMemoryManager::N_MAX_TOTAL_COMMIT) {
        return false;
    }
    const XADDR nEntry = memoryMap.nEntryPointAddress;
    if (nEntry != 0
        && (nEntry < nPreferredBase
            || nEntry - nPreferredBase >= nImageSize)) {
        return false;
    }

    const XADDR nReservedBase =
        pMemoryManager->reserve(nMapBase, nImageSize, sModuleName);
    if (nReservedBase != nMapBase) {
        if (nReservedBase != 0) {
            pMemoryManager->release(nReservedBase);
        }
        return false;
    }

    for (int i = 0; i < memoryMap.listRecords.count(); i++) {
        const XBinary::_MEMORY_RECORD &record = memoryMap.listRecords.at(i);

        // Only map records that fall inside the reserved image (guards against
        // malformed / overlay records with out-of-range addresses).
        if ((record.nSize <= 0) || (record.nAddress < nPreferredBase)) {
            continue;
        }
        quint64 nOffsetInImage = record.nAddress - nPreferredBase;
        if (nOffsetInImage >= nImageSize) {
            continue;
        }
        quint64 nMapSize = qMin<quint64>(record.nSize, nImageSize - nOffsetInImage);

        XADDR nTarget = nMapBase + nOffsetInImage;
        if (!pMemoryManager->commit(
                nTarget, nMapSize,
                XEmuMemoryManager::MEMORY_FLAGS(
                    true, true, true))) {
            pMemoryManager->release(nMapBase);
            return false;
        }

        if (!record.bIsVirtual) {
            const qint64 nBinarySize = pBinary->getSize();
            if (record.nOffset < 0 || nBinarySize < 0
                || record.nOffset > nBinarySize
                || nMapSize
                       > static_cast<quint64>(
                           nBinarySize - record.nOffset)) {
                pMemoryManager->release(nMapBase);
                return false;
            }
            const QByteArray data =
                pBinary->read_array(record.nOffset, nMapSize);
            if (data.size() != static_cast<int>(nMapSize)
                || !pMemoryManager->write(nTarget, data)) {
                pMemoryManager->release(nMapBase);
                return false;
            }
        }
    }

    if (pModuleResult) {
        pModuleResult->sName = sModuleName;
        pModuleResult->nBaseAddress = nMapBase;
        pModuleResult->nImageSize = nImageSize;
        pModuleResult->nEntryPointAddress = nEntry ? (nMapBase + (nEntry - nPreferredBase)) : 0;
    }

    return true;
}
