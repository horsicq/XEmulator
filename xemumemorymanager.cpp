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
#include "xemumemorymanager.h"

#include <QtEndian>
#include <cstring>
#include <limits>

const quint64 XEmuMemoryManager::N_MAX_SINGLE_COMMIT;
const quint64 XEmuMemoryManager::N_MAX_TOTAL_COMMIT;
const int XEmuMemoryManager::N_MAX_REGIONS;

XEmuMemoryManager::XEmuMemoryManager(QObject *pParent)
    : QObject(pParent),
      m_nBits(64),
      m_nMinAddress(0x10000),
      m_nMaxAddress(Q_UINT64_C(0x00007FFFFFFF0000)),
      m_nCommittedBytes(0),
      m_nNextCallbackId(1)
{
}

void XEmuMemoryManager::setBits(quint8 nBits)
{
    if ((nBits != 32 && nBits != 64)
        || (!m_listRegions.isEmpty() && nBits != m_nBits)) {
        emit errorMessage(tr("Cannot change the emulated address width while memory is mapped"));
        return;
    }
    m_nBits = nBits;

    if (nBits == 32) {
        m_nMinAddress = 0x10000;
        m_nMaxAddress = 0x7FFF0000;
    } else {
        m_nMinAddress = 0x10000;
        m_nMaxAddress = Q_UINT64_C(0x00007FFFFFFF0000);
    }
}

quint8 XEmuMemoryManager::getBits() const
{
    return m_nBits;
}

void XEmuMemoryManager::clear()
{
    m_listRegions.clear();
    m_nCommittedBytes = 0;
}

quint64 XEmuMemoryManager::alignUp(quint64 nValue, quint64 nAlignment)
{
    if (nAlignment == 0) {
        return nValue;
    }

    const quint64 nRemainder = nValue % nAlignment;
    if (nRemainder == 0) {
        return nValue;
    }
    const quint64 nDelta = nAlignment - nRemainder;
    if (nValue > (std::numeric_limits<quint64>::max)() - nDelta) {
        return 0;
    }
    return nValue + nDelta;
}

quint64 XEmuMemoryManager::alignDown(quint64 nValue, quint64 nAlignment)
{
    if (nAlignment == 0) {
        return nValue;
    }

    return (nValue / nAlignment) * nAlignment;
}

int XEmuMemoryManager::_findContainingIndex(XADDR nAddress) const
{
    for (int i = 0; i < m_listRegions.size(); i++) {
        const REGION &region = m_listRegions.at(i);

        if (nAddress >= region.nAddress
            && nAddress - region.nAddress < region.nSize) {
            return i;
        }
    }

    return -1;
}

bool XEmuMemoryManager::_regionAddressLess(const REGION &r1, const REGION &r2)
{
    return r1.nAddress < r2.nAddress;
}

void XEmuMemoryManager::_sort()
{
    std::sort(m_listRegions.begin(), m_listRegions.end(), _regionAddressLess);
}

int XEmuMemoryManager::_split(int nIndex, XADDR nStart, XADDR nEnd)
{
    if (nIndex < 0 || nIndex >= m_listRegions.size()) {
        return -1;
    }
    REGION region = m_listRegions.at(nIndex);
    if (region.nAddress
            > (std::numeric_limits<quint64>::max)() - region.nSize) {
        return -1;
    }
    XADDR nRegionEnd = region.nAddress + region.nSize;
    const int nGrowth = _splitGrowth(nIndex, nStart, nEnd);
    if (nGrowth < 0
        || nGrowth > N_MAX_REGIONS - m_listRegions.size()
        || !_validateBacking(region)) {
        return -1;
    }

    QList<REGION> listPieces;
    int nMidOffset = 0;

    if (nStart > region.nAddress) {
        REGION left = region;
        left.nSize = nStart - region.nAddress;
        if (!_sliceBacking(region, 0, left.nSize,
                           &left.listData)) {
            return -1;
        }
        listPieces.append(left);
        nMidOffset = 1;
    }

    REGION mid = region;
    mid.nAddress = nStart;
    mid.nSize = nEnd - nStart;
    if (!_sliceBacking(region, nStart - region.nAddress,
                       mid.nSize, &mid.listData)) {
        return -1;
    }
    listPieces.append(mid);

    if (nEnd < nRegionEnd) {
        REGION right = region;
        right.nAddress = nEnd;
        right.nSize = nRegionEnd - nEnd;
        if (!_sliceBacking(region, nEnd - region.nAddress,
                           right.nSize, &right.listData)) {
            return -1;
        }
        listPieces.append(right);
    }

    m_listRegions.removeAt(nIndex);

    for (int i = 0; i < listPieces.size(); i++) {
        m_listRegions.insert(nIndex + i, listPieces.at(i));
    }

    return nIndex + nMidOffset;
}

int XEmuMemoryManager::_splitGrowth(int nIndex, XADDR nStart,
                                    XADDR nEnd) const
{
    if (nIndex < 0 || nIndex >= m_listRegions.size()) {
        return -1;
    }
    const REGION &region = m_listRegions.at(nIndex);
    if (region.nAddress
            > (std::numeric_limits<quint64>::max)() - region.nSize) {
        return -1;
    }
    const XADDR nRegionEnd = region.nAddress + region.nSize;
    if (nStart < region.nAddress || nEnd <= nStart
        || nEnd > nRegionEnd) {
        return -1;
    }
    return (nStart > region.nAddress ? 1 : 0)
           + (nEnd < nRegionEnd ? 1 : 0);
}

bool XEmuMemoryManager::_normalizePageRange(XADDR nAddress, quint64 nSize,
                                            XADDR *pStart,
                                            XADDR *pEnd) const
{
    if (nSize == 0
        || nAddress
               > (std::numeric_limits<quint64>::max)() - nSize) {
        return false;
    }
    const XADDR nStart = alignDown(nAddress, N_PAGE_SIZE);
    const XADDR nEnd = alignUp(nAddress + nSize, N_PAGE_SIZE);
    if (nEnd == 0 || nEnd <= nStart || nEnd > m_nMaxAddress) {
        return false;
    }
    if (pStart) {
        *pStart = nStart;
    }
    if (pEnd) {
        *pEnd = nEnd;
    }
    return true;
}

bool XEmuMemoryManager::_flagsEqual(const MEMORY_FLAGS &left,
                                    const MEMORY_FLAGS &right)
{
    return left.bRead == right.bRead
           && left.bWrite == right.bWrite
           && left.bExec == right.bExec
           && left.bGuard == right.bGuard;
}

void XEmuMemoryManager::_appendBackingSlice(
    QList<BACKING_SLICE> *pList,
    const BACKING_SLICE &slice)
{
    if (!pList || slice.nSize == 0) {
        return;
    }
    if (!pList->isEmpty()) {
        BACKING_SLICE &last = (*pList)[pList->size() - 1];
        if (last.pData == slice.pData
            && last.nDataOffset
                   <= (std::numeric_limits<quint64>::max)()
                          - last.nSize
            && last.nDataOffset + last.nSize
                   == slice.nDataOffset
            && last.nSize
                   <= (std::numeric_limits<quint64>::max)()
                          - slice.nSize) {
            last.nSize += slice.nSize;
            return;
        }
    }
    pList->append(slice);
}

bool XEmuMemoryManager::_validateBacking(const REGION &region)
{
    if (region.state != STATE_COMMIT) {
        return region.listData.isEmpty();
    }
    quint64 nTotal = 0;
    for (int i = 0; i < region.listData.size(); i++) {
        const BACKING_SLICE &slice =
            region.listData.at(i);
        if (slice.pData.isNull() || slice.nSize == 0
            || slice.nDataOffset
                   > static_cast<quint64>(
                       slice.pData->size())
            || slice.nSize
                   > static_cast<quint64>(
                         slice.pData->size())
                         - slice.nDataOffset
            || nTotal
                   > (std::numeric_limits<quint64>::max)()
                         - slice.nSize) {
            return false;
        }
        nTotal += slice.nSize;
    }
    return nTotal == region.nSize;
}

bool XEmuMemoryManager::_sliceBacking(
    const REGION &region, quint64 nOffset,
    quint64 nSize, QList<BACKING_SLICE> *pResult)
{
    if (!pResult || nOffset > region.nSize
        || nSize > region.nSize - nOffset
        || !_validateBacking(region)) {
        return false;
    }
    pResult->clear();
    if (region.state != STATE_COMMIT) {
        return true;
    }

    quint64 nSkip = nOffset;
    quint64 nRemaining = nSize;
    for (int i = 0;
         i < region.listData.size() && nRemaining > 0;
         i++) {
        const BACKING_SLICE &source =
            region.listData.at(i);
        if (nSkip >= source.nSize) {
            nSkip -= source.nSize;
            continue;
        }
        BACKING_SLICE result = source;
        result.nDataOffset += nSkip;
        result.nSize =
            qMin(source.nSize - nSkip, nRemaining);
        _appendBackingSlice(pResult, result);
        nRemaining -= result.nSize;
        nSkip = 0;
    }
    if (nRemaining != 0) {
        pResult->clear();
        return false;
    }
    return true;
}

void XEmuMemoryManager::_coalesce()
{
    for (int i = 0; i + 1 < m_listRegions.size();) {
        REGION &left = m_listRegions[i];
        const REGION &right = m_listRegions.at(i + 1);
        if (left.nAddress
                > (std::numeric_limits<quint64>::max)()
                      - left.nSize
            || left.nAddress + left.nSize != right.nAddress
            || left.nAllocationBase != right.nAllocationBase
            || left.state != right.state
            || !_flagsEqual(left.flags, right.flags)
            || left.sName != right.sName) {
            ++i;
            continue;
        }
        if (left.state == STATE_COMMIT) {
            if (!_validateBacking(left)
                || !_validateBacking(right)) {
                ++i;
                continue;
            }
        }
        if (left.nSize
                > (std::numeric_limits<quint64>::max)()
                      - right.nSize) {
            ++i;
            continue;
        }
        if (left.state == STATE_COMMIT) {
            for (int j = 0; j < right.listData.size();
                 j++) {
                _appendBackingSlice(
                    &left.listData,
                    right.listData.at(j));
            }
        }
        left.nSize += right.nSize;
        m_listRegions.removeAt(i + 1);
    }
}

XADDR XEmuMemoryManager::reserve(XADDR nAddress, quint64 nSize, const QString &sName)
{
    if (nSize == 0) {
        emit errorMessage(tr("Cannot reserve a zero-sized region"));
        return 0;
    }

    quint64 nAlignedSize = 0;
    if (m_listRegions.size() >= N_MAX_REGIONS) {
        emit errorMessage(tr("Reservation size/count exceeds the emulator safety limit"));
        return 0;
    }

    if (nAddress == 0) {
        nAlignedSize = alignUp(nSize, N_PAGE_SIZE);
        if (nAlignedSize == 0) {
            emit errorMessage(tr("Reservation size exceeds the emulator safety limit"));
            return 0;
        }
        nAddress = findFree(nAlignedSize, m_nMinAddress, N_ALLOCATION_GRANULARITY);

        if (nAddress == 0) {
            emit errorMessage(tr("Cannot find a free region of size %1").arg(nAlignedSize));
            return 0;
        }
    } else {
        XADDR nStart = 0;
        XADDR nEnd = 0;
        if (!_normalizePageRange(nAddress, nSize, &nStart, &nEnd)
            || nStart == 0) {
            emit errorMessage(tr("Reservation range exceeds the emulated address space"));
            return 0;
        }
        nAddress = nStart;
        nAlignedSize = nEnd - nStart;
    }

    if (nAddress > m_nMaxAddress
        || nAlignedSize > m_nMaxAddress - nAddress) {
        emit errorMessage(tr("Reservation range exceeds the emulated address space"));
        return 0;
    }
    XADDR nEnd = nAddress + nAlignedSize;

    // The whole range must be free.
    for (int i = 0; i < m_listRegions.size(); i++) {
        const REGION &region = m_listRegions.at(i);
        XADDR nRegionEnd = region.nAddress + region.nSize;

        if ((nAddress < nRegionEnd) && (region.nAddress < nEnd)) {
            emit errorMessage(tr("Address range %1 is already reserved").arg(nAddress, 0, 16));
            return 0;
        }
    }

    REGION region;
    region.nAddress = nAddress;
    region.nSize = nAlignedSize;
    region.nAllocationBase = nAddress;
    region.state = STATE_RESERVED;
    region.sName = sName;
    QList<REGION> listOriginal;
    try {
        listOriginal = m_listRegions;
    } catch (...) {
        emit errorMessage(tr("Cannot snapshot the memory map for a transactional reservation"));
        return 0;
    }
    try {
        m_listRegions.append(region);
        _sort();
    } catch (...) {
        m_listRegions.swap(listOriginal);
        emit errorMessage(tr("Host allocation failed while reserving emulated memory"));
        return 0;
    }

    return nAddress;
}

bool XEmuMemoryManager::mapFixed(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags, const QString &sName)
{
    if (m_listRegions.size() >= N_MAX_REGIONS) {
        return false;
    }

    XADDR nStart = 0;
    XADDR nAlignedEnd = 0;
    if (!_normalizePageRange(nAddress, nSize, &nStart,
                             &nAlignedEnd)) {
        return false;
    }
    quint64 nAlignedSize = nAlignedEnd - nStart;
    XADDR nEnd = nStart + nAlignedSize;

    // The whole range must be free.
    for (int i = 0; i < m_listRegions.size(); i++) {
        const REGION &region = m_listRegions.at(i);
        XADDR nRegionEnd = region.nAddress + region.nSize;
        if ((nStart < nRegionEnd) && (region.nAddress < nEnd)) {
            emit errorMessage(tr("Address range %1 is already reserved").arg(nStart, 0, 16));
            return false;
        }
    }

    REGION region;
    region.nAddress = nStart;
    region.nSize = nAlignedSize;
    region.nAllocationBase = nStart;
    region.state = STATE_RESERVED;
    region.sName = sName;
    QList<REGION> listOriginal;
    try {
        listOriginal = m_listRegions;
    } catch (...) {
        emit errorMessage(tr("Cannot snapshot the memory map for a transactional fixed mapping"));
        return false;
    }
    try {
        m_listRegions.append(region);
        _sort();
    } catch (...) {
        m_listRegions.swap(listOriginal);
        emit errorMessage(tr("Host allocation failed while mapping fixed emulated memory"));
        return false;
    }

    if (!commit(nStart, nAlignedSize, flags)) {
        release(nStart);
        return false;
    }
    return true;
}

bool XEmuMemoryManager::commit(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags)
{
    XADDR nStart = 0;
    XADDR nEnd = 0;
    if (!_normalizePageRange(nAddress, nSize, &nStart, &nEnd)) {
        return false;
    }

    QList<REGION> listOriginal;
    try {
        listOriginal = m_listRegions;
    } catch (...) {
        emit errorMessage(tr("Cannot snapshot the memory map for a transactional commit"));
        return false;
    }
    const quint64 nOriginalCommittedBytes = m_nCommittedBytes;
    const auto rollback = [&]() -> bool {
        m_listRegions.swap(listOriginal);
        m_nCommittedBytes = nOriginalCommittedBytes;
        return false;
    };

    try {
        _coalesce();
        const int nStartIndex =
            _findContainingIndex(nStart);
        if (nStartIndex < 0) {
            emit errorMessage(tr("Cannot commit memory at %1: not reserved").arg(nStart, 0, 16));
            return rollback();
        }
        const quint64 nCommitSize = nEnd - nStart;
        if (nCommitSize > N_MAX_SINGLE_COMMIT
            || nCommitSize
                   > static_cast<quint64>(
                       (std::numeric_limits<int>::max)())) {
            emit errorMessage(tr("Commit of %1 bytes exceeds the emulator host-memory safety limit")
                                  .arg(nCommitSize));
            return rollback();
        }

        const XADDR nAllocationBase =
            m_listRegions.at(nStartIndex).nAllocationBase;
        quint64 nNewCommittedBytes = 0;
        int nRequiredGrowth = 0;
        XADDR nPreflightCursor = nStart;
        while (nPreflightCursor < nEnd) {
            const int nIndex =
                _findContainingIndex(nPreflightCursor);
            if (nIndex < 0) {
                emit errorMessage(tr("Commit range contains unreserved memory"));
                return rollback();
            }
            const REGION &region =
                m_listRegions.at(nIndex);
            if (region.nAllocationBase != nAllocationBase
                || region.nAddress
                       > (std::numeric_limits<quint64>::max)()
                             - region.nSize) {
                emit errorMessage(tr("Commit range crosses a reservation boundary at %1").arg(nPreflightCursor, 0, 16));
                return rollback();
            }
            const XADDR nRegionEnd =
                region.nAddress + region.nSize;
            const XADDR nSliceEnd =
                qMin(nEnd, nRegionEnd);
            if (nSliceEnd <= nPreflightCursor) {
                return rollback();
            }
            const bool bNeedsChange =
                region.state != STATE_COMMIT
                || !_flagsEqual(region.flags, flags);
            if (bNeedsChange) {
                const int nGrowth =
                    _splitGrowth(
                        nIndex, nPreflightCursor,
                        nSliceEnd);
                if (nGrowth < 0
                    || nRequiredGrowth
                           > N_MAX_REGIONS
                                 - m_listRegions.size()
                                 - nGrowth) {
                    emit errorMessage(tr("Commit would exceed the emulator region safety limit"));
                    return rollback();
                }
                nRequiredGrowth += nGrowth;
            }
            if (region.state != STATE_COMMIT) {
                const quint64 nSliceSize =
                    nSliceEnd - nPreflightCursor;
                if (nNewCommittedBytes
                        > N_MAX_TOTAL_COMMIT
                              - nSliceSize) {
                    emit errorMessage(tr("Commit exceeds the emulator host-memory safety limit"));
                    return rollback();
                }
                nNewCommittedBytes += nSliceSize;
            }
            nPreflightCursor = nSliceEnd;
        }

        if (nNewCommittedBytes
                > N_MAX_TOTAL_COMMIT
                      - qMin(m_nCommittedBytes,
                             N_MAX_TOTAL_COMMIT)) {
            emit errorMessage(tr("Commit exceeds the emulator host-memory safety limit"));
            return rollback();
        }

        XADDR nCursor = nStart;
        while (nCursor < nEnd) {
            const int nIndex =
                _findContainingIndex(nCursor);
            if (nIndex < 0) {
                return rollback();
            }
            const XADDR nRegionEnd =
                m_listRegions.at(nIndex).nAddress
                + m_listRegions.at(nIndex).nSize;
            const XADDR nSliceEnd =
                qMin(nEnd, nRegionEnd);
            if (m_listRegions.at(nIndex).state
                    == STATE_COMMIT
                && _flagsEqual(
                    m_listRegions.at(nIndex).flags,
                    flags)) {
                nCursor = nSliceEnd;
                continue;
            }
            const int nMid =
                _split(nIndex, nCursor, nSliceEnd);
            if (nMid < 0) {
                return rollback();
            }
            REGION &mid = m_listRegions[nMid];
            if (mid.state != STATE_COMMIT) {
                BACKING_SLICE slice;
                slice.pData =
                    QSharedPointer<QByteArray>::create(
                        static_cast<int>(mid.nSize), 0);
                slice.nDataOffset = 0;
                slice.nSize = mid.nSize;
                mid.listData.clear();
                mid.listData.append(slice);
                mid.state = STATE_COMMIT;
                m_nCommittedBytes += mid.nSize;
            }
            mid.flags = flags;
            nCursor = nSliceEnd;
        }

        _coalesce();
        return true;
    } catch (...) {
        emit errorMessage(tr("Host allocation failed while committing emulated memory"));
        return rollback();
    }
}

XADDR XEmuMemoryManager::allocate(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags, const QString &sName)
{
    XADDR nBase = reserve(nAddress, nSize, sName);

    if (nBase == 0) {
        return 0;
    }

    const int nReservationIndex =
        _findContainingIndex(nBase);
    if (nReservationIndex < 0
        || m_listRegions.at(nReservationIndex).nAllocationBase
               != nBase
        || m_listRegions.at(nReservationIndex).state
               != STATE_RESERVED
        || !commit(
            nBase,
            m_listRegions.at(nReservationIndex).nSize,
            flags)) {
        release(nBase);
        return 0;
    }

    return nBase;
}

bool XEmuMemoryManager::protect(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags)
{
    XADDR nStart = 0;
    XADDR nEnd = 0;
    if (!_normalizePageRange(nAddress, nSize, &nStart, &nEnd)) {
        return false;
    }

    // Like Linux mprotect, the range may span several adjacent mappings; every page
    // in it must be committed. Apply the new protection to each covered region,
    // splitting them at the range boundaries.
    if (!isCommitted(nStart, nEnd - nStart)) {
        return false;
    }

    int nRequiredGrowth = 0;
    XADDR nPreflightCursor = nStart;
    while (nPreflightCursor < nEnd) {
        const int nIndex = _findContainingIndex(nPreflightCursor);
        if (nIndex < 0) {
            return false;
        }
        const REGION &region = m_listRegions.at(nIndex);
        if (region.nAddress
                > (std::numeric_limits<quint64>::max)()
                      - region.nSize) {
            return false;
        }
        const XADDR nRegionEnd = region.nAddress + region.nSize;
        const XADDR nSliceEnd = qMin(nEnd, nRegionEnd);
        if (nSliceEnd <= nPreflightCursor) {
            return false;
        }
        if (!_flagsEqual(region.flags, flags)) {
            const int nGrowth =
                _splitGrowth(nIndex, nPreflightCursor, nSliceEnd);
            if (nGrowth < 0
                || nRequiredGrowth
                       > N_MAX_REGIONS - m_listRegions.size() - nGrowth) {
                emit errorMessage(tr("Protection change would exceed the emulator region safety limit"));
                return false;
            }
            nRequiredGrowth += nGrowth;
        }
        nPreflightCursor = nSliceEnd;
    }

    QList<REGION> listOriginal;
    try {
        listOriginal = m_listRegions;
    } catch (...) {
        emit errorMessage(tr("Cannot snapshot the memory map for a transactional protection change"));
        return false;
    }
    const auto rollback = [&]() -> bool {
        m_listRegions.swap(listOriginal);
        return false;
    };

    try {
        XADDR nCursor = nStart;
        while (nCursor < nEnd) {
            const int nIndex =
                _findContainingIndex(nCursor);
            if (nIndex < 0) {
                return rollback();
            }

            const XADDR nRegionEnd =
                m_listRegions.at(nIndex).nAddress
                + m_listRegions.at(nIndex).nSize;
            const XADDR nSliceEnd =
                qMin(nEnd, nRegionEnd);

            if (!_flagsEqual(
                    m_listRegions.at(nIndex).flags,
                    flags)) {
                const int nMid =
                    _split(nIndex, nCursor, nSliceEnd);
                if (nMid < 0) {
                    return rollback();
                }
                m_listRegions[nMid].flags = flags;
            }

            nCursor = nSliceEnd;
        }

        _coalesce();
        return true;
    } catch (...) {
        emit errorMessage(tr("Host allocation failed while changing emulated memory protection"));
        return rollback();
    }
}

bool XEmuMemoryManager::release(XADDR nAddress)
{
    int nIndex = _findContainingIndex(nAddress);

    if (nIndex < 0) {
        return false;
    }

    XADDR nAllocationBase = m_listRegions.at(nIndex).nAllocationBase;

    for (int i = m_listRegions.size() - 1; i >= 0; i--) {
        if (m_listRegions.at(i).nAllocationBase == nAllocationBase) {
            if (m_listRegions.at(i).state == STATE_COMMIT) {
                const quint64 nBytes = m_listRegions.at(i).nSize;
                m_nCommittedBytes =
                    nBytes <= m_nCommittedBytes
                        ? m_nCommittedBytes - nBytes
                        : 0;
            }
            m_listRegions.removeAt(i);
        }
    }

    return true;
}

XADDR XEmuMemoryManager::findFree(quint64 nSize, XADDR nStart, quint64 nAlignment) const
{
    if (nAlignment == 0) {
        nAlignment = N_PAGE_SIZE;
    }

    quint64 nAlignedSize = alignUp(nSize, N_PAGE_SIZE);
    if (nAlignedSize == 0 || nAlignedSize > m_nMaxAddress) {
        return 0;
    }
    XADDR nCandidate = alignUp(qMax(nStart, m_nMinAddress), nAlignment);
    if (nCandidate == 0) {
        return 0;
    }

    // m_listRegions is kept sorted by address.
    for (int i = 0; i < m_listRegions.size(); i++) {
        const REGION &region = m_listRegions.at(i);
        XADDR nRegionEnd = region.nAddress + region.nSize;

        if (nRegionEnd <= nCandidate) {
            continue;
        }

        if (nCandidate <= (std::numeric_limits<quint64>::max)() - nAlignedSize
            && region.nAddress >= (nCandidate + nAlignedSize)) {
            break;  // there is a big enough gap before this region
        }

        nCandidate = alignUp(nRegionEnd, nAlignment);
    }

    if (nCandidate <= m_nMaxAddress
        && nAlignedSize <= m_nMaxAddress - nCandidate) {
        return nCandidate;
    }

    return 0;
}

bool XEmuMemoryManager::isCommitted(XADDR nAddress, quint64 nSize) const
{
    if (nSize == 0) {
        return true;
    }
    if (nAddress
            > (std::numeric_limits<quint64>::max)() - nSize) {
        return false;
    }
    const XADDR nEnd = nAddress + nSize;
    XADDR nCursor = nAddress;

    while (nCursor < nEnd) {
        int nIndex = _findContainingIndex(nCursor);

        if (nIndex < 0) {
            return false;
        }

        const REGION &region = m_listRegions.at(nIndex);

        if (region.state != STATE_COMMIT) {
            return false;
        }

        if (region.nAddress
                > (std::numeric_limits<quint64>::max)()
                      - region.nSize) {
            return false;
        }
        const XADDR nNext =
            qMin(nEnd, region.nAddress + region.nSize);
        if (nNext <= nCursor) {
            return false;
        }
        nCursor = nNext;
    }

    return true;
}

bool XEmuMemoryManager::isRangeFree(XADDR nAddress, quint64 nSize) const
{
    XADDR nStart = 0;
    XADDR nEnd = 0;
    if (!_normalizePageRange(nAddress, nSize, &nStart, &nEnd)) {
        return false;
    }

    for (int i = 0; i < m_listRegions.size(); i++) {
        const REGION &region = m_listRegions.at(i);
        XADDR nRegionEnd = region.nAddress + region.nSize;

        if ((nStart < nRegionEnd) && (region.nAddress < nEnd)) {
            return false;
        }
    }

    return true;
}

bool XEmuMemoryManager::read(XADDR nAddress, void *pBuffer, quint64 nSize) const
{
    if (nSize == 0) {
        return true;
    }
    if (!pBuffer || nSize > N_MAX_TOTAL_COMMIT
        || nAddress
               > (std::numeric_limits<quint64>::max)() - nSize
        || !isCommitted(nAddress, nSize)) {
        return false;
    }
    quint64 nDone = 0;

    while (nDone < nSize) {
        XADDR nCurrent = nAddress + nDone;
        int nIndex = _findContainingIndex(nCurrent);

        if (nIndex < 0) {
            return false;
        }

        const REGION &region = m_listRegions.at(nIndex);

        if (region.state != STATE_COMMIT) {
            return false;
        }

        quint64 nOffset = nCurrent - region.nAddress;
        quint64 nAvailable = region.nSize - nOffset;
        quint64 nChunk = qMin(nAvailable, nSize - nDone);

        if (!_validateBacking(region)) {
            return false;
        }
        quint64 nSliceBase = 0;
        quint64 nRegionDone = 0;
        for (int i = 0;
             i < region.listData.size()
             && nRegionDone < nChunk;
             i++) {
            const BACKING_SLICE &slice =
                region.listData.at(i);
            if (nOffset >= nSliceBase + slice.nSize) {
                nSliceBase += slice.nSize;
                continue;
            }
            const quint64 nSliceOffset =
                nOffset > nSliceBase
                    ? nOffset - nSliceBase
                    : 0;
            const quint64 nSliceChunk =
                qMin(slice.nSize - nSliceOffset,
                     nChunk - nRegionDone);
            memcpy(
                static_cast<char *>(pBuffer)
                    + static_cast<size_t>(
                        nDone + nRegionDone),
                slice.pData->constData()
                    + static_cast<int>(
                        slice.nDataOffset
                        + nSliceOffset),
                static_cast<size_t>(nSliceChunk));
            nRegionDone += nSliceChunk;
            nOffset += nSliceChunk;
            nSliceBase += slice.nSize;
        }
        if (nRegionDone != nChunk) {
            return false;
        }
        nDone += nChunk;
    }

    return true;
}

bool XEmuMemoryManager::write(XADDR nAddress, const void *pBuffer, quint64 nSize)
{
    if (nSize == 0) {
        return true;
    }
    if (!pBuffer || nSize > N_MAX_TOTAL_COMMIT
        || nAddress
               > (std::numeric_limits<quint64>::max)() - nSize
        || !isCommitted(nAddress, nSize)) {
        return false;
    }
    quint64 nDone = 0;

    while (nDone < nSize) {
        XADDR nCurrent = nAddress + nDone;
        int nIndex = _findContainingIndex(nCurrent);

        if (nIndex < 0) {
            return false;
        }

        REGION &region = m_listRegions[nIndex];

        if (region.state != STATE_COMMIT) {
            return false;
        }

        quint64 nOffset = nCurrent - region.nAddress;
        quint64 nAvailable = region.nSize - nOffset;
        quint64 nChunk = qMin(nAvailable, nSize - nDone);

        if (!_validateBacking(region)) {
            return false;
        }
        quint64 nSliceBase = 0;
        quint64 nRegionDone = 0;
        for (int i = 0;
             i < region.listData.size()
             && nRegionDone < nChunk;
             i++) {
            const BACKING_SLICE &slice =
                region.listData.at(i);
            if (nOffset >= nSliceBase + slice.nSize) {
                nSliceBase += slice.nSize;
                continue;
            }
            const quint64 nSliceOffset =
                nOffset > nSliceBase
                    ? nOffset - nSliceBase
                    : 0;
            const quint64 nSliceChunk =
                qMin(slice.nSize - nSliceOffset,
                     nChunk - nRegionDone);
            memcpy(
                slice.pData->data()
                    + static_cast<int>(
                        slice.nDataOffset
                        + nSliceOffset),
                static_cast<const char *>(pBuffer)
                    + static_cast<size_t>(
                        nDone + nRegionDone),
                static_cast<size_t>(nSliceChunk));
            nRegionDone += nSliceChunk;
            nOffset += nSliceChunk;
            nSliceBase += slice.nSize;
        }
        if (nRegionDone != nChunk) {
            return false;
        }
        nDone += nChunk;
    }

    return true;
}

QByteArray XEmuMemoryManager::read(XADDR nAddress, quint64 nSize, bool *pbOk) const
{
    if (nSize > N_MAX_SINGLE_COMMIT
        || nSize > static_cast<quint64>(
                       (std::numeric_limits<int>::max)())) {
        if (pbOk) {
            *pbOk = false;
        }
        return QByteArray();
    }
    QByteArray baResult((int)nSize, 0);
    bool bOk = read(nAddress, baResult.data(), nSize);

    if (pbOk) {
        *pbOk = bOk;
    }

    if (!bOk) {
        baResult.clear();
    }

    return baResult;
}

bool XEmuMemoryManager::write(XADDR nAddress, const QByteArray &baData)
{
    return write(nAddress, baData.constData(), (quint64)baData.size());
}

void XEmuMemoryManager::setReadCallback(const MEM_CALLBACK &callback)
{
    m_readCallback = callback;
}

void XEmuMemoryManager::setWriteCallback(const MEM_CALLBACK &callback)
{
    m_writeCallback = callback;
}

void XEmuMemoryManager::setCodeCallback(const CODE_CALLBACK &callback)
{
    m_codeCallback = callback;
}

void XEmuMemoryManager::setInvalidCallback(const INVALID_CALLBACK &callback)
{
    m_invalidCallback = callback;
}

XEmuMemoryManager::CALLBACK_ID XEmuMemoryManager::addReadCallback(
    const MEM_CALLBACK &callback)
{
    static const int N_MAX_SUBSCRIBERS = 1024;
    if (!callback || m_listReadSubscribers.size() >= N_MAX_SUBSCRIBERS)
        return 0;
    CALLBACK_ID nId = m_nNextCallbackId++;
    if (nId == 0) nId = m_nNextCallbackId++;
    m_listReadSubscribers.append(MEM_SUBSCRIBER(nId, callback));
    return nId;
}

XEmuMemoryManager::CALLBACK_ID XEmuMemoryManager::addWriteCallback(
    const MEM_CALLBACK &callback)
{
    static const int N_MAX_SUBSCRIBERS = 1024;
    if (!callback || m_listWriteSubscribers.size() >= N_MAX_SUBSCRIBERS)
        return 0;
    CALLBACK_ID nId = m_nNextCallbackId++;
    if (nId == 0) nId = m_nNextCallbackId++;
    m_listWriteSubscribers.append(MEM_SUBSCRIBER(nId, callback));
    return nId;
}

bool XEmuMemoryManager::removeReadCallback(CALLBACK_ID nId)
{
    if (nId == 0) return false;
    for (int i = 0; i < m_listReadSubscribers.size(); ++i) {
        if (m_listReadSubscribers.at(i).nId == nId) {
            m_listReadSubscribers.removeAt(i);
            return true;
        }
    }
    return false;
}

bool XEmuMemoryManager::removeWriteCallback(CALLBACK_ID nId)
{
    if (nId == 0) return false;
    for (int i = 0; i < m_listWriteSubscribers.size(); ++i) {
        if (m_listWriteSubscribers.at(i).nId == nId) {
            m_listWriteSubscribers.removeAt(i);
            return true;
        }
    }
    return false;
}

void XEmuMemoryManager::_fireReadCallbacks(
    XADDR nAddress, quint32 nSize, quint64 nValue) const
{
    // Snapshotting permits a callback to unsubscribe itself without
    // invalidating this dispatch or changing the subscriber set of the current
    // event. Own a copy of the legacy function as well: it may clear or replace
    // its registration while executing. Take both snapshots before invoking it
    // because a legacy observer may also add/remove subscribers.
    const MEM_CALLBACK legacy = m_readCallback;
    const QList<MEM_SUBSCRIBER> subscribers = m_listReadSubscribers;
    if (legacy) legacy(nAddress, nSize, nValue);
    for (const MEM_SUBSCRIBER &subscriber : subscribers) {
        if (subscriber.callback)
            subscriber.callback(nAddress, nSize, nValue);
    }
}

void XEmuMemoryManager::_fireWriteCallbacks(
    XADDR nAddress, quint32 nSize, quint64 nValue) const
{
    const MEM_CALLBACK legacy = m_writeCallback;
    const QList<MEM_SUBSCRIBER> subscribers = m_listWriteSubscribers;
    if (legacy) legacy(nAddress, nSize, nValue);
    for (const MEM_SUBSCRIBER &subscriber : subscribers) {
        if (subscriber.callback)
            subscriber.callback(nAddress, nSize, nValue);
    }
}

void XEmuMemoryManager::clearCallbacks()
{
    m_readCallback = nullptr;
    m_writeCallback = nullptr;
    m_codeCallback = nullptr;
    m_invalidCallback = nullptr;
    m_listReadSubscribers.clear();
    m_listWriteSubscribers.clear();
}

void XEmuMemoryManager::fireCodeHook(XADDR nAddress, quint32 nLength) const
{
    if (m_codeCallback) {
        m_codeCallback(nAddress, nLength);
    }
}

quint8 XEmuMemoryManager::readByte(XADDR nAddress, bool *pbOk) const
{
    quint8 nValue = 0;
    bool bOk = read(nAddress, &nValue, 1);
    if (pbOk) {
        *pbOk = bOk;
    }
    if (bOk) {
        _fireReadCallbacks(nAddress, 1, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 1, false);
    }
    return nValue;
}

quint16 XEmuMemoryManager::readWord(XADDR nAddress, bool *pbOk) const
{
    quint16 nValue = 0;
    bool bOk = read(nAddress, &nValue, 2);
    if (pbOk) {
        *pbOk = bOk;
    }
    nValue = qFromLittleEndian(nValue);
    if (bOk) {
        _fireReadCallbacks(nAddress, 2, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 2, false);
    }
    return nValue;
}

quint32 XEmuMemoryManager::readDword(XADDR nAddress, bool *pbOk) const
{
    quint32 nValue = 0;
    bool bOk = read(nAddress, &nValue, 4);
    if (pbOk) {
        *pbOk = bOk;
    }
    nValue = qFromLittleEndian(nValue);
    if (bOk) {
        _fireReadCallbacks(nAddress, 4, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 4, false);
    }
    return nValue;
}

quint64 XEmuMemoryManager::readQword(XADDR nAddress, bool *pbOk) const
{
    quint64 nValue = 0;
    bool bOk = read(nAddress, &nValue, 8);
    if (pbOk) {
        *pbOk = bOk;
    }
    nValue = qFromLittleEndian(nValue);
    if (bOk) {
        _fireReadCallbacks(nAddress, 8, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 8, false);
    }
    return nValue;
}

quint8 XEmuMemoryManager::fetchByte(XADDR nAddress, bool *pbOk) const
{
    quint8 nValue = 0;
    bool bOk = read(nAddress, &nValue, 1);
    if (pbOk) {
        *pbOk = bOk;
    }
    if (!bOk && m_invalidCallback) {
        m_invalidCallback(nAddress, 1, false);
    }
    return nValue;
}

quint16 XEmuMemoryManager::fetchWord(XADDR nAddress, bool *pbOk) const
{
    quint16 nValue = 0;
    bool bOk = read(nAddress, &nValue, 2);
    if (pbOk) {
        *pbOk = bOk;
    }
    if (!bOk && m_invalidCallback) {
        m_invalidCallback(nAddress, 2, false);
    }
    return qFromLittleEndian(nValue);
}

quint32 XEmuMemoryManager::fetchDword(XADDR nAddress, bool *pbOk) const
{
    quint32 nValue = 0;
    bool bOk = read(nAddress, &nValue, 4);
    if (pbOk) {
        *pbOk = bOk;
    }
    if (!bOk && m_invalidCallback) {
        m_invalidCallback(nAddress, 4, false);
    }
    return qFromLittleEndian(nValue);
}

quint64 XEmuMemoryManager::fetchQword(XADDR nAddress, bool *pbOk) const
{
    quint64 nValue = 0;
    bool bOk = read(nAddress, &nValue, 8);
    if (pbOk) {
        *pbOk = bOk;
    }
    if (!bOk && m_invalidCallback) {
        m_invalidCallback(nAddress, 8, false);
    }
    return qFromLittleEndian(nValue);
}

bool XEmuMemoryManager::writeByte(XADDR nAddress, quint8 nValue)
{
    bool bOk = write(nAddress, &nValue, 1);
    if (bOk) {
        _fireWriteCallbacks(nAddress, 1, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 1, true);
    }
    return bOk;
}

bool XEmuMemoryManager::writeWord(XADDR nAddress, quint16 nValue)
{
    quint16 nLE = qToLittleEndian(nValue);
    bool bOk = write(nAddress, &nLE, 2);
    if (bOk) {
        _fireWriteCallbacks(nAddress, 2, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 2, true);
    }
    return bOk;
}

bool XEmuMemoryManager::writeDword(XADDR nAddress, quint32 nValue)
{
    quint32 nLE = qToLittleEndian(nValue);
    bool bOk = write(nAddress, &nLE, 4);
    if (bOk) {
        _fireWriteCallbacks(nAddress, 4, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 4, true);
    }
    return bOk;
}

bool XEmuMemoryManager::writeQword(XADDR nAddress, quint64 nValue)
{
    quint64 nLE = qToLittleEndian(nValue);
    bool bOk = write(nAddress, &nLE, 8);
    if (bOk) {
        _fireWriteCallbacks(nAddress, 8, nValue);
    } else if (m_invalidCallback) {
        m_invalidCallback(nAddress, 8, true);
    }
    return bOk;
}

QList<XEmuMemoryManager::REGION> XEmuMemoryManager::getRegions() const
{
    QList<REGION> listResult = m_listRegions;
    for (int i = 0; i < listResult.size(); i++) {
        listResult[i].listData.clear();
    }
    return listResult;
}

bool XEmuMemoryManager::findRegion(XADDR nAddress, REGION *pResult) const
{
    int nIndex = _findContainingIndex(nAddress);

    if (nIndex < 0) {
        return false;
    }

    if (pResult) {
        *pResult = m_listRegions.at(nIndex);
        pResult->listData.clear();
    }

    return true;
}

XADDR XEmuMemoryManager::getMinAddress() const
{
    return m_nMinAddress;
}

XADDR XEmuMemoryManager::getMaxAddress() const
{
    return m_nMaxAddress;
}
