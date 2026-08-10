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
#ifndef XEMUMEMORYMANAGER_H
#define XEMUMEMORYMANAGER_H

#include <functional>

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QSharedPointer>
#include <QString>

#include "xbinary.h"

// A virtual address space that models the memory of a running Windows process.
//
// Memory is described by a sorted, non-overlapping list of regions. A region is
// either RESERVED (address range claimed, no backing store) or COMMIT (backed by
// real bytes and accessible). Anything not covered by a region is FREE. The
// primitives (reserve / commit / protect / free) mirror VirtualAlloc/VirtualFree
// and keep the same allocation-granularity and page-rounding behaviour.
class XEmuMemoryManager : public QObject {
    Q_OBJECT

public:
    static const quint64 N_PAGE_SIZE = 0x1000;
    static const quint64 N_ALLOCATION_GRANULARITY = 0x10000;
    static const quint64 N_MAX_SINGLE_COMMIT = 128ULL * 1024ULL * 1024ULL;
    static const quint64 N_MAX_TOTAL_COMMIT = 512ULL * 1024ULL * 1024ULL;
    static const int N_MAX_REGIONS = 65536;

    enum STATE {
        STATE_FREE = 0,
        STATE_RESERVED,
        STATE_COMMIT
    };

    struct MEMORY_FLAGS {
        bool bRead;
        bool bWrite;
        bool bExec;
        bool bGuard;

        MEMORY_FLAGS() : bRead(false), bWrite(false), bExec(false), bGuard(false)
        {
        }
        MEMORY_FLAGS(bool _bRead, bool _bWrite, bool _bExec, bool _bGuard = false) : bRead(_bRead), bWrite(_bWrite), bExec(_bExec), bGuard(_bGuard)
        {
        }
    };

    struct BACKING_SLICE {
        QSharedPointer<QByteArray> pData;
        quint64 nDataOffset;
        quint64 nSize;

        BACKING_SLICE() : nDataOffset(0), nSize(0)
        {
        }
    };

    struct REGION {
        XADDR nAddress;
        quint64 nSize;
        XADDR nAllocationBase;
        STATE state;
        MEMORY_FLAGS flags;
        QString sName;
        // Split regions share one backing object and select their own byte
        // range. This keeps protection changes metadata-only: they cannot
        // duplicate hundreds of MiB of committed memory.
        QList<BACKING_SLICE> listData;

        REGION()
            : nAddress(0),
              nSize(0),
              nAllocationBase(0),
              state(STATE_FREE)
        {
        }
    };

    // Hook callbacks (Unicorn-style). A data read/write callback receives the
    // accessed address, size and value; the code callback fires once per executed
    // instruction with its address and length; the invalid callback fires when an
    // access misses committed memory (bWrite tells read vs. write).
    typedef std::function<void(XADDR nAddress, quint32 nSize, quint64 nValue)> MEM_CALLBACK;
    typedef std::function<void(XADDR nAddress, quint32 nSize)> CODE_CALLBACK;
    typedef std::function<void(XADDR nAddress, quint32 nSize, bool bWrite)> INVALID_CALLBACK;
    typedef quint64 CALLBACK_ID;

    explicit XEmuMemoryManager(QObject *pParent = nullptr);

    void setBits(quint8 nBits);  // 32 or 64
    quint8 getBits() const;

    void setReadCallback(const MEM_CALLBACK &callback);
    void setWriteCallback(const MEM_CALLBACK &callback);
    void setCodeCallback(const CODE_CALLBACK &callback);
    void setInvalidCallback(const INVALID_CALLBACK &callback);
    // Additional read/write subscribers coexist with the legacy single-owner
    // setters above. Subscribers are invoked in registration order after the
    // legacy callback. A value of zero is never a valid subscription id.
    CALLBACK_ID addReadCallback(const MEM_CALLBACK &callback);
    CALLBACK_ID addWriteCallback(const MEM_CALLBACK &callback);
    bool removeReadCallback(CALLBACK_ID nId);
    bool removeWriteCallback(CALLBACK_ID nId);
    void clearCallbacks();

    void clear();

    // VirtualAlloc-like primitives.
    XADDR reserve(XADDR nAddress, quint64 nSize, const QString &sName = QString());
    bool commit(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags);
    XADDR allocate(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags, const QString &sName = QString());
    // Reserve + commit at an EXACT address, including linear 0 (allocate() treats 0 as "any" and
    // returns 0 for failure, so it cannot map the very bottom -- needed for real-mode segment 0 /
    // the IVT). Returns true on success.
    bool mapFixed(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags, const QString &sName = QString());
    bool protect(XADDR nAddress, quint64 nSize, const MEMORY_FLAGS &flags);
    bool release(XADDR nAddress);  // frees the whole allocation that contains nAddress
    XADDR findFree(quint64 nSize, XADDR nStart = 0, quint64 nAlignment = N_ALLOCATION_GRANULARITY) const;

    bool isCommitted(XADDR nAddress, quint64 nSize = 1) const;
    bool isRangeFree(XADDR nAddress, quint64 nSize) const;

    // Raw access. Every touched byte must belong to a committed region.
    bool read(XADDR nAddress, void *pBuffer, quint64 nSize) const;
    bool write(XADDR nAddress, const void *pBuffer, quint64 nSize);
    QByteArray read(XADDR nAddress, quint64 nSize, bool *pbOk = nullptr) const;
    bool write(XADDR nAddress, const QByteArray &baData);

    // Little-endian typed data accessors. These fire the read/write hooks.
    quint8 readByte(XADDR nAddress, bool *pbOk = nullptr) const;
    quint16 readWord(XADDR nAddress, bool *pbOk = nullptr) const;
    quint32 readDword(XADDR nAddress, bool *pbOk = nullptr) const;
    quint64 readQword(XADDR nAddress, bool *pbOk = nullptr) const;
    bool writeByte(XADDR nAddress, quint8 nValue);
    bool writeWord(XADDR nAddress, quint16 nValue);
    bool writeDword(XADDR nAddress, quint32 nValue);
    bool writeQword(XADDR nAddress, quint64 nValue);

    // Instruction-byte fetch accessors. Used by the CPU cores to read opcodes; they
    // do NOT fire the data read hook (the code hook is fired once per instruction
    // via fireCodeHook()).
    quint8 fetchByte(XADDR nAddress, bool *pbOk = nullptr) const;
    quint16 fetchWord(XADDR nAddress, bool *pbOk = nullptr) const;
    quint32 fetchDword(XADDR nAddress, bool *pbOk = nullptr) const;
    quint64 fetchQword(XADDR nAddress, bool *pbOk = nullptr) const;
    void fireCodeHook(XADDR nAddress, quint32 nLength) const;

    // Metadata snapshots deliberately omit backing-store pointers so callers
    // cannot retain committed host memory after release/clear.
    QList<REGION> getRegions() const;
    bool findRegion(XADDR nAddress, REGION *pResult) const;

    XADDR getMinAddress() const;
    XADDR getMaxAddress() const;

    static quint64 alignUp(quint64 nValue, quint64 nAlignment);
    static quint64 alignDown(quint64 nValue, quint64 nAlignment);

signals:
    void errorMessage(const QString &sErrorMessage);

private:
    XEmuMemoryManager(const XEmuMemoryManager &) = delete;
    XEmuMemoryManager &operator=(const XEmuMemoryManager &) = delete;

    int _findContainingIndex(XADDR nAddress) const;
    int _split(int nIndex, XADDR nStart, XADDR nEnd);  // returns index of the [nStart,nEnd) middle piece
    int _splitGrowth(int nIndex, XADDR nStart, XADDR nEnd) const;
    bool _normalizePageRange(XADDR nAddress, quint64 nSize,
                             XADDR *pStart, XADDR *pEnd) const;
    static bool _flagsEqual(const MEMORY_FLAGS &left,
                            const MEMORY_FLAGS &right);
    static bool _sliceBacking(const REGION &region,
                              quint64 nOffset, quint64 nSize,
                              QList<BACKING_SLICE> *pResult);
    static bool _validateBacking(const REGION &region);
    static void _appendBackingSlice(
        QList<BACKING_SLICE> *pList,
        const BACKING_SLICE &slice);
    void _coalesce();
    void _sort();
    static bool _regionAddressLess(const REGION &r1, const REGION &r2);  // std::sort comparator
    void _fireReadCallbacks(XADDR nAddress, quint32 nSize,
                            quint64 nValue) const;
    void _fireWriteCallbacks(XADDR nAddress, quint32 nSize,
                             quint64 nValue) const;

    struct MEM_SUBSCRIBER {
        CALLBACK_ID nId;
        MEM_CALLBACK callback;

        MEM_SUBSCRIBER() : nId(0) {}
        MEM_SUBSCRIBER(CALLBACK_ID _nId, const MEM_CALLBACK &_callback)
            : nId(_nId), callback(_callback) {}
    };

    QList<REGION> m_listRegions;
    quint8 m_nBits;
    XADDR m_nMinAddress;
    XADDR m_nMaxAddress;
    quint64 m_nCommittedBytes;

    MEM_CALLBACK m_readCallback;
    MEM_CALLBACK m_writeCallback;
    CODE_CALLBACK m_codeCallback;
    INVALID_CALLBACK m_invalidCallback;
    QList<MEM_SUBSCRIBER> m_listReadSubscribers;
    QList<MEM_SUBSCRIBER> m_listWriteSubscribers;
    CALLBACK_ID m_nNextCallbackId;
};

#endif  // XEMUMEMORYMANAGER_H
