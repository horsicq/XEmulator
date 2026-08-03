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
#include "xemupe.h"

#include <QFileInfo>
#include <limits>

namespace {
const quint32 N_SCN_MEM_EXECUTE = 0x20000000;
const quint32 N_SCN_MEM_READ = 0x40000000;
const quint32 N_SCN_MEM_WRITE = 0x80000000;
const quint32 N_FILE_DLL = 0x2000;
const quint32 N_REL_BASED_ABSOLUTE = 0;
const quint32 N_REL_BASED_HIGH = 1;
const quint32 N_REL_BASED_LOW = 2;
const quint32 N_REL_BASED_HIGHLOW = 3;
const quint32 N_REL_BASED_HIGHADJ = 4;
const quint32 N_REL_BASED_ARM_MOV32A = 5;
const quint32 N_REL_BASED_ARM_MOV32T = 7;
const quint32 N_REL_BASED_DIR64 = 10;
const quint16 N_FILE_MACHINE_ARMNT = 0x01C4;
}  // namespace

XEmuPE::XEmuPE(QObject *pParent) : XEmuFileFormat(pParent), m_pFile(nullptr), m_pPE(nullptr), m_bValid(false), m_bExportCacheBuilt(false)
{
}

XEmuPE::~XEmuPE()
{
    _close();
}

void XEmuPE::_close()
{
    if (m_pPE) {
        delete m_pPE;
        m_pPE = nullptr;
    }

    if (m_pFile) {
        m_pFile->close();
        delete m_pFile;
        m_pFile = nullptr;
    }

    m_bValid = false;
    m_bExportCacheBuilt = false;
    m_mapExportByName.clear();
    m_mapExportByOrdinal.clear();
}

bool XEmuPE::setFileName(const QString &sFileName)
{
    _close();

    m_sFileName = sFileName;
    m_sModuleName = QFileInfo(sFileName).fileName().toLower();

    m_pFile = new QFile(sFileName);

    if (!m_pFile->open(QIODevice::ReadOnly)) {
        emit errorMessage(tr("Cannot open file: %1").arg(sFileName));
        _close();
        return false;
    }

    m_pPE = new XPE(m_pFile);

    if (!m_pPE->isValid()) {
        emit errorMessage(tr("Not a valid PE file: %1").arg(sFileName));
        _close();
        return false;
    }

    m_bValid = true;

    return true;
}

bool XEmuPE::isValid() const
{
    return m_bValid;
}

bool XEmuPE::is64Bit() const
{
    if (!m_bValid) {
        return false;
    }

    return m_pPE->is64();
}

XEmuArchType XEmuPE::getArchType() const
{
    if (!m_bValid) {
        return XARCH_UNKNOWN;
    }

    return xemuArchTypeFromDisasmMode(m_pPE->getDisasmMode());
}

XBinary::OSNAME XEmuPE::getOSName() const
{
    return XBinary::OSNAME_WINDOWS;
}

bool XEmuPE::isDll() const
{
    if (!m_bValid) {
        return false;
    }

    return (m_pPE->getFileHeader_Characteristics() & N_FILE_DLL) != 0;
}

XADDR XEmuPE::getPreferredImageBase() const
{
    if (!m_bValid) {
        return 0;
    }

    return m_pPE->getOptionalHeader_ImageBase();
}

quint64 XEmuPE::getImageSize() const
{
    if (!m_bValid) {
        return 0;
    }

    return m_pPE->getOptionalHeader_SizeOfImage();
}

qint64 XEmuPE::getEntryPointRVA() const
{
    if (!m_bValid) {
        return 0;
    }

    return m_pPE->getOptionalHeader_AddressOfEntryPoint();
}

bool XEmuPE::map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult)
{
    if (!m_bValid || !pMemoryManager) {
        return false;
    }

    const quint64 nMaximumMappedImage = 64ULL * 1024ULL * 1024ULL;
    const quint64 nTailSlackSize = 0x10000;
    quint64 nImageSize = getImageSize();
    XADDR nPreferredBase = getPreferredImageBase();
    const quint32 nNumberOfSections =
        m_pPE->getFileHeader_NumberOfSections();
    const quint32 nSizeOfHeaders =
        m_pPE->getOptionalHeader_SizeOfHeaders();
    const qint64 nFileSize = m_pPE->getSize();
    const qint64 nSectionsTableOffset =
        m_pPE->getSectionsTableOffset();
    const qint64 nSectionTableBytes =
        static_cast<qint64>(nNumberOfSections)
        * static_cast<qint64>(
            sizeof(XPE_DEF::IMAGE_SECTION_HEADER));
    const qint64 nEntryRVA = getEntryPointRVA();
    if (nImageSize == 0 || nImageSize > nMaximumMappedImage
        || nNumberOfSections == 0 || nNumberOfSections > 96
        || nSizeOfHeaders == 0 || nSizeOfHeaders > nImageSize
        || nFileSize < 0
        || nSizeOfHeaders > static_cast<quint64>(nFileSize)
        || nSectionsTableOffset < 0
        || nSectionsTableOffset > nFileSize
        || nSectionTableBytes > nFileSize - nSectionsTableOffset
        || nSectionsTableOffset + nSectionTableBytes
               > static_cast<qint64>(nSizeOfHeaders)
        || nEntryRVA < 0
        || nMapBase == 0
        || nMapBase
               != XEmuMemoryManager::alignDown(
                   nMapBase, XEmuMemoryManager::N_PAGE_SIZE)) {
        emit errorMessage(tr("PE image/header layout exceeds emulator safety limits"));
        return false;
    }

    quint32 nFileAlignment =
        m_pPE->getOptionalHeader_FileAlignment();
    quint32 nSectionAlignment =
        m_pPE->getOptionalHeader_SectionAlignment();
    const bool bFileAlignmentPow2 =
        nFileAlignment != 0
        && (nFileAlignment & (nFileAlignment - 1)) == 0;
    if (!bFileAlignmentPow2 || nFileAlignment > 0x10000
        || nSectionAlignment == 0
        || (nSectionAlignment & (nSectionAlignment - 1)) != 0
        || nSectionAlignment > nMaximumMappedImage
        || (nSectionAlignment < 0x1000
                ? nFileAlignment != nSectionAlignment
                : nFileAlignment < 0x200)) {
        emit errorMessage(tr("Invalid PE file/section alignment"));
        return false;
    }

    QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections =
        m_pPE->getSectionHeaders();
    if (listSections.size() != static_cast<int>(nNumberOfSections)) {
        emit errorMessage(tr("PE section table is truncated"));
        return false;
    }

    // Some malformed/packed PE headers report SizeOfImage smaller than the highest
    // mapped section end (ASDPack family in particular). The Windows loader maps
    // based on section layout, so clamp image size upward to the minimum safe extent.
    quint64 nMappedImageSize = nImageSize;
    const quint64 nSectionAlignMinus1 = nSectionAlignment - 1;
    for (int i = 0; i < listSections.count(); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &sectionHeader = listSections.at(i);

        quint64 nVirtualSize = sectionHeader.Misc.VirtualSize
            ? sectionHeader.Misc.VirtualSize
            : sectionHeader.SizeOfRawData;

        if (nVirtualSize == 0) {
            continue;
        }

        if ((sectionHeader.VirtualAddress % nSectionAlignment) != 0) {
            emit errorMessage(tr("PE section virtual address is misaligned"));
            return false;
        }

        if (nVirtualSize > (std::numeric_limits<quint64>::max)()
                - nSectionAlignMinus1) {
            emit errorMessage(tr("PE section size overflow"));
            return false;
        }

        quint64 nCommitSize =
            (nVirtualSize + nSectionAlignMinus1) & ~nSectionAlignMinus1;
        if (nCommitSize == 0
            || sectionHeader.VirtualAddress > nMaximumMappedImage
            || nCommitSize > nMaximumMappedImage
                - sectionHeader.VirtualAddress) {
            emit errorMessage(tr("PE section exceeds mapped-image safety bounds"));
            return false;
        }

        nMappedImageSize =
            qMax<quint64>(nMappedImageSize,
                          sectionHeader.VirtualAddress + nCommitSize);
    }

    if (nMappedImageSize > nMaximumMappedImage
        || static_cast<quint64>(nEntryRVA) >= nMappedImageSize
        || nSizeOfHeaders > nMappedImageSize) {
        emit errorMessage(tr("PE image/header layout exceeds emulator safety limits"));
        return false;
    }

    nImageSize = nMappedImageSize;

    const quint64 nSlackOffset =
        XEmuMemoryManager::alignUp(
            nImageSize, XEmuMemoryManager::N_PAGE_SIZE);
    if (nSlackOffset == 0
        || nSlackOffset
               > (std::numeric_limits<quint64>::max)()
                     - nTailSlackSize) {
        emit errorMessage(tr("PE image reservation size overflow"));
        return false;
    }
    const quint64 nReservationSize =
        nSlackOffset + nTailSlackSize;
    const XADDR nReservedBase =
        pMemoryManager->reserve(nMapBase, nReservationSize,
                                m_sModuleName);
    if (nReservedBase != nMapBase) {
        if (nReservedBase != 0) {
            pMemoryManager->release(nReservedBase);
        }
        emit errorMessage(tr("Cannot reserve %1 bytes at %2 for %3").arg(nReservationSize).arg(nMapBase, 0, 16).arg(m_sModuleName));
        return false;
    }

    // Headers.
    if (nSizeOfHeaders > 0) {
        // Read + execute: a header-EP packer (QuickPack NT, ...) runs code straight
        // from the PE header page, so it must be executable.
        if (!pMemoryManager->commit(
                nMapBase, nSizeOfHeaders,
                XEmuMemoryManager::MEMORY_FLAGS(true, false, true))) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("Cannot commit PE headers"));
            return false;
        }
        const QByteArray headers =
            m_pPE->read_array(0, nSizeOfHeaders);
        if (headers.size() != static_cast<int>(nSizeOfHeaders)
            || !pMemoryManager->write(nMapBase, headers)) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("Cannot copy PE headers"));
            return false;
        }
    }

    // Sections.
    // The Windows loader ignores the sub-FileAlignment bits of PointerToRawData:
    // it maps each section starting from (PointerToRawData & ~(FileAlignment-1)).
    // Packers (NSpack 2.x, Winupack 0.36+) deliberately store an unaligned raw
    // pointer (e.g. 0x8f, 0x10) so a naive loader copies the wrong bytes to the
    // entry point; mask it down to match real loader behaviour.
    quint32 nAlignMask = nFileAlignment - 1;

    quint64 nTotalCommitted = nSizeOfHeaders;
    for (int i = 0; i < listSections.count(); i++) {
        const XPE_DEF::IMAGE_SECTION_HEADER &sectionHeader = listSections.at(i);

        quint64 nVirtualSize = sectionHeader.Misc.VirtualSize ? sectionHeader.Misc.VirtualSize : sectionHeader.SizeOfRawData;

        if (nVirtualSize == 0) {
            continue;
        }
        if ((sectionHeader.VirtualAddress % nSectionAlignment)
            != 0) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("PE section virtual address is misaligned"));
            return false;
        }

        // The Windows loader commits each section as whole pages (VirtualSize rounded up to
        // SectionAlignment). Some packers set a tiny VirtualSize (e.g. 0xb) but keep the real
        // compressed/entry payload in a larger SizeOfRawData (0x200); committing only the raw
        // VirtualSize would drop those bytes (dePack, eptricker leave the EP itself uninitialised).
        if (nVirtualSize
            > (std::numeric_limits<quint64>::max)()
                  - (nSectionAlignment - 1)) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("PE section size overflow"));
            return false;
        }
        quint64 nCommitSize = (nVirtualSize + (nSectionAlignment - 1)) & ~(quint64)(nSectionAlignment - 1);
        if (nCommitSize == 0
            || sectionHeader.VirtualAddress > nImageSize
            || nCommitSize > nImageSize - sectionHeader.VirtualAddress
            || nTotalCommitted > nMaximumMappedImage - nCommitSize) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("PE section exceeds mapped-image safety bounds"));
            return false;
        }
        nTotalCommitted += nCommitSize;

        XADDR nSectionAddress = nMapBase + sectionHeader.VirtualAddress;

        XEmuMemoryManager::MEMORY_FLAGS flags((sectionHeader.Characteristics & N_SCN_MEM_READ) != 0, (sectionHeader.Characteristics & N_SCN_MEM_WRITE) != 0,
                                              (sectionHeader.Characteristics & N_SCN_MEM_EXECUTE) != 0);

        if (!pMemoryManager->commit(nSectionAddress, nCommitSize, flags)) {
            emit errorMessage(tr("Cannot commit section at %1").arg(nSectionAddress, 0, 16));
            pMemoryManager->release(nMapBase);
            return false;
        }

        if ((sectionHeader.SizeOfRawData > 0) && (sectionHeader.PointerToRawData > 0)) {
            quint32 nRawPtr = sectionHeader.PointerToRawData & ~nAlignMask;
            quint32 nDelta = sectionHeader.PointerToRawData - nRawPtr;  // bytes folded in ahead of the stored pointer
            quint64 nCopySize = qMin<quint64>((quint64)sectionHeader.SizeOfRawData + nDelta, nCommitSize);
            const QByteArray rawData =
                m_pPE->read_array(nRawPtr, nCopySize);
            if (rawData.size() != static_cast<int>(nCopySize)
                || !pMemoryManager->write(nSectionAddress, rawData)) {
                pMemoryManager->release(nMapBase);
                emit errorMessage(tr("Cannot copy PE section data"));
                return false;
            }
        }
    }

    // Trailing slack region: some stubs' decompressors run slightly past the end of the last
    // section / SizeOfImage. nPack's range decoder reads 1 byte past (msvc/fasm/tcc), but its
    // larger bcb-compiled image WRITES one byte past the image end via a `movsb` copy loop. On a
    // real process the image is followed by other committed allocations, so both succeed; commit a
    // WRITABLE slack region (0x10000, to absorb multi-byte overshoot) so neither faults. This is
    // out-of-image scratch (at/after nMapBase+SizeOfImage) and the unpacker's dirty-page watcher
    // is bounded to [imageBase, imageBase+imageSize), so it cannot affect any OEP heuristic.
    {
        const XADDR nSlackAddress = nMapBase + nSlackOffset;
        if (!pMemoryManager->commit(
                nSlackAddress, nTailSlackSize,
                XEmuMemoryManager::MEMORY_FLAGS(
                    true, true, false))) {
            pMemoryManager->release(nMapBase);
            emit errorMessage(tr("Cannot commit PE image-tail slack"));
            return false;
        }
    }

    // Base relocations.
    if (nMapBase != nPreferredBase
        && !_applyRelocations(pMemoryManager, nMapBase,
                              nPreferredBase, nImageSize)) {
        pMemoryManager->release(nMapBase);
        return false;
    }

    if (pModuleResult) {
        pModuleResult->sName = m_sModuleName;
        pModuleResult->sFileName = m_sFileName;
        pModuleResult->nBaseAddress = nMapBase;
        pModuleResult->nImageSize = nImageSize;
        // RVA 0 is a legitimate entry point: some packers (QuickPack NT, ...) set
        // AddressOfEntryPoint = 0 and execute from the PE header itself. Map it to
        // nMapBase + RVA unconditionally rather than treating 0 as "no entry point".
        pModuleResult->nEntryPointAddress = nMapBase + nEntryRVA;
        pModuleResult->bIs64 = is64Bit();
    }

    emit infoMessage(tr("Mapped %1 at %2 (%3 bytes)").arg(m_sModuleName).arg(nMapBase, 0, 16).arg(nImageSize));

    return true;
}

bool XEmuPE::_applyRelocations(XEmuMemoryManager *pMemoryManager,
                              XADDR nMapBase,
                              XADDR nPreferredBase,
                              quint64 nImageSize)
{
    if (!m_pPE->isRelocsPresent()) {
        emit errorMessage(tr("%1 has no relocation table and cannot be mapped at a non-preferred base").arg(m_sModuleName));
        return false;
    }

    const XPE_DEF::IMAGE_DATA_DIRECTORY relocationDirectory =
        m_pPE->getOptionalHeader_DataDirectory(
            XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const qint64 nRelocationDirectoryOffset =
        m_pPE->getDataDirectoryOffset(
            XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (nRelocationDirectoryOffset < 0
        || relocationDirectory.Size
               < sizeof(XPE_DEF::IMAGE_BASE_RELOCATION)
        || relocationDirectory.Size > 4U * 1024U * 1024U
        || (relocationDirectory.VirtualAddress & 3U)
        || relocationDirectory.VirtualAddress > nImageSize
        || relocationDirectory.Size
               > nImageSize
                     - relocationDirectory.VirtualAddress
        || relocationDirectory.Size
               > static_cast<quint64>(
                   (std::numeric_limits<qint64>::max)()
                   - nRelocationDirectoryOffset)) {
        emit errorMessage(tr("%1 has invalid relocation-directory bounds").arg(m_sModuleName));
        return false;
    }
    XBinary::_MEMORY_MAP relocationMemoryMap =
        m_pPE->getMemoryMap();
    if (relocationMemoryMap.nModuleAddress
            > (std::numeric_limits<quint64>::max)()
                  - relocationDirectory.VirtualAddress) {
        emit errorMessage(tr("%1 has an invalid mapped relocation-directory address").arg(m_sModuleName));
        return false;
    }
    const XADDR nRelocationDirectoryAddress =
        relocationMemoryMap.nModuleAddress
        + relocationDirectory.VirtualAddress;
    if (!XBinary::isPhysicalAddressRange(
            &relocationMemoryMap,
            nRelocationDirectoryAddress,
            static_cast<qint64>(
                relocationDirectory.Size))
        || XBinary::addressToOffset(
               &relocationMemoryMap,
               nRelocationDirectoryAddress)
               != nRelocationDirectoryOffset) {
        emit errorMessage(tr("%1 has a non-contiguous mapped relocation directory").arg(m_sModuleName));
        return false;
    }
    const QList<XPE::RELOCS_HEADER> listHeaders =
        m_pPE->getRelocsHeaders();
    if (listHeaders.isEmpty()) {
        emit errorMessage(tr("%1 has an invalid or empty relocation table").arg(m_sModuleName));
        return false;
    }
    const qint64 nRelocationDirectoryEnd =
        nRelocationDirectoryOffset
        + static_cast<qint64>(relocationDirectory.Size);
    qint64 nExpectedBlockOffset = nRelocationDirectoryOffset;
    for (int i = 0; i < listHeaders.count(); ++i) {
        const XPE::RELOCS_HEADER &header = listHeaders.at(i);
        const quint64 nBlockRVA =
            static_cast<quint64>(
                relocationDirectory.VirtualAddress)
            + static_cast<quint64>(
                nExpectedBlockOffset
                - nRelocationDirectoryOffset);
        if ((nBlockRVA & 3U)
            || header.nOffset != nExpectedBlockOffset
            || header.baseRelocation.SizeOfBlock
                   > static_cast<quint64>(
                       nRelocationDirectoryEnd
                       - nExpectedBlockOffset)) {
            emit errorMessage(tr("%1 has a non-contiguous relocation table").arg(m_sModuleName));
            return false;
        }
        nExpectedBlockOffset +=
            static_cast<qint64>(
                header.baseRelocation.SizeOfBlock);
    }
    while (nExpectedBlockOffset < nRelocationDirectoryEnd) {
        const qint64 nChunkSize =
            qMin<qint64>(4096,
                         nRelocationDirectoryEnd
                             - nExpectedBlockOffset);
        const QByteArray padding =
            m_pPE->read_array(nExpectedBlockOffset,
                              nChunkSize);
        if (padding.size() != static_cast<int>(nChunkSize)) {
            emit errorMessage(tr("%1 has truncated relocation-directory padding").arg(m_sModuleName));
            return false;
        }
        for (int i = 0; i < padding.size(); ++i) {
            if (padding.at(i) != '\0') {
                emit errorMessage(tr("%1 has unparsed relocation-directory data").arg(m_sModuleName));
                return false;
            }
        }
        nExpectedBlockOffset += nChunkSize;
    }

    const bool bIs64 = is64Bit();
    const quint16 nMachine = m_pPE->getFileHeader_Machine();
    const XEmuArchType archType = getArchType();
    const bool bIsArm32 =
        archType == XARCH_ARM
        && (nMachine == XPE_DEF::S_IMAGE_FILE_MACHINE_ARM
            || nMachine == XPE_DEF::S_IMAGE_FILE_MACHINE_THUMB
            || nMachine == N_FILE_MACHINE_ARMNT);
    const quint64 nDelta64 =
        static_cast<quint64>(nMapBase)
        - static_cast<quint64>(nPreferredBase);
    const quint32 nDelta32 =
        static_cast<quint32>(nMapBase)
        - static_cast<quint32>(nPreferredBase);
    qint32 nTotalRecords = 0;
    const auto getTargetAddress =
        [&](quint64 nRVA, quint64 nWidth,
            XADDR *pAddress) -> bool {
        if (nWidth > nImageSize
            || nRVA > nImageSize - nWidth
            || nMapBase
                   > (std::numeric_limits<quint64>::max)()
                         - nRVA) {
            return false;
        }
        if (pAddress) {
            *pAddress = nMapBase + nRVA;
        }
        return true;
    };

    for (int i = 0; i < listHeaders.count(); ++i) {
        const XPE::RELOCS_HEADER &header = listHeaders.at(i);
        const QList<XPE::RELOCS_POSITION> listPositions =
            m_pPE->getRelocsPositions(header.nOffset);
        if (header.nCount < 0
            || listPositions.size() != header.nCount
            || header.nCount > 65536 - nTotalRecords) {
            emit errorMessage(tr("%1 has a truncated or oversized relocation block").arg(m_sModuleName));
            return false;
        }
        nTotalRecords += header.nCount;

        for (int j = 0; j < listPositions.count(); ++j) {
            const XPE::RELOCS_POSITION &position =
                listPositions.at(j);
            if (position.nType == N_REL_BASED_ABSOLUTE) {
                continue;
            }
            const quint64 nRVA =
                static_cast<quint64>(position.nAddress);
            bool bOk = false;

            if (position.nType == N_REL_BASED_DIR64) {
                if (!bIs64) {
                    emit errorMessage(tr("%1 uses a 64-bit relocation in a 32-bit image").arg(m_sModuleName));
                    return false;
                }
                XADDR nAddress = 0;
                if (!getTargetAddress(nRVA, 8, &nAddress)) {
                    emit errorMessage(tr("%1 has an out-of-image relocation target").arg(m_sModuleName));
                    return false;
                }
                const quint64 nValue =
                    pMemoryManager->readQword(nAddress, &bOk);
                if (!bOk
                    || !pMemoryManager->writeQword(
                        nAddress, nValue + nDelta64)) {
                    emit errorMessage(tr("Cannot apply a 64-bit relocation in %1").arg(m_sModuleName));
                    return false;
                }
                continue;
            }

            if (position.nType == N_REL_BASED_HIGH
                || position.nType == N_REL_BASED_LOW
                || position.nType == N_REL_BASED_HIGHLOW
                || position.nType == N_REL_BASED_HIGHADJ) {
                quint64 nWidth = 0;
                switch (position.nType) {
                    case N_REL_BASED_HIGH:
                    case N_REL_BASED_LOW:
                    case N_REL_BASED_HIGHADJ:
                        nWidth = 2;
                        break;
                    case N_REL_BASED_HIGHLOW:
                        nWidth = 4;
                        break;
                    default:
                        emit errorMessage(tr("%1 uses unsupported standard relocation type %2").arg(m_sModuleName).arg(position.nType));
                        return false;
                }
                XADDR nAddress = 0;
                if (!getTargetAddress(nRVA, nWidth, &nAddress)) {
                    emit errorMessage(tr("%1 has an out-of-image relocation target").arg(m_sModuleName));
                    return false;
                }

                if (position.nType == N_REL_BASED_HIGHLOW) {
                    const quint32 nValue =
                        pMemoryManager->readDword(
                            nAddress, &bOk);
                    if (!bOk
                        || !pMemoryManager->writeDword(
                            nAddress,
                            nValue + nDelta32)) {
                        emit errorMessage(tr("Cannot apply a 32-bit relocation in %1").arg(m_sModuleName));
                        return false;
                    }
                    continue;
                }

                const quint16 nValue =
                    pMemoryManager->readWord(nAddress, &bOk);
                if (!bOk) {
                    emit errorMessage(tr("Cannot read a 16-bit relocation target in %1").arg(m_sModuleName));
                    return false;
                }
                quint32 nAdjusted = 0;
                if (position.nType == N_REL_BASED_HIGH) {
                    nAdjusted =
                        (static_cast<quint32>(nValue) << 16)
                        + nDelta32;
                    nAdjusted >>= 16;
                } else if (position.nType == N_REL_BASED_LOW) {
                    nAdjusted =
                        static_cast<quint32>(
                            static_cast<qint32>(
                                static_cast<qint16>(nValue)))
                        + nDelta32;
                } else {
                    if (j + 1 >= listPositions.count()) {
                        emit errorMessage(tr("%1 has a truncated HIGHADJ relocation pair").arg(m_sModuleName));
                        return false;
                    }
                    const qint16 nLow =
                        static_cast<qint16>(
                            listPositions.at(j + 1).nTypeOffset);
                    nAdjusted =
                        (static_cast<quint32>(nValue) << 16)
                        + static_cast<quint32>(
                            static_cast<qint32>(nLow))
                        + nDelta32 + 0x8000U;
                    nAdjusted >>= 16;
                    ++j;  // HIGHADJ consumes the following raw 16-bit slot.
                }
                if (!pMemoryManager->writeWord(
                        nAddress,
                        static_cast<quint16>(nAdjusted))) {
                    emit errorMessage(tr("Cannot apply a 16-bit relocation in %1").arg(m_sModuleName));
                    return false;
                }
                continue;
            }

            if (bIsArm32
                && (position.nType == N_REL_BASED_ARM_MOV32A
                    || position.nType == N_REL_BASED_ARM_MOV32T)) {
                XADDR nAddress = 0;
                if (!getTargetAddress(nRVA, 8, &nAddress)) {
                    emit errorMessage(tr("%1 has an out-of-image ARM relocation target").arg(m_sModuleName));
                    return false;
                }
                quint32 nInstructionLow =
                    pMemoryManager->readDword(nAddress, &bOk);
                if (!bOk) {
                    emit errorMessage(tr("Cannot read the first ARM relocation instruction in %1").arg(m_sModuleName));
                    return false;
                }
                bool bSecondOk = false;
                quint32 nInstructionHigh =
                    pMemoryManager->readDword(
                        nAddress + 4, &bSecondOk);
                if (!bSecondOk) {
                    emit errorMessage(tr("Cannot read the second ARM relocation instruction in %1").arg(m_sModuleName));
                    return false;
                }

                // The relocation record selects the instruction encoding.
                // Machine type only establishes that this is an ARM32 image:
                // type 5 is the A32 MOVW/MOVT form, while type 7 is Thumb-2.
                const bool bThumbEncoding =
                    position.nType
                    == N_REL_BASED_ARM_MOV32T;
                quint16 nImmediateLow = 0;
                quint16 nImmediateHigh = 0;
                if (bThumbEncoding) {
                    if ((nInstructionLow & 0x8000FBF0U)
                            != 0x0000F240U
                        || (nInstructionHigh & 0x8000FBF0U)
                               != 0x0000F2C0U
                        || (nInstructionLow & 0x0F000000U)
                               != (nInstructionHigh
                                   & 0x0F000000U)) {
                        emit errorMessage(tr("%1 has an invalid Thumb MOVW/MOVT relocation pair").arg(m_sModuleName));
                        return false;
                    }
                    nImmediateLow =
                        static_cast<quint16>(
                            ((nInstructionLow << 1) & 0x0800U)
                            | ((nInstructionLow << 12)
                               & 0xF000U)
                            | ((nInstructionLow >> 20)
                               & 0x0700U)
                            | ((nInstructionLow >> 16)
                               & 0x00FFU));
                    nImmediateHigh =
                        static_cast<quint16>(
                            ((nInstructionHigh << 1) & 0x0800U)
                            | ((nInstructionHigh << 12)
                               & 0xF000U)
                            | ((nInstructionHigh >> 20)
                               & 0x0700U)
                            | ((nInstructionHigh >> 16)
                               & 0x00FFU));
                } else {
                    if ((nInstructionLow & 0x0FF00000U)
                            != 0x03000000U
                        || (nInstructionHigh & 0x0FF00000U)
                               != 0x03400000U
                        || (nInstructionLow & 0x0000F000U)
                               != (nInstructionHigh
                                   & 0x0000F000U)) {
                        emit errorMessage(tr("%1 has an invalid ARM MOVW/MOVT relocation pair").arg(m_sModuleName));
                        return false;
                    }
                    nImmediateLow =
                        static_cast<quint16>(
                            ((nInstructionLow >> 4)
                             & 0xF000U)
                            | (nInstructionLow & 0x0FFFU));
                    nImmediateHigh =
                        static_cast<quint16>(
                            ((nInstructionHigh >> 4)
                             & 0xF000U)
                            | (nInstructionHigh & 0x0FFFU));
                }

                const quint32 nImmediate =
                    (static_cast<quint32>(nImmediateHigh)
                     << 16)
                    | nImmediateLow;
                const quint32 nRelocatedImmediate =
                    nImmediate + nDelta32;
                nImmediateLow =
                    static_cast<quint16>(
                        nRelocatedImmediate & 0xFFFFU);
                nImmediateHigh =
                    static_cast<quint16>(
                        nRelocatedImmediate >> 16);

                if (bThumbEncoding) {
                    nInstructionLow =
                        (nInstructionLow & 0x8F00FBF0U)
                        | ((nImmediateLow >> 1) & 0x0400U)
                        | ((nImmediateLow >> 12) & 0x000FU)
                        | ((static_cast<quint32>(
                                nImmediateLow)
                            << 20)
                           & 0x70000000U)
                        | ((static_cast<quint32>(
                                nImmediateLow)
                            << 16)
                           & 0x00FF0000U);
                    nInstructionHigh =
                        (nInstructionHigh & 0x8F00FBF0U)
                        | ((nImmediateHigh >> 1)
                           & 0x0400U)
                        | ((nImmediateHigh >> 12)
                           & 0x000FU)
                        | ((static_cast<quint32>(
                                nImmediateHigh)
                            << 20)
                           & 0x70000000U)
                        | ((static_cast<quint32>(
                                nImmediateHigh)
                            << 16)
                           & 0x00FF0000U);
                } else {
                    nInstructionLow =
                        (nInstructionLow & 0xFFF0F000U)
                        | ((static_cast<quint32>(
                                nImmediateLow)
                            & 0xF000U)
                           << 4)
                        | (nImmediateLow & 0x0FFFU);
                    nInstructionHigh =
                        (nInstructionHigh & 0xFFF0F000U)
                        | ((static_cast<quint32>(
                                nImmediateHigh)
                            & 0xF000U)
                           << 4)
                        | (nImmediateHigh & 0x0FFFU);
                }

                if (!pMemoryManager->writeDword(
                        nAddress, nInstructionLow)
                    || !pMemoryManager->writeDword(
                        nAddress + 4, nInstructionHigh)) {
                    emit errorMessage(tr("Cannot apply an ARM MOVW/MOVT relocation in %1").arg(m_sModuleName));
                    return false;
                }
                continue;
            }

            emit errorMessage(tr("%1 uses unsupported relocation type %2 for its machine architecture").arg(m_sModuleName).arg(position.nType));
            return false;
        }
    }

    return true;
}

QStringList XEmuPE::getImportLibraries() const
{
    QStringList listResult;

    if (!m_bValid) {
        return listResult;
    }

    QList<XPE::IMPORT_HEADER> listImports = m_pPE->getImports();

    for (int i = 0; i < listImports.count(); i++) {
        QString sLibrary = listImports.at(i).sName.toLower();

        if (!listResult.contains(sLibrary)) {
            listResult.append(sLibrary);
        }
    }

    return listResult;
}

void XEmuPE::_buildExportCache() const
{
    m_bExportCacheBuilt = true;

    if (!m_bValid) {
        return;
    }

    XPE::EXPORT_HEADER exportHeader = m_pPE->getExport();

    for (int i = 0; i < exportHeader.listPositions.count(); i++) {
        const XPE::EXPORT_POSITION &position = exportHeader.listPositions.at(i);

        if (!position.sFunctionName.isEmpty()) {
            m_mapExportByName.insert(position.sFunctionName, position.nRVA);
        }

        m_mapExportByOrdinal.insert((qint64)position.nOrdinal, position.nRVA);
    }
}

qint64 XEmuPE::getExportRVA(const QString &sFunction, qint64 nOrdinal) const
{
    if (!m_bValid) {
        return -1;
    }

    if (!m_bExportCacheBuilt) {
        _buildExportCache();
    }

    if (!sFunction.isEmpty()) {
        return m_mapExportByName.value(sFunction, -1);
    }

    if (nOrdinal >= 0) {
        return m_mapExportByOrdinal.value(nOrdinal, -1);
    }

    return -1;
}

QList<XEmuFileFormat::EXPORT_ENTRY> XEmuPE::getExportEntries() const
{
    QList<EXPORT_ENTRY> listResult;

    if (!m_bValid) {
        return listResult;
    }

    XPE::EXPORT_HEADER exportHeader = m_pPE->getExport();
    listResult.reserve(exportHeader.listPositions.count());

    for (int i = 0; i < exportHeader.listPositions.count(); i++) {
        const XPE::EXPORT_POSITION &position = exportHeader.listPositions.at(i);
        EXPORT_ENTRY e;
        e.sName = position.sFunctionName;
        e.nOrdinal = (qint64)position.nOrdinal;
        e.nRVA = (qint64)position.nRVA;
        listResult.append(e);
    }

    return listResult;
}

QList<XEmuFileFormat::IMPORT> XEmuPE::getImports() const
{
    QList<IMPORT> listResult;

    if (!m_bValid) {
        return listResult;
    }

    QList<XPE::IMPORT_HEADER> listImports = m_pPE->getImports();

    for (int i = 0; i < listImports.count(); i++) {
        const XPE::IMPORT_HEADER &importHeader = listImports.at(i);

        for (int j = 0; j < importHeader.listPositions.count(); j++) {
            const XPE::IMPORT_POSITION &importPosition = importHeader.listPositions.at(j);

            IMPORT import;
            import.sLibrary = importHeader.sName.toLower();
            import.sFunction = importPosition.sFunction.isEmpty() ? importPosition.sName : importPosition.sFunction;
            import.nOrdinal = importPosition.nOrdinal;
            import.nSlotRVA = importPosition.nThunkRVA;
            listResult.append(import);
        }
    }

    return listResult;
}
