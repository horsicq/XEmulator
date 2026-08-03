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
#include "xemugenericformat.h"

#include <QFileInfo>

XEmuGenericFormat::XEmuGenericFormat(QObject *pParent)
    : XEmuFileFormat(pParent), m_pFile(nullptr), m_pBinary(nullptr), m_bValid(false), m_archType(XARCH_UNKNOWN), m_osName(XBinary::OSNAME_UNKNOWN),
      m_bIs64(false), m_nPreferredBase(0), m_nImageSize(0), m_nEntryRVA(0)
{
}

XEmuGenericFormat::~XEmuGenericFormat()
{
    _close();
}

void XEmuGenericFormat::_close()
{
    if (m_pBinary) {
        delete m_pBinary;
        m_pBinary = nullptr;
    }
    if (m_pFile) {
        m_pFile->close();
        delete m_pFile;
        m_pFile = nullptr;
    }
    m_bValid = false;
}

bool XEmuGenericFormat::setFileName(const QString &sFileName)
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

    m_pBinary = createBinary(m_pFile);
    if (!m_pBinary || !m_pBinary->isValid()) {
        emit errorMessage(tr("Not a valid image: %1").arg(sFileName));
        _close();
        return false;
    }

    XBinary::_MEMORY_MAP memoryMap = m_pBinary->getMemoryMap();
    m_nPreferredBase = memoryMap.nModuleAddress;

    XADDR nMaxEnd = m_nPreferredBase;
    for (int i = 0; i < memoryMap.listRecords.count(); i++) {
        const XBinary::_MEMORY_RECORD &record = memoryMap.listRecords.at(i);
        nMaxEnd = qMax<XADDR>(nMaxEnd, record.nAddress + record.nSize);
    }
    m_nImageSize = XEmuMemoryManager::alignUp(nMaxEnd - m_nPreferredBase, XEmuMemoryManager::N_PAGE_SIZE);
    if ((quint64)memoryMap.nImageSize > m_nImageSize) {
        m_nImageSize = XEmuMemoryManager::alignUp(memoryMap.nImageSize, XEmuMemoryManager::N_PAGE_SIZE);
    }

    XADDR nEntry = memoryMap.nEntryPointAddress;
    m_nEntryRVA = nEntry ? (qint64)(nEntry - m_nPreferredBase) : 0;

    m_bIs64 = m_pBinary->is64();
    m_archType = xemuArchTypeFromDisasmMode(m_pBinary->getDisasmMode());

    XBinary::FILEFORMATINFO fileFormatInfo = m_pBinary->getFileFormatInfo(nullptr);
    m_osName = fileFormatInfo.osName;

    m_bValid = true;
    return true;
}

bool XEmuGenericFormat::isValid() const
{
    return m_bValid;
}

bool XEmuGenericFormat::is64Bit() const
{
    return m_bIs64;
}

XEmuArchType XEmuGenericFormat::getArchType() const
{
    return m_archType;
}

XBinary::OSNAME XEmuGenericFormat::getOSName() const
{
    return m_osName;
}

bool XEmuGenericFormat::isDll() const
{
    return false;
}

XADDR XEmuGenericFormat::getPreferredImageBase() const
{
    return m_nPreferredBase;
}

quint64 XEmuGenericFormat::getImageSize() const
{
    return m_nImageSize;
}

qint64 XEmuGenericFormat::getEntryPointRVA() const
{
    return m_nEntryRVA;
}

bool XEmuGenericFormat::map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult)
{
    if (!m_bValid) {
        return false;
    }

    if (!mapByMemoryMap(m_pBinary, pMemoryManager, nMapBase, m_sModuleName, pModuleResult)) {
        emit errorMessage(tr("Cannot map %1 at %2").arg(m_sModuleName).arg(nMapBase, 0, 16));
        return false;
    }

    if (pModuleResult) {
        pModuleResult->sFileName = m_sFileName;
        pModuleResult->bIs64 = m_bIs64;
    }

    emit infoMessage(tr("Mapped %1 at %2 (%3 bytes)").arg(m_sModuleName).arg(nMapBase, 0, 16).arg(m_nImageSize));
    return true;
}

QStringList XEmuGenericFormat::getImportLibraries() const
{
    return QStringList();
}

QList<XEmuFileFormat::IMPORT> XEmuGenericFormat::getImports() const
{
    return QList<IMPORT>();
}

qint64 XEmuGenericFormat::getExportRVA(const QString &sFunction, qint64 nOrdinal) const
{
    Q_UNUSED(sFunction)
    Q_UNUSED(nOrdinal)
    return -1;
}
