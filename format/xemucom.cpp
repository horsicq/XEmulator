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
#include "xemucom.h"

#include <QFile>
#include <QFileInfo>

XEmuCOM::XEmuCOM(QObject *pParent) : XEmuFileFormat(pParent), m_bValid(false)
{
}

bool XEmuCOM::setFileName(const QString &sFileName)
{
    m_sFileName = sFileName;
    m_sModuleName = QFileInfo(sFileName).fileName().toLower();
    m_baData.clear();
    m_bValid = false;

    QFile file(sFileName);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorMessage(tr("Cannot open file: %1").arg(sFileName));
        return false;
    }

    m_baData = file.readAll();
    file.close();

    // A COM image plus its PSP must fit inside one 64 KiB segment.
    if (m_baData.isEmpty() || (m_baData.size() > (0x10000 - 0x100))) {
        emit errorMessage(tr("Not a valid COM image (size out of range): %1").arg(sFileName));
        return false;
    }

    m_bValid = true;
    return true;
}

bool XEmuCOM::isValid() const
{
    return m_bValid;
}

bool XEmuCOM::is64Bit() const
{
    return false;
}

XEmuArchType XEmuCOM::getArchType() const
{
    return XARCH_X86_16;
}

XBinary::OSNAME XEmuCOM::getOSName() const
{
    return XBinary::OSNAME_MSDOS;
}

bool XEmuCOM::isDll() const
{
    return false;
}

bool XEmuCOM::isDosCom() const
{
    return true;
}

XADDR XEmuCOM::getPreferredImageBase() const
{
    return 0;
}

quint64 XEmuCOM::getImageSize() const
{
    return (quint64)m_baData.size();
}

qint64 XEmuCOM::getEntryPointRVA() const
{
    return 0;  // execution starts at IP=0x100; the DOS loader applies the segment layout
}

bool XEmuCOM::map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult)
{
    if (!m_bValid) {
        return false;
    }

    if (pMemoryManager->allocate(nMapBase, (quint64)m_baData.size(), XEmuMemoryManager::MEMORY_FLAGS(true, true, true), m_sModuleName) != nMapBase) {
        emit errorMessage(tr("Cannot map COM image at %1").arg(nMapBase, 0, 16));
        return false;
    }
    pMemoryManager->write(nMapBase, m_baData);

    if (pModuleResult) {
        pModuleResult->sName = m_sModuleName;
        pModuleResult->sFileName = m_sFileName;
        pModuleResult->nBaseAddress = nMapBase;
        pModuleResult->nImageSize = (quint64)m_baData.size();
        pModuleResult->nEntryPointAddress = nMapBase;
        pModuleResult->bIs64 = false;
    }
    return true;
}

QStringList XEmuCOM::getImportLibraries() const
{
    return QStringList();
}

QList<XEmuFileFormat::IMPORT> XEmuCOM::getImports() const
{
    return QList<IMPORT>();
}

qint64 XEmuCOM::getExportRVA(const QString &sFunction, qint64 nOrdinal) const
{
    Q_UNUSED(sFunction)
    Q_UNUSED(nOrdinal)
    return -1;
}

const QByteArray &XEmuCOM::getData() const
{
    return m_baData;
}

QString XEmuCOM::getModuleName() const
{
    return m_sModuleName;
}
