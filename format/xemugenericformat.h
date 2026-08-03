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
#ifndef XEMUGENERICFORMAT_H
#define XEMUGENERICFORMAT_H

#include <QFile>

#include "xemufileformat.h"

// Shared implementation for formats that can be mapped straight from their
// XBinary memory map (ELF, Mach-O, MZ). A concrete subclass only has to construct
// the right XBinary-derived parser via createBinary(). Dependency resolution
// (imports/exports) is not implemented for these formats yet.
class XEmuGenericFormat : public XEmuFileFormat {
    Q_OBJECT

public:
    explicit XEmuGenericFormat(QObject *pParent = nullptr);
    ~XEmuGenericFormat() override;

    bool setFileName(const QString &sFileName) override;
    bool isValid() const override;

    bool is64Bit() const override;
    XEmuArchType getArchType() const override;
    XBinary::OSNAME getOSName() const override;
    bool isDll() const override;

    XADDR getPreferredImageBase() const override;
    quint64 getImageSize() const override;
    qint64 getEntryPointRVA() const override;

    bool map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult) override;

    QStringList getImportLibraries() const override;
    QList<IMPORT> getImports() const override;
    qint64 getExportRVA(const QString &sFunction, qint64 nOrdinal) const override;

protected:
    // Construct the concrete parser (e.g. new XELF(pDevice)). Ownership passes to
    // this class. pDevice stays open for the lifetime of the returned object.
    virtual XBinary *createBinary(QIODevice *pDevice) = 0;

    void _close();

    QFile *m_pFile;
    XBinary *m_pBinary;
    QString m_sFileName;
    QString m_sModuleName;
    bool m_bValid;

    XEmuArchType m_archType;
    XBinary::OSNAME m_osName;
    bool m_bIs64;
    XADDR m_nPreferredBase;
    quint64 m_nImageSize;
    qint64 m_nEntryRVA;
};

#endif  // XEMUGENERICFORMAT_H
