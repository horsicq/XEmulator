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
#ifndef XEMUCOM_H
#define XEMUCOM_H

#include <QByteArray>

#include "xemufileformat.h"

// MS-DOS .COM loader. A COM file is a flat 16-bit binary with no header: it is
// loaded at offset 0x100 within a 64 KiB segment (right after the PSP), execution
// starts at IP=0x100 and all segment registers point at the load segment. The DOS
// personality performs that segment layout using getData().
class XEmuCOM : public XEmuFileFormat {
    Q_OBJECT

public:
    explicit XEmuCOM(QObject *pParent = nullptr);

    bool setFileName(const QString &sFileName) override;
    bool isValid() const override;

    bool is64Bit() const override;
    XEmuArchType getArchType() const override;
    XBinary::OSNAME getOSName() const override;
    bool isDll() const override;
    bool isDosCom() const override;

    XADDR getPreferredImageBase() const override;
    quint64 getImageSize() const override;
    qint64 getEntryPointRVA() const override;

    bool map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult) override;

    QStringList getImportLibraries() const override;
    QList<IMPORT> getImports() const override;
    qint64 getExportRVA(const QString &sFunction, qint64 nOrdinal) const override;

    const QByteArray &getData() const;
    QString getModuleName() const;

private:
    QString m_sFileName;
    QString m_sModuleName;
    QByteArray m_baData;
    bool m_bValid;
};

#endif  // XEMUCOM_H
