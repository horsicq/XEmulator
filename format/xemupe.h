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
#ifndef XEMUPE_H
#define XEMUPE_H

#include <QFile>
#include <QHash>

#include "xemufileformat.h"
#include "xpe.h"

// PE (Portable Executable) loader. Maps an image the way the Windows loader does:
// headers + sections placed at their virtual addresses, section protection taken
// from the section characteristics, base relocations applied when the image is
// mapped away from its preferred base.
class XEmuPE : public XEmuFileFormat {
    Q_OBJECT

public:
    explicit XEmuPE(QObject *pParent = nullptr);
    ~XEmuPE() override;

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
    QList<EXPORT_ENTRY> getExportEntries() const override;

private:
    void _close();
    bool _applyRelocations(XEmuMemoryManager *pMemoryManager,
                           XADDR nMapBase, XADDR nPreferredBase,
                           quint64 nImageSize);
    void _buildExportCache() const;

    QFile *m_pFile;
    XPE *m_pPE;
    QString m_sFileName;
    QString m_sModuleName;
    bool m_bValid;

    // Export directory is parsed once and cached (import patching resolves thousands
    // of symbols against the same module).
    mutable bool m_bExportCacheBuilt;
    mutable QHash<QString, qint64> m_mapExportByName;
    mutable QHash<qint64, qint64> m_mapExportByOrdinal;
};

#endif  // XEMUPE_H
