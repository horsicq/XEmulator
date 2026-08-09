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
#ifndef XEMUFILEFORMAT_H
#define XEMUFILEFORMAT_H

#include <QObject>
#include <QString>
#include <QStringList>

#include "xbinary.h"
#include "xemumemorymanager.h"
#include "xemutypes.h"

// Abstract executable-file-format loader. A concrete implementation knows how to
// parse one object format (PE, ELF, Mach-O, ...) and how to map its image into an
// XEmuMemoryManager the way the target operating system's loader would.
class XEmuFileFormat : public QObject {
    Q_OBJECT

public:
    // A single image that has been (or will be) mapped into the address space.
    struct MODULE {
        QString sName;      // lower-case base name, e.g. "kernel32.dll"
        QString sFileName;  // absolute path on the host
        XADDR nBaseAddress;
        quint64 nImageSize;
        XADDR nEntryPointAddress;  // absolute (0 if none)
        bool bIs64;

        MODULE() : nBaseAddress(0), nImageSize(0), nEntryPointAddress(0), bIs64(false)
        {
        }
    };

    // One imported symbol together with the address-space slot that must be patched
    // with the resolved function address (the Import Address Table entry).
    struct IMPORT {
        QString sLibrary;
        QString sFunction;
        qint64 nOrdinal;  // -1 when imported by name
        qint64 nSlotRVA;  // RVA of the IAT thunk to patch

        IMPORT() : nOrdinal(-1), nSlotRVA(0)
        {
        }
    };

    explicit XEmuFileFormat(QObject *pParent = nullptr);
    ~XEmuFileFormat() override;

    virtual bool setFileName(const QString &sFileName) = 0;
    virtual bool isValid() const = 0;

    virtual bool is64Bit() const = 0;
    virtual XEmuArchType getArchType() const = 0;
    virtual XBinary::OSNAME getOSName() const = 0;
    virtual bool isDll() const = 0;

    virtual XADDR getPreferredImageBase() const = 0;
    virtual quint64 getImageSize() const = 0;
    virtual qint64 getEntryPointRVA() const = 0;

    // True for a flat MS-DOS .COM image (loaded at offset 0x100 within a segment).
    virtual bool isDosCom() const
    {
        return false;
    }

    // Map headers and sections at nMapBase, fixing up relocations when nMapBase differs
    // from the preferred base. Fills pModuleResult on success.
    virtual bool map(XEmuMemoryManager *pMemoryManager, XADDR nMapBase, MODULE *pModuleResult) = 0;

    virtual QStringList getImportLibraries() const = 0;
    virtual QList<IMPORT> getImports() const = 0;

    // Resolve an exported symbol to its RVA (relative to this module's base).
    // Returns -1 when the symbol is not exported. nOrdinal is used only when
    // sFunction is empty (import by ordinal).
    virtual qint64 getExportRVA(const QString &sFunction, qint64 nOrdinal) const = 0;

    // One entry of the module's export directory (for building a resolved-VA -> API map when
    // a real system DLL is mapped: every reachable export VA must be intercepted so the subset
    // CPU never executes real DLL code).
    struct EXPORT_ENTRY {
        QString sName;       // export name (empty for by-ordinal only)
        qint64 nOrdinal;     // ordinal
        qint64 nRVA;         // executable function RVA, or -1 for a forwarder
        QString sForwarder;  // validated "module.symbol" forwarder, otherwise empty
    };
    virtual QList<EXPORT_ENTRY> getExportEntries() const
    {
        return QList<EXPORT_ENTRY>();
    }

signals:
    void infoMessage(const QString &sText);
    void errorMessage(const QString &sText);

protected:
    // Generic loader: reserve the image and copy every memory-map record from its
    // file offset to its virtual address. Works for any XBinary-derived format
    // (ELF, Mach-O, MZ, ...). Sections are committed read/write/execute (the record
    // list does not carry per-segment protection). Returns the mapped image size.
    static bool mapByMemoryMap(XBinary *pBinary, XEmuMemoryManager *pMemoryManager, XADDR nMapBase, const QString &sModuleName, MODULE *pModuleResult);
};

#endif  // XEMUFILEFORMAT_H
