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
#ifndef XEMUEMULATOR_H
#define XEMUEMULATOR_H

#include <QObject>

#include "arch/xemuarch.h"
#include "format/xemufileformat.h"
#include "os/xemuoperatingsystem.h"
#include "xemumemorymanager.h"
#include "xemuregisters.h"

// Top-level façade. Detects the file format, instantiates the matching architecture
// and operating-system personalities, drives the loader and then exposes the
// resulting process (memory, registers, modules) plus single-step / run execution.
class XEmuEmulator : public QObject {
    Q_OBJECT

public:
    struct OPTIONS {
        QString sSystemRoot;
        quint64 nStackSize;
        bool bLoadDependencies;
        QString sCommandLine;       // program arguments (DOS: PSP command tail)
        QString sWorkingDirectory;  // DOS current directory: base for INT 21h file I/O paths
        quint64 nImageBaseOverride;  // map the MAIN image here instead of its preferred base (0 = preferred); relocation-reconstruction uses this to run the stub at a second base

        OPTIONS() : nStackSize(0x100000), bLoadDependencies(true), nImageBaseOverride(0)
        {
        }
    };

    explicit XEmuEmulator(QObject *pParent = nullptr);
    ~XEmuEmulator() override;

    bool loadFile(const QString &sFileName, const OPTIONS &options);

    bool isReady() const;

    XEmuArch::STEP_INFO step();
    qint64 run(qint64 nMaxSteps);  // returns number of instructions executed

    XEmuMemoryManager *getMemoryManager();
    XEmuArch *getArch();
    XEmuRegisters *getRegisters();
    bool fireTimerInterrupt();  // inject IRQ0 if the guest hooked INT 8 (XEmuOperatingSystem::timerTick)

    QList<XEmuFileFormat::MODULE> getModules() const;

    // Import reconstruction support: the emulated-API arena bounds (to recognise resolved
    // imports in the guest IAT) and a reverse map from an arena pointer to its import name.
    quint64 getApiStubBase() const;
    quint64 getApiStubLimit() const;
    bool resolveImportStub(quint64 nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const;

    // True if the process replaced itself via execve with a reconstructed program
    // image (a Linux packer stub handing back the unpacked ELF); fills pbaImage.
    bool getReplacementImage(QByteArray *pbaImage) const;

    QString getOSName() const;
    QString getArchName() const;
    QString getRegistersText() const;
    QString getMemoryMapText() const;

    // Snapshot the DOS VGA text screen: pbaVram gets the 80x25x2 (char+attribute) buffer,
    // and the cursor position is returned. Returns false when the current OS is not the
    // text-mode MS-DOS personality. Used by a display widget to render the screen.
    bool getTextScreen(QByteArray *pbaVram, int *pnCols, int *pnRows, int *pnCursorRow, int *pnCursorCol) const;

signals:
    void infoMessage(const QString &sText);
    void errorMessage(const QString &sText);

private:
    void _cleanup();

    XEmuMemoryManager m_memoryManager;
    XEmuRegisters m_registers;
    XEmuArch *m_pArch;
    XEmuOperatingSystem *m_pOS;
    XEmuFileFormat *m_pFormat;
    bool m_bReady;
};

#endif  // XEMUEMULATOR_H
