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
#ifndef XEMUUNIXOS_H
#define XEMUUNIXOS_H

#include "xemuoperatingsystem.h"
#include "xemusyscalls.h"

// Shared base for the Unix-family personalities (Linux, FreeBSD, macOS). Maps the
// main image, lays out a thread stack with the initial process vector and sets the
// initial PC / SP / segment state. Subclasses customise the OS name and the exact
// initial-stack layout (ELF argc/argv/envp/auxv vs. the Mach-O variant).
class XEmuUnixOS : public XEmuOperatingSystem {
    Q_OBJECT

public:
    explicit XEmuUnixOS(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent = nullptr);
    ~XEmuUnixOS() override;

    bool setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options) override;
    bool handleSyscall(XEmuRegisters *pRegisters) override;
    bool getReplacementImage(QByteArray *pbaImage) override;

protected:
    // Build the initial process stack; returns the final stack pointer.
    virtual XADDR buildInitialStack(XEmuFileFormat *pMainFormat, const XEmuFileFormat::MODULE &mainModule, XADDR nStackTop, XEmuRegisters *pRegisters);

    XADDR _chooseBase(XEmuFileFormat *pFormat);
    int _ptrSize() const;
    void _pushPtr(XADDR nAddress, quint64 nValue);
    void _setupX86Segments(XEmuRegisters *pRegisters);

    // Build the emulated syscall layer for this personality. The base creates the
    // Linux layer; BSD/Darwin personalities override to create the BSD one.
    virtual XEmuSyscalls *createSyscalls();

    // Forwards syscall-layer log text to this OS object's infoMessage() signal.
    void _forwardSyscallLog(const QString &sText);

    bool m_bIs64;
    XEmuArchType m_archType;
    XEmuSyscalls *m_pSyscalls;  // emulated syscall layer (personality-specific)
};

#endif  // XEMUUNIXOS_H
