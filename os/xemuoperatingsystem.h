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
#ifndef XEMUOPERATINGSYSTEM_H
#define XEMUOPERATINGSYSTEM_H

#include <QByteArray>
#include <QObject>

#include "xemuarch.h"
#include "xemufileformat.h"
#include "xemumemorymanager.h"
#include "xemuregisters.h"

// Abstract operating-system personality. A concrete implementation knows how to
// turn a mapped main image into a ready-to-run process: build the OS-specific
// control structures (PEB / TEB, loader lists, ...), lay out the stack, load the
// image's dependencies and set the initial register / segment state.
class XEmuOperatingSystem : public QObject {
    Q_OBJECT

public:
    struct OPTIONS {
        QString sSystemRoot;       // directory searched for dependency modules
        quint64 nStackSize;        // thread stack size
        bool bLoadDependencies;
        QString sCommandLine;      // program arguments (DOS: written to the PSP command tail)
        QString sWorkingDirectory; // DOS current directory: base for INT 21h file I/O paths
        QString sProgramName;      // loaded file's base name (DOS: env-block program-path tail)
        quint64 nImageBaseOverride; // map the MAIN image here instead of its preferred base (0 = preferred)

        OPTIONS() : nStackSize(0x100000), bLoadDependencies(true), nImageBaseOverride(0)
        {
        }
    };

    explicit XEmuOperatingSystem(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, QObject *pParent = nullptr);
    ~XEmuOperatingSystem() override;

    virtual QString getOSName() const = 0;

    // Map pMainFormat and everything around it, then fill pRegisters with the
    // initial thread state.
    virtual bool setupProcess(XEmuFileFormat *pMainFormat, XEmuRegisters *pRegisters, const OPTIONS &options) = 0;

    // Called by the emulator before each instruction. If the current PC is an
    // emulated-API trampoline, the OS handles the call (updates registers/PC to
    // model the API and its return) and returns true; the CPU step is skipped.
    virtual bool handleApiCall(XEmuRegisters *pRegisters, XADDR nPC)
    {
        Q_UNUSED(pRegisters)
        Q_UNUSED(nPC)
        return false;
    }

    // Called by the emulator when the CPU executes syscall / int 0x80. The OS reads
    // the syscall number and arguments from pRegisters and writes the return value.
    // Returns true to continue execution, false when the process has exited (the
    // emulator then reports a halt).
    virtual bool handleSyscall(XEmuRegisters *pRegisters)
    {
        Q_UNUSED(pRegisters)
        return false;
    }

    // Service a software interrupt (INT n) other than the Linux int 0x80. The PC has
    // already advanced past the instruction; the handler models the effect on the
    // registers/memory. Returns false if the vector is not modelled (the caller then
    // stops the run). Default: unhandled.
    virtual bool handleInterrupt(int nVector, XEmuRegisters *pRegisters)
    {
        Q_UNUSED(nVector)
        Q_UNUSED(pRegisters)
        return false;
    }

    // Deliver a periodic hardware timer interrupt (IRQ0 / INT 8) if the guest hooked it. DOS
    // protectors install a timer handler and spin until it fires; with no asynchronous interrupts
    // such a program never progresses. Returns true if one was injected (CS:IP now points at the
    // guest handler). Default: none.
    virtual bool timerTick(XEmuRegisters *pRegisters)
    {
        Q_UNUSED(pRegisters)
        return false;
    }

    // Called by the emulator when the CPU raised a hardware exception (currently a
    // memory access violation) and the arch left the PC at the faulting instruction.
    // The OS may dispatch it to a guest exception handler (Win32 SEH: the fs:[0]
    // EXCEPTION_REGISTRATION_RECORD chain) and redirect execution -- return true to
    // continue, false to let the emulator report the fault. Default: unhandled.
    virtual bool handleException(XEmuRegisters *pRegisters, XADDR nFaultingPC, XADDR nFaultAddress)
    {
        Q_UNUSED(pRegisters)
        Q_UNUSED(nFaultingPC)
        Q_UNUSED(nFaultAddress)
        return false;
    }

    // True once the guest has requested process termination (e.g. called ExitProcess /
    // TerminateProcess). The emulator turns the current step into a clean halt rather than
    // executing the trampoline's filler and crashing. Default: never exits this way.
    virtual bool processExited() const
    {
        return false;
    }

    // Import reconstruction support (Windows). The emulated-API arena bounds let a caller
    // recognise a resolved-import pointer written into the guest IAT; resolveImportStub maps
    // such a pointer back to its (library, function) so a real import directory can be
    // rebuilt. Default: no modelled imports.
    virtual quint64 apiStubBase() const
    {
        return 0;
    }
    virtual quint64 apiStubLimit() const
    {
        return 0;
    }
    virtual bool resolveImportStub(quint64 nStub, QString *pLibrary, QString *pFunction, qint64 *pOrdinal) const
    {
        Q_UNUSED(nStub)
        Q_UNUSED(pLibrary)
        Q_UNUSED(pFunction)
        Q_UNUSED(pOrdinal)
        return false;
    }

    // If the process replaced itself with a new program image (execve of a packer's
    // reconstructed file), returns true and fills pbaImage with that image. This is
    // how a Linux packer stub hands back the unpacked executable.
    virtual bool getReplacementImage(QByteArray *pbaImage)
    {
        Q_UNUSED(pbaImage)
        return false;
    }

    QList<XEmuFileFormat::MODULE> getModules() const;

    // The raw bytes of the main executable file. A Linux packer stub re-opens itself
    // (via /proc/self/exe) to read its compressed payload, so the syscall layer needs
    // the original file content.
    void setImageFileBytes(const QByteArray &baBytes)
    {
        m_baImageFile = baBytes;
    }

signals:
    void infoMessage(const QString &sText);
    void errorMessage(const QString &sText);

protected:
    XEmuMemoryManager *m_pMemoryManager;
    XEmuArch *m_pArch;
    QList<XEmuFileFormat::MODULE> m_listModules;
    QByteArray m_baImageFile;  // raw bytes of the main executable
};

#endif  // XEMUOPERATINGSYSTEM_H
