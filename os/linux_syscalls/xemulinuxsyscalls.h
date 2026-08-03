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
#ifndef XEMULINUXSYSCALLS_H
#define XEMULINUXSYSCALLS_H

#include <functional>

#include <QByteArray>
#include <QMap>
#include <QString>
#include <QVector>

#include "xemuarch.h"
#include "xemumemorymanager.h"
#include "xemuregisters.h"
#include "xemusyscalls.h"

// Emulated Linux system-call layer for the user-mode emulator.
//
// The CPU core turns `syscall` / `int 0x80` into a STEP_SYSCALL; the OS personality
// forwards it here. This class reads the syscall number and arguments from the
// registers (x86-64 ABI: nr in RAX, args in RDI/RSI/RDX/R10/R8/R9; i386 ABI: nr in
// EAX, args in EBX/ECX/EDX/ESI/EDI/EBP), models the call against the emulator's own
// memory manager, and writes the result back into RAX/EAX.
//
// This is exactly what a Linux packer stub (UPX and friends) needs. Two styles are
// supported:
//   * anonymous:  mmap(MAP_ANONYMOUS) a RWX scratch buffer, decompress into it,
//                 mprotect, jump.
//   * fd-backed (modern UPX / W^X):  memfd_create or open a descriptor, ftruncate
//                 and write the decompressed image into it, then mmap that fd as
//                 executable at the target address and jump. This layer keeps an
//                 in-memory file per descriptor and makes a shared mmap alias its
//                 contents, so writing through one mapping is visible in another.
// Memory-shaping calls (mmap/mprotect/munmap/brk) are modelled faithfully; calls
// the stub does not depend on before the OEP transfer return a benign value.
class XEmuLinuxSyscalls : public XEmuSyscalls {
public:
    XEmuLinuxSyscalls(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64);

    QString getName() const override
    {
        return QStringLiteral("Linux");
    }
    void setLogger(const LOG_CALLBACK &fnLog) override;

    // Reset per-process state (heap break). Call once when a process is set up.
    void reset() override;

    // Provide the packed executable's own bytes. A read-only open() (the stub
    // re-opening itself through /proc/self/exe to read its compressed payload) is
    // backed by these, and readlink() reports this path.
    void setSelfExe(const QByteArray &baBytes, const QString &sPath) override;

    // Service the pending syscall. Returns true to continue execution, false when
    // the process has exited (exit / exit_group) or replaced itself (execve).
    bool dispatch(XEmuRegisters *pRegisters) override;

    bool hasExited() const;
    int exitCode() const;

    // A Linux packer stub reconstructs the original program inside a file descriptor
    // and then execve()s it. That descriptor's contents are the unpacked ELF: these
    // expose it so the generic unpacker can emit it directly.
    bool hasExeced() const override;
    QByteArray execImage() const override;

private:
    // Architecture-neutral syscall kinds the two ABIs both map onto.
    enum SCK_KIND {
        SCK_UNKNOWN = 0,
        SCK_MMAP,
        SCK_MMAP2,  // 32-bit mmap2: file offset is in pages
        SCK_MPROTECT,
        SCK_MUNMAP,
        SCK_MSYNC,
        SCK_BRK,
        SCK_ARCH_PRCTL,
        SCK_SET_THREAD_AREA,
        SCK_WRITE,
        SCK_READ,
        SCK_OPEN,
        SCK_MEMFD,
        SCK_FTRUNCATE,
        SCK_LSEEK,
        SCK_PWRITE,
        SCK_FSTAT,
        SCK_CLOSE,
        SCK_DUP,
        SCK_READLINK,
        SCK_EXECVE,
        SCK_EXECVEAT,
        SCK_EXIT,
        SCK_EXIT_GROUP,
        SCK_IGNORED  // known-but-irrelevant (returns 0)
    };

    // In-memory backing for an emulated file descriptor.
    struct FAKE_FILE {
        QByteArray baData;
        quint64 nOffset;

        FAKE_FILE() : nOffset(0)
        {
        }
    };

    // A shared (fd-backed) mapping; its bytes alias the file's contents.
    struct SHARED_MAP {
        XADDR nBase;
        quint64 nLen;
        int nFd;
        quint64 nFileOffset;
    };

    SCK_KIND _classify(quint64 nNumber) const;

    quint64 _arg(XEmuRegisters *pRegisters, int nIndex) const;
    quint64 _number(XEmuRegisters *pRegisters) const;
    void _return(XEmuRegisters *pRegisters, quint64 nValue);

    QByteArray _readMem(XADDR nAddress, quint64 nSize) const;
    XEmuMemoryManager::MEMORY_FLAGS _flagsFromProt(quint64 nProt) const;

    int _newFd();
    void _syncMapsToFile(int nFd);  // flush shared mappings of nFd back into its file

    quint64 _sysMmap(XEmuRegisters *pRegisters, bool bPageOffset);
    quint64 _sysMprotect(XEmuRegisters *pRegisters);
    quint64 _sysBrk(XEmuRegisters *pRegisters);
    quint64 _sysArchPrctl(XEmuRegisters *pRegisters);
    quint64 _sysWrite(XEmuRegisters *pRegisters);
    quint64 _sysRead(XEmuRegisters *pRegisters);
    quint64 _sysOpen(XEmuRegisters *pRegisters, bool bMemfd, quint64 nFlags, const QString &sPath);
    quint64 _sysReadlink(XEmuRegisters *pRegisters);
    quint64 _sysFtruncate(XEmuRegisters *pRegisters);
    quint64 _sysLseek(XEmuRegisters *pRegisters);
    quint64 _sysPwrite(XEmuRegisters *pRegisters);
    quint64 _sysFstat(XEmuRegisters *pRegisters);
    bool _sysExecve(XEmuRegisters *pRegisters, bool bExecveAt);  // returns false (process replaced)

    QString _readStr(XADDR nAddress, int nMax = 512) const;
    int _fdFromPath(const QString &sPath) const;
    int _largestFile() const;

    void _log(const QString &sText) const;

    XEmuMemoryManager *m_pMemoryManager;
    XEmuArch *m_pArch;
    bool m_bIs64;
    LOG_CALLBACK m_fnLog;

    XADDR m_nBrkBase;
    XADDR m_nBrkCurrent;
    XADDR m_nBrkLimit;

    QMap<int, FAKE_FILE> m_files;
    QVector<SHARED_MAP> m_sharedMaps;
    int m_nNextFd;

    bool m_bExited;
    int m_nExitCode;

    bool m_bExeced;
    QByteArray m_baExecImage;

    QByteArray m_baSelfExe;  // the packed executable's own bytes
    QString m_sSelfPath;
};

#endif  // XEMULINUXSYSCALLS_H
