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
#ifndef XEMUBSDSYSCALLS_H
#define XEMUBSDSYSCALLS_H

#include <QByteArray>
#include <QMap>
#include <QString>

#include "xemuarch.h"
#include "xemumemorymanager.h"
#include "xemuregisters.h"
#include "xemusyscalls.h"

// Emulated BSD / Darwin system-call layer.
//
// FreeBSD and macOS/Darwin share the classic BSD user/kernel convention on x86:
//   * arguments: 64-bit uses the System V registers (RDI, RSI, RDX, R10, R8, R9);
//     32-bit passes them on the stack above the return address.
//   * the syscall number is in RAX; Darwin tags it with a class in the high byte
//     (0x2000000 = BSD/Unix), which is masked off here.
//   * ERRORS ARE REPORTED IN THE CARRY FLAG (not a negative return like Linux):
//     on failure CF is set and RAX holds the positive errno; on success CF is
//     cleared and RAX holds the result.
//
// This services the memory-shaping calls a Mach-O / ELF packer stub makes
// (mmap/mprotect/munmap) plus a minimal file model, so a BSD/Darwin UPX stub can
// run without a real kernel. Unmodelled calls return a benign success or ENOSYS.
class XEmuBSDSyscalls : public XEmuSyscalls {
public:
    enum FLAVOR { FLAVOR_FREEBSD, FLAVOR_DARWIN };

    XEmuBSDSyscalls(XEmuMemoryManager *pMemoryManager, XEmuArch *pArch, bool bIs64, FLAVOR flavor);

    QString getName() const override
    {
        return (m_flavor == FLAVOR_DARWIN) ? QStringLiteral("Darwin") : QStringLiteral("FreeBSD");
    }
    void setLogger(const LOG_CALLBACK &fnLog) override;
    void reset() override;
    void setSelfExe(const QByteArray &baBytes, const QString &sPath) override;
    bool dispatch(XEmuRegisters *pRegisters) override;

    bool hasExited() const;
    int exitCode() const;

private:
    enum SCK_KIND {
        SCK_UNKNOWN = 0,
        SCK_MMAP,
        SCK_MPROTECT,
        SCK_MUNMAP,
        SCK_MADVISE,
        SCK_MINCORE,
        SCK_WRITE,
        SCK_READ,
        SCK_OPEN,
        SCK_CLOSE,
        SCK_LSEEK,
        SCK_FSTAT,
        SCK_SYSCTL,
        SCK_EXIT,
        SCK_IGNORED
    };

    struct FAKE_FILE {
        QByteArray baData;
        quint64 nOffset;

        FAKE_FILE() : nOffset(0)
        {
        }
    };

    SCK_KIND _classify(quint64 nNumber) const;

    quint64 _arg(XEmuRegisters *pRegisters, int nIndex) const;
    quint64 _number(XEmuRegisters *pRegisters) const;
    void _returnOk(XEmuRegisters *pRegisters, quint64 nValue);
    void _returnErr(XEmuRegisters *pRegisters, quint64 nErrno);

    QString _readStr(XADDR nAddress, int nMax = 512) const;
    XEmuMemoryManager::MEMORY_FLAGS _flagsFromProt(quint64 nProt) const;

    int _newFd();
    quint64 _sysMmap(XEmuRegisters *pRegisters);
    quint64 _sysMprotect(XEmuRegisters *pRegisters);
    quint64 _sysOpen(XEmuRegisters *pRegisters, quint64 nFlags, const QString &sPath);
    quint64 _sysRead(XEmuRegisters *pRegisters);
    quint64 _sysWrite(XEmuRegisters *pRegisters);

    void _log(const QString &sText) const;

    XEmuMemoryManager *m_pMemoryManager;
    XEmuArch *m_pArch;
    bool m_bIs64;
    FLAVOR m_flavor;
    LOG_CALLBACK m_fnLog;

    QMap<int, FAKE_FILE> m_files;
    int m_nNextFd;

    QByteArray m_baSelfExe;
    QString m_sSelfPath;

    bool m_bExited;
    int m_nExitCode;
};

#endif  // XEMUBSDSYSCALLS_H
