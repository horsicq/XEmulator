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
#ifndef XEMUSYSCALLS_H
#define XEMUSYSCALLS_H

#include <functional>

#include <QByteArray>
#include <QString>

#include "xemuregisters.h"

// Abstract emulated system-call layer. The CPU core turns `syscall` / `int 0x80`
// into a STEP_SYSCALL; the OS personality forwards it to a concrete implementation
// (Linux, BSD/Darwin, ...). Each implementation reads the syscall number and
// arguments from the registers, models the call against the emulator's memory
// manager, and writes the result back -- servicing the memory-shaping calls a
// packer stub makes (mmap/mprotect/munmap/...) without any real kernel.
class XEmuSyscalls {
public:
    typedef std::function<void(const QString &)> LOG_CALLBACK;

    virtual ~XEmuSyscalls()
    {
    }

    virtual QString getName() const = 0;

    virtual void setLogger(const LOG_CALLBACK &fnLog) = 0;

    // Reset per-process state; call once when a process is set up.
    virtual void reset() = 0;

    // The raw bytes (and path) of the packed executable, so a stub that re-opens
    // itself to read its payload can be served.
    virtual void setSelfExe(const QByteArray &baBytes, const QString &sPath) = 0;

    // Service the pending syscall. Returns true to continue execution, false when the
    // process has exited or replaced itself (execve).
    virtual bool dispatch(XEmuRegisters *pRegisters) = 0;

    // If the process replaced itself with a reconstructed program image (a Linux
    // packer's execve), returns true and its bytes.
    virtual bool hasExeced() const
    {
        return false;
    }
    virtual QByteArray execImage() const
    {
        return QByteArray();
    }
};

#endif  // XEMUSYSCALLS_H
