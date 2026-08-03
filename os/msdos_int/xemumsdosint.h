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
#ifndef XEMUMSDOSINT_H
#define XEMUMSDOSINT_H

#include <functional>

#include <QMap>
#include <QSet>
#include <QString>
#include <QStringList>

class QFile;
class XEmuMemoryManager;
class XEmuRegisters;

// MS-DOS INT 21h services for the DOS personality (16-bit real mode): a subset of the
// common functions a console program uses -- character/string output, buffered/direct
// console input, get-version/date/time, get/set interrupt vector, program termination,
// and the handle-based file API (create/open/close/read/write/seek/delete). File I/O is
// backed by the host filesystem, rooted at the working directory set by the owner; DOS
// paths are resolved relative to it. Console output and diagnostics are forwarded to the
// sinks installed by the owner. int21() sets *pbTerminate when the program requested to
// exit (AH=00h/4Ch).
class XEmuMsdosInt {
public:
    explicit XEmuMsdosInt(XEmuMemoryManager *pMemoryManager);
    ~XEmuMsdosInt();

    void setOutputSink(const std::function<void(char)> &fnOut) { m_fnOut = fnOut; }
    void setLogSink(const std::function<void(const QString &)> &fnLog) { m_fnLog = fnLog; }

    // Base directory for INT 21h file I/O: DOS paths (DS:DX ASCIIZ) are resolved against it.
    void setWorkingDirectory(const QString &sDir) { m_sWorkingDirectory = sDir; }
    void setPspSegment(quint16 nSeg) { m_nPspSeg = nSeg; }  // the loader's program PSP (for AH=55 copy)
    // Set up the DOS MCB chain the loader built: env block (nEnvSeg, nEnvParas) owned by nPspSeg, then the
    // program block (nPspSeg, nPspParas) owned by nPspSeg, then -- if it doesn't reach nMemTop -- a trailing
    // free block up to nMemTop. A maxalloc=0 load-high program owns everything (nPspParas == nMemTop-nPspSeg).
    void mcbSetup(quint16 nEnvSeg, quint16 nEnvParas, quint16 nPspSeg, quint16 nPspParas, quint16 nMemTop);

    void int21(XEmuRegisters *pRegisters, bool *pbTerminate);

    // Memory-arena access for the owner (INT 21h AH=4Bh EXEC has to place a child program before
    // any guest code runs, so it cannot go through the guest-facing AH=48h path).
    bool allocParas(quint16 nParas, quint16 *pnSeg)
    {
        quint16 nMax = 0;  // _memAlloc writes the largest free block here when it fails
        return m_nFirstMcb && _memAlloc(nParas, pnSeg, &nMax);
    }
    bool freeSeg(quint16 nSeg) { return _memFree(nSeg); }
    // Resolve an ASCIIZ DOS path at seg:off to a host path, using the same working-directory and
    // name rules as the file functions (so AH=4Bh finds a child exactly where AH=3Dh would).
    QString resolveGuestPath(quint16 nSeg, quint16 nOff) { return _resolvePath(_readAsciiz(((quint64)nSeg) << 4, nOff)); }
    void setPspOwner(quint16 nSeg, quint16 nOwner) { _mcbClaim(nSeg, nOwner); }

private:
    void _out(char c)
    {
        if (m_fnOut) {
            m_fnOut(c);
        }
    }
    void _log(const QString &sText)
    {
        if (m_fnLog) {
            m_fnLog(sText);
        }
    }

    // Handle-based file API (AH=3Ch..42h etc.). Returns true when nAH was a file function
    // (whether it succeeded or set CF for a DOS error), false to fall through to the caller.
    bool _fileFunction(quint8 nAH, XEmuRegisters *pRegisters);

    QByteArray _readAsciiz(quint64 nBase, quint16 nOffset, int nMax = 260) const;  // ASCIIZ path at seg:off
    QString _resolvePath(const QByteArray &baDosName) const;                       // DOS path -> host path
    void _releaseHostFile(const QString &sPath);  // close host handles so DOS delete/rename can proceed
    void _syncPath(const QString &sPath, int nExceptHandle = -1);  // flush other open handles on this path
    int _lowestFreeHandle() const;                                                 // DOS JFT rule: lowest free >= 5
    int _allocHandle(QFile *pFile);                                                // open a handle for pFile
    void _fillFindRecord(const QString &sFileName);                                // write a 43-byte find record to the DTA

    // --- DOS memory control block (MCB) chain, stored in guest memory (real MCB format) ---
    quint8 _mcbType(quint16 nMcb) const;                       // 'M'(0x4D) more / 'Z'(0x5A) last
    quint16 _mcbOwner(quint16 nMcb) const;                     // owner PSP (0 = free)
    quint16 _mcbSize(quint16 nMcb) const;                      // block size in paragraphs
    void _mcbWrite(quint16 nMcb, quint8 nType, quint16 nOwner, quint16 nSize);
    bool _memAlloc(quint16 nParas, quint16 *pnSeg, quint16 *pnMaxParas);  // AH=48
    bool _memFree(quint16 nSeg);                                          // AH=49
    bool _memResize(quint16 nSeg, quint16 nParas, quint16 *pnMaxParas);   // AH=4A
    void _mcbClaim(quint16 nSeg, quint16 nOwner);                         // split the containing block, own [nSeg]

    XEmuMemoryManager *m_pMemoryManager;
    std::function<void(char)> m_fnOut;
    std::function<void(const QString &)> m_fnLog;
    QMap<int, quint32> m_mapIvt;      // vectors set via 21h.25 / read via 21h.35 (seg<<16 | off)
    QString m_sWorkingDirectory;      // host directory that backs the DOS current directory
    QMap<int, QFile *> m_mapFiles;    // open DOS file handles (>= 5) -> host file
    QSet<int> m_conHandles;          // handles that alias the console (from AH=45 DUP of stdout/stderr)
    QSet<int> m_nulHandles;          // handles opened on the NUL/PRN/AUX device: writes discarded, reads EOF
    quint16 m_nPspSeg;               // current program PSP segment (source for AH=55 create-PSP copy)
    int m_nTempSeq;                  // counter for AH=5Ah unique temp-file names
    quint16 m_nAllocSeg;             // bump allocator fallback (used only when the MCB chain is not set up)
    quint16 m_nFirstMcb;             // first MCB segment of the memory-control-block chain (0 = not set up)
    quint64 m_nDtaAddr;              // linear Disk Transfer Address (AH=1Ah; default PSP:0080h)
    quint16 m_nDtaSeg, m_nDtaOff;    // ...and the seg:off the program set, so AH=2Fh returns it verbatim
    QStringList m_findResults;       // current AH=4Eh/4Fh directory-search matches
    int m_nFindIndex;                // index into m_findResults for find-next
    QString m_sFindDir;              // host directory the search ran in
};

#endif  // XEMUMSDOSINT_H
