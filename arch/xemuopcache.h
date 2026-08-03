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
#ifndef XEMUOPCACHE_H
#define XEMUOPCACHE_H

#include <QHash>

#include "xbinary.h"

// A minimal per-address decoded-instruction cache: an instruction at a given guest
// address is decoded once and re-used on subsequent executions. This is the
// "translate once, execute many" idea from QEMU applied to fixed-width RISC ISAs
// (ARM / AArch64), where each guest address maps to exactly one decoded op.
template <class TOp>
class XEmuOpCache {
public:
    XEmuOpCache()
    {
    }

    const TOp *find(XADDR nAddress) const
    {
        typename QHash<XADDR, TOp>::const_iterator it = m_map.constFind(nAddress);
        return (it == m_map.constEnd()) ? nullptr : &it.value();
    }

    const TOp *insert(XADDR nAddress, const TOp &op)
    {
        m_map.insert(nAddress, op);
        return &m_map[nAddress];
    }

    void clear()
    {
        m_map.clear();
    }

    void invalidate(XADDR nFrom, XADDR nTo)
    {
        QList<XADDR> listKeys = m_map.keys();
        for (int i = 0; i < listKeys.size(); i++) {
            if ((listKeys.at(i) >= nFrom) && (listKeys.at(i) < nTo)) {
                m_map.remove(listKeys.at(i));
            }
        }
    }

    int count() const
    {
        return m_map.size();
    }

private:
    QHash<XADDR, TOp> m_map;
};

#endif  // XEMUOPCACHE_H
