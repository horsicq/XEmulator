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
#ifndef XEMUBIOSINT_H
#define XEMUBIOSINT_H

#include <functional>

#include <QString>

class XEmuMemoryManager;
class XEmuRegisters;

// BIOS software-interrupt services for the MS-DOS personality (16-bit real mode):
// INT 10h (video) and INT 16h (keyboard). These are the BIOS calls a console-mode DOS
// program relies on; there is no real hardware behind them, so the model returns
// plausible results (video mode 3, an immediate Enter for blocking key reads, ...).
// Console output is forwarded to the sink installed by the owner. handle() returns true
// when it serviced the vector.
class XEmuBiosInt {
public:
    explicit XEmuBiosInt(XEmuMemoryManager *pMemoryManager);

    void setOutputSink(const std::function<void(char)> &fnOut) { m_fnOut = fnOut; }

    bool handle(int nVector, XEmuRegisters *pRegisters);

private:
    void _video(XEmuRegisters *pRegisters);  // video
    void _keyboard(XEmuRegisters *pRegisters);  // keyboard
    void _timer(XEmuRegisters *pRegisters);  // INT 1Ah system timer / RTC

    void _out(char c)
    {
        if (m_fnOut) {
            m_fnOut(c);
        }
    }

    XEmuMemoryManager *m_pMemoryManager;
    std::function<void(char)> m_fnOut;
};

#endif  // XEMUBIOSINT_H
