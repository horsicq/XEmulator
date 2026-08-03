# XEmulator

A user-mode process **emulator** core (Qt/C++). It opens an executable, builds a
virtual address space that mirrors a real OS loader, wires up the CPU register/segment
state, and executes the image. No dependency on Unicorn — the CPU cores are our own,
built with QEMU-style dynamic translation.

Built from three abstract layers that combine freely:

| Layer | Abstract base | Implementations |
| --- | --- | --- |
| Operating system | `XEmuOperatingSystem` | `XEmuWindows` (PEB/TEB, LDR lists, DLL loader), `XEmuLinux`, `XEmuFreeBSD`, `XEmuMacOS`, `XEmuDOS` |
| Architecture | `XEmuArch` | `XEmuX86` (16/32/64-bit), `XEmuArm` (AArch32), `XEmuArm64` (AArch64) |
| File format | `XEmuFileFormat` | `XEmuPE`, `XEmuELF`, `XEmuMachO`, `XEmuMSDOS` (MZ), `XEmuCOM` |

Supported combinations:

| Format | OS | Architectures |
| --- | --- | --- |
| PE | Windows | x86, x86-64, ARM, ARM64 |
| ELF | Linux / FreeBSD | x86, x86-64, ARM, ARM64 |
| Mach-O | macOS | x86-64, ARM64 |
| MZ, COM | MS-DOS | x86-16 (real mode) |

`XEmuEmulator` is the façade: it detects the format, resolves the architecture and OS,
instantiates the matching trio, drives the loader and exposes step/run execution plus the
memory map, registers and modules.

## Directory layout

```
XEmulator/
├── xemulator.cmake             # source-list + include dirs (this is what you include)
├── xemuemulator.{h,cpp}        # top-level façade
├── xemumemorymanager.{h,cpp}   # Windows-like virtual memory manager + hook callbacks
├── xemuregisters.{h,cpp}       # x86 / ARM / AArch64 register file
├── xemutypes.h                 # XEmuArchType
├── arch/                       # XEmuArch + x86 (translation blocks), arm, arm64
├── format/                     # XEmuFileFormat + pe, elf, macho, msdos, com
└── os/                         # XEmuOperatingSystem + windows, linux, freebsd, macos, dos
```

## Using it

`xemulator.cmake` is a `_mylibs` source-list library. Include it and add
`${XEMULATOR_SOURCES}` to your target:

```cmake
include(${CMAKE_CURRENT_LIST_DIR}/../../_mylibs/XEmulator/xemulator.cmake)
add_executable(MyApp ${XEMULATOR_SOURCES} main.cpp)
target_link_libraries(MyApp PRIVATE Qt6::Core)
if(WIN32)
    target_link_libraries(MyApp PRIVATE Wintrust Crypt32)  # XPE Authenticode parsing
endif()
```

It pulls in only the parts of `_mylibs/Formats` needed to parse the supported formats
(XBinary + XMSDOS + XPE + XELF + XMACH + XCLIAssembly); the archive / DEX / PDF backends
are intentionally excluded, so the only extra link dependencies are `Wintrust` / `Crypt32`
on Windows.

## Memory hooks

`XEmuMemoryManager` exposes Unicorn-style hook callbacks fired as the guest executes:
`setCodeCallback` (once per instruction), `setReadCallback` / `setWriteCallback` (per data
access, with value) and `setInvalidCallback` (access to un-committed memory). Instruction
fetches use a separate `fetch*` path so opcode bytes do not fire the data-read hook.

The reference front end is `xvlknew_source` (GUI + CLI).
