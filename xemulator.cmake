# XEmulator - user-mode process emulator core.
#
# Multi-format (PE / ELF / Mach-O / MZ / COM), multi-OS (Windows / Linux / FreeBSD /
# macOS / MS-DOS) and multi-arch (x86 16/32/64, ARM, AArch64) emulator with a
# Windows-like virtual memory manager and QEMU-style dynamic-translation CPU cores.
#
# Usage (as a _mylibs source-list library):
#   include(${CMAKE_CURRENT_LIST_DIR}/../../_mylibs/XEmulator/xemulator.cmake)
#   add_executable(MyApp ${XEMULATOR_SOURCES} main.cpp ...)
# On Windows also link Wintrust and Crypt32 (XPE Authenticode parsing).
#
# Pulls in only the parts of _mylibs/Formats needed to parse the supported formats;
# the archive / DEX / PDF backends are intentionally excluded.

if(NOT DEFINED XEMULATOR_SOURCES)

set(XEMULATOR_FORMATS_DIR "${CMAKE_CURRENT_LIST_DIR}/../Formats")

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/arch)
include_directories(${CMAKE_CURRENT_LIST_DIR}/format)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os/winapi)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os/bios_int)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os/msdos_int)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os/linux_syscalls)
include_directories(${CMAKE_CURRENT_LIST_DIR}/os/bsd_syscalls)
include_directories(${XEMULATOR_FORMATS_DIR})
include_directories(${XEMULATOR_FORMATS_DIR}/exec)
include_directories(${XEMULATOR_FORMATS_DIR}/xsimd/src)

set(XEMULATOR_FORMATS_SOURCES
    ${XEMULATOR_FORMATS_DIR}/xbinary.cpp
    ${XEMULATOR_FORMATS_DIR}/xbinary.h
    ${XEMULATOR_FORMATS_DIR}/xiodevice.cpp
    ${XEMULATOR_FORMATS_DIR}/xiodevice.h
    ${XEMULATOR_FORMATS_DIR}/subdevice.cpp
    ${XEMULATOR_FORMATS_DIR}/subdevice.h
    ${XEMULATOR_FORMATS_DIR}/exec/xmsdos.cpp
    ${XEMULATOR_FORMATS_DIR}/exec/xmsdos.h
    ${XEMULATOR_FORMATS_DIR}/exec/xpe.cpp
    ${XEMULATOR_FORMATS_DIR}/exec/xpe.h
    ${XEMULATOR_FORMATS_DIR}/exec/xcliassembly.cpp
    ${XEMULATOR_FORMATS_DIR}/exec/xcliassembly.h
    ${XEMULATOR_FORMATS_DIR}/exec/xelf.cpp
    ${XEMULATOR_FORMATS_DIR}/exec/xelf.h
    ${XEMULATOR_FORMATS_DIR}/exec/xmach.cpp
    ${XEMULATOR_FORMATS_DIR}/exec/xmach.h
)

set(XEMULATOR_SOURCES
    ${XEMULATOR_FORMATS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xemuemulator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemuemulator.h
    ${CMAKE_CURRENT_LIST_DIR}/xemumemorymanager.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemumemorymanager.h
    ${CMAKE_CURRENT_LIST_DIR}/xemuregisters.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xemuregisters.h
    ${CMAKE_CURRENT_LIST_DIR}/xemutypes.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarch.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemutb.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuopcache.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemux86.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemux86.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarm64.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarm64.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xemuarm.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemufileformat.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemufileformat.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemugenericformat.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemugenericformat.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemupe.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemupe.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemuelf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemuelf.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemumacho.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemumacho.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemumsdos.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemumsdos.h
    ${CMAKE_CURRENT_LIST_DIR}/format/xemucom.cpp
    ${CMAKE_CURRENT_LIST_DIR}/format/xemucom.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuoperatingsystem.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuoperatingsystem.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemusyscalls.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuwindows.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuwindows.h
    ${CMAKE_CURRENT_LIST_DIR}/os/winapi/xemuwinapi.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/winapi/xemuwinapi.h
    ${CMAKE_CURRENT_LIST_DIR}/os/bios_int/xemubiosint.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/bios_int/xemubiosint.h
    ${CMAKE_CURRENT_LIST_DIR}/os/msdos_int/xemumsdosint.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/msdos_int/xemumsdosint.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuunixos.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemuunixos.h
    ${CMAKE_CURRENT_LIST_DIR}/os/linux_syscalls/xemulinuxsyscalls.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/linux_syscalls/xemulinuxsyscalls.h
    ${CMAKE_CURRENT_LIST_DIR}/os/bsd_syscalls/xemubsdsyscalls.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/bsd_syscalls/xemubsdsyscalls.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemulinux.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemulinux.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemufreebsd.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemufreebsd.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemumacos.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemumacos.h
    ${CMAKE_CURRENT_LIST_DIR}/os/xemudos.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os/xemudos.h
)

endif()
