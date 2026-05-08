#pragma once
#include "../driver/driver.hpp"
#include <cstdint>

namespace Decrypt {
    inline uintptr_t Il2cppGetHandle(int32_t ObjectHandleID) {
        uint64_t rdi_1 = (uint64_t)(ObjectHandleID >> 3);
        uint64_t rcx_1 = (uint64_t)((ObjectHandleID & 7) - 1);
        uintptr_t gameAssembly = driver::vulnerable()->exported_functions().get_module_dll(L"GameAssembly.dll");
        uintptr_t ObjectArray = driver::vulnerable()->get().read_physical_memory<uintptr_t>((rcx_1 * 0x28) + gameAssembly + 0xdb6ee20 + 0x8) + (rdi_1 << 3);

        if (driver::vulnerable()->get().read_physical_memory<uint8_t>((rcx_1 * 0x28) + gameAssembly + 0xdb6ee20 + 0x14) > 1)
            return driver::vulnerable()->get().read_physical_memory<uintptr_t>(ObjectArray);

        uint32_t eax = driver::vulnerable()->get().read_physical_memory<uint32_t>(ObjectArray);
        return static_cast<uintptr_t>(~eax);
    }

    inline uint64_t BaseNetworkableKey(uint64_t address) {
        uint32_t v33[3];
        uint32_t* rdx = (uint32_t*)v33;

        uint32_t readValue = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + 0x18);
        v33[0] = readValue;

        uint32_t r8d = 2;
        do
        {
            uint32_t eax = *rdx;
            rdx = (uint32_t*)((char*)rdx + 4);
            eax ^= 0x8099F03B;
            eax += 0xD170F063;
            uint32_t ecx = eax;
            eax <<= 0x0B;
            ecx >>= 0x15;
            ecx |= eax;
            ecx += 0x179959E1;
            *(rdx - 1) = ecx;
            r8d -= 1;
        } while (r8d);

        return Il2cppGetHandle(v33[0]);
    }

    inline uint64_t DecryptList(uint64_t address) {
        uint32_t v35[3];
        uint32_t* rdx = (uint32_t*)v35;
        v35[0] = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + 0x18);

        uint32_t r8d = 2;
        do
        {
            uint32_t ecx = *rdx;
            rdx = (uint32_t*)((char*)rdx + 4);
            ecx ^= 0xFDB6056B;
            uint32_t eax = ecx;
            ecx <<= 0x06;
            eax >>= 0x1A;
            eax |= ecx;
            eax += 0xC2BF6C0D;
            ecx = eax;
            eax <<= 0x0B;
            ecx >>= 0x15;
            ecx |= eax;
            *(rdx - 1) = ecx;
            r8d -= 1;
        } while (r8d);

        return Il2cppGetHandle(v35[0]);
    }
}
