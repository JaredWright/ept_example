//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfvmm/vcpu/vcpu_factory.h>
#include <eapis/vcpu/arch/intel_x64/vcpu.h>
#include <intrinsics.h>
#include <eapis/hve/arch/intel_x64/ept.h>

namespace ept = eapis::intel_x64::ept;
namespace vmcs = ::intel_x64::vmcs;

namespace ept_example
{

class ept_vcpu : public eapis::intel_x64::vcpu
{
public:

    /// Default Constructor
    ///
    /// @expects
    /// @ensures
    ///
    ept_vcpu(vcpuid::type id);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ept_vcpu();

private:

    // An EPT memory map that manages the extended page tables for this example
    std::unique_ptr<ept::memory_map> m_mem_map = std::make_unique<ept::memory_map>();

    // A 4KB page that this example traps read access to
    std::unique_ptr<uint8_t[]> m_page_to_trap = std::make_unique<uint8_t[]>(ept::page_size_4k);

    // The host physical address of the page the be trapped
    ept::hpa_t m_page_to_trap_hpa = g_mm->virtptr_to_physint(m_page_to_trap.get());

private:

    /// Sets up exit handlers for EPT read/write/execute violations and EPT
    /// misconfigurations
    ///
    /// @expects
    /// @ensures
    ///
    void register_ept_exit_handlers();

    /// Sets up the EPT memory map (i.e. the extended page tables) to pass
    /// through all access except to a single 4KB page managed by this example
    ///
    /// @expects
    /// @ensures
    ///
    void setup_memory_map();

    /// Enables EPT using this example's EPT memory map
    ///
    /// @expects
    /// @ensures
    ///
    void enable_ept();

    /// Exit handler for EPT read violations
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Always returns true to indicate the EPT violation was handled
    ///
    bool handle_read_violation(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info);

    /// Exit handler for EPT write violations
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Always returns false to indicate the EPT violation was handled
    ///
    bool handle_write_violation(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info);

    /// Exit handler for EPT execute violations
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Always returns false to indicate the EPT violation was handled
    ///
    bool handle_execute_violation(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        eapis::intel_x64::ept_violation::info_t &info);

    /// Exit handler for EPT misconfigurations
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Always returns false to indicate the EPT misconfiguration was handled
    ///
    bool handle_ept_misconfiguration (gsl::not_null<vmcs_t *> vmcs,
        eapis::intel_x64::ept_misconfiguration::info_t &info);

};

}
