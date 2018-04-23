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

#include "ept_example.h"

namespace ept_example
{

ept_vcpu::ept_vcpu(vcpuid::type id) :
    eapis::intel_x64::vcpu{id}
{
    this->register_ept_exit_handlers();
    this->setup_memory_map();
    this->enable_ept();
    bfdebug_info(0, "EPT example VMM loaded, unload to cause an EPT violation");
}

ept_vcpu::~ept_vcpu()
{
    // The VCPU's destructor runs in VMX-non-root operation, so any
    // attempt to read from this example's trapped page will cause and EPT
    // read violation.
    auto val = m_page_to_trap[0];
    bfdebug_nhex(0, "Value read from trapped page", val);
}

void
ept_vcpu::register_ept_exit_handlers()
{
    auto hve = this->hve();

    hve->add_ept_read_violation_handler(
        eapis::intel_x64::ept_violation::handler_delegate_t::create<ept_vcpu, &ept_vcpu::handle_read_violation>(this)
    );

    hve->add_ept_write_violation_handler(
        eapis::intel_x64::ept_violation::handler_delegate_t::create<ept_vcpu, &ept_vcpu::handle_write_violation>(this)
    );

    hve->add_ept_execute_violation_handler(
        eapis::intel_x64::ept_violation::handler_delegate_t::create<ept_vcpu, &ept_vcpu::handle_execute_violation>(this)
    );

    hve->add_ept_misconfiguration_handler(
        eapis::intel_x64::ept_misconfiguration::handler_delegate_t::create<ept_vcpu, &ept_vcpu::handle_ept_misconfiguration>(this)
    );

    hve->ept_misconfiguration()->enable_log();
    hve->ept_violation()->enable_log();
}

void
ept_vcpu::setup_memory_map()
{
    // Set up pass-through identity mapping (gpa == hpa) for the entire
    // address space of the guest with 1GB page granularity (assumed to be
    // 64 GB in size)
    const auto m_num_1g_pages = 64ULL;
    ept::identity_map_n_contig_1g(*m_mem_map, 0, m_num_1g_pages, ept::epte::memory_attr::wb_pt);

    // Remap the 1GB region that contains our page of interest at the 4KB
    // granularity.
    auto region_begin = m_page_to_trap_hpa & 0xffffffffc0000000ULL;
    auto region_end = region_begin + (ept::page_size_1g - 1);
    ept::unmap(*m_mem_map, region_begin);
    ept::identity_map_range_4k(*m_mem_map, region_begin, region_end, ept::epte::memory_attr::wb_pt);

    // Set permissions of the page we allocated to execute only, so that any
    // reads or writes to that page will be trapped to our exit handlers
    auto &shadow_page_entry = m_mem_map->gpa_to_epte(m_page_to_trap_hpa);
    ept::epte::memory_attr::set(shadow_page_entry, ept::epte::memory_attr::wb_eo);
}

void
ept_vcpu::enable_ept()
{
    auto eptp = ept::eptp(*m_mem_map);
    vmcs::ept_pointer::set(eptp);
    vmcs::secondary_processor_based_vm_execution_controls::enable_ept::enable();
}

bool
ept_vcpu::handle_read_violation(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    eapis::intel_x64::ept_violation::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    bfdebug_nhex(0, "Caught ept read violation @ gpa: ", info.gpa);

    // When we catch an EPT read violation, reset the trapped page's access
    // rights to pass thorugh without advancing the guest's instruction
    // pointer. This will cause the read to happen again without causing a
    // VM exit
    auto &ept_entry = m_mem_map->gpa_to_epte(info.gpa);
    ept::epte::memory_attr::set(ept_entry, ept::epte::memory_attr::wb_pt);
    info.ignore_advance = true;

    // Set a value to be observed at the trapped address
    m_page_to_trap[0] = 0xa5;

    return true;
}

bool
ept_vcpu::handle_write_violation(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    eapis::intel_x64::ept_violation::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    // TODO: You can handle EPT write violations here
    bfdebug_nhex(0, "Unhandled ept write violation @ gpa: ", info.gpa);

    return false;
}

bool
ept_vcpu::handle_execute_violation(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    eapis::intel_x64::ept_violation::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    // TODO: You can handle EPT execute violations here
    bfdebug_nhex(0, "Unhandled ept execute violation @ gpa: ", info.gpa);

    return false;
}

bool
ept_vcpu::handle_ept_misconfiguration (
    gsl::not_null<vmcs_t *> vmcs,
    eapis::intel_x64::ept_misconfiguration::info_t &info)
{
    bfignored(vmcs);
    bfignored(info);

    // TODO: You can handle EPT misconfigurations here
    bfdebug_nhex(0, "Unhandled ept misconfiguration @ gpa: ", info.gpa);

    return false;
}

}

namespace bfvmm
{

WEAK_SYM std::unique_ptr<vcpu>
bfvmm::vcpu_factory::make_vcpu(vcpuid::type vcpuid, bfobject *obj)
{
    bfignored(obj);
    return std::make_unique<ept_example::ept_vcpu>(vcpuid);
}

}
