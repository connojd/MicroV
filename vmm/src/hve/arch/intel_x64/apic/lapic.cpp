//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <arch/intel_x64/apic/lapic.h>
#include <bfvmm/memory_manager/arch/x64/cr3/mmap.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/apic/lapic.h>
#include <printv.h>

namespace microv::intel_x64 {

using namespace ::intel_x64::msrs;
using namespace ::bfvmm::x64;

static constexpr size_t xapic_bytes{4096};
static constexpr uintptr_t x2apic_base{0x800};

/* Register offsets */
static constexpr uint32_t ID_REG = 0x02;
static constexpr uint32_t EOI_REG = 0x0B;
static constexpr uint32_t LDR_REG = 0x0D;
static constexpr uint32_t DFR_REG = 0x0E;
static constexpr uint32_t ICR_REG = 0x30;

/* x2APIC operations */
static uint32_t x2apic_read(uintptr_t base, uint32_t reg)
{
    return gsl::narrow_cast<uint32_t>(::x64::msrs::get(base | reg));
}

static void x2apic_write(uintptr_t base, uint32_t reg, uint32_t val)
{
    ::x64::msrs::set(base | reg, val);
}

static void x2apic_write_icr(uintptr_t base, uint64_t val)
{
    bfignored(base);
    ia32_x2apic_icr::set(val);
}

static void x2apic_write_eoi(uintptr_t base)
{
    bfignored(base);
    ia32_x2apic_eoi::set(0);
}

/* xAPIC operations */
static uint32_t xapic_read(uintptr_t base, uint32_t reg)
{
    return *reinterpret_cast<volatile uint32_t *>(base | (reg << 4));
}

static void xapic_write(uintptr_t base, uint32_t reg, uint32_t val)
{
    *reinterpret_cast<volatile uint32_t *>(base | (reg << 4)) = val;
}

static void xapic_write_icr(uintptr_t base, uint64_t val)
{
    constexpr uintptr_t icr_hi = 0x310;
    constexpr uintptr_t icr_lo = 0x300;

    auto hi_addr = reinterpret_cast<volatile uint32_t *>(base | icr_hi);
    auto lo_addr = reinterpret_cast<volatile uint32_t *>(base | icr_lo);

    *hi_addr = (uint32_t)(val >> 32);
    ::intel_x64::wmb();
    *lo_addr = (uint32_t)val;
}

static void xapic_write_eoi(uintptr_t base)
{
    xapic_write(base, EOI_REG, 0);
}

/* class implementation */

lapic::lapic(vcpu *vcpu) : m_vcpu{vcpu}
{
    expects(vcpu->is_dom0());

    m_base_msr = ia32_apic_base::get();
    auto state = ia32_apic_base::state::get(m_base_msr);

    switch (state) {
    case ia32_apic_base::state::xapic:
        init_xapic();
        break;
    case ia32_apic_base::state::x2apic:
        init_x2apic();
        break;
    default:
        bferror_nhex(0, "Unsupported lapic state", state);
        throw std::runtime_error("Unsupported lapic state");
    }

    vcpu->emulate_wrmsr(ia32_apic_base::addr,
                        {&lapic::emulate_wrmsr_base, this});

    const auto id = this->read(ID_REG);
    m_local_id = (m_xapic_hva) ? id >> 24 : id;

    expects(m_local_id < 0xFF);
}

void lapic::init_xapic()
{
    auto msr_hpa = ia32_apic_base::apic_base::get(m_base_msr);
    auto hpa = m_vcpu->gpa_to_hpa(msr_hpa).first;
    ensures(hpa == msr_hpa);

    m_xapic_hpa = hpa;
    m_xapic_hva = reinterpret_cast<uint32_t *>(g_mm->alloc_map(xapic_bytes));

    g_cr3->map_4k(m_xapic_hva,
                  m_xapic_hpa,
                  cr3::mmap::attr_type::read_write,
                  cr3::mmap::memory_type::uncacheable);

    m_base_addr = reinterpret_cast<uintptr_t>(m_xapic_hva);
    m_ops.write = xapic_write;
    m_ops.write_icr = xapic_write_icr;
    m_ops.write_eoi = xapic_write_eoi;
    m_ops.read = xapic_read;
}

void lapic::init_x2apic()
{
    m_base_addr = x2apic_base;
    m_ops.write = x2apic_write;
    m_ops.write_icr = x2apic_write_icr;
    m_ops.write_eoi = x2apic_write_eoi;
    m_ops.read = x2apic_read;
}

void lapic::write(uint32_t reg, uint32_t val)
{
    m_ops.write(m_base_addr, reg, val);
}

uint32_t lapic::read(uint32_t reg) const
{
    return m_ops.read(m_base_addr, reg);
}

void lapic::write_icr(uint64_t val)
{
    m_ops.write_icr(m_base_addr, val);
}

void lapic::write_eoi()
{
    m_ops.write_eoi(m_base_addr);
}

void lapic::write_ipi_fixed(uint64_t vector, uint64_t dest_vcpuid)
{
    expects(m_vcpu->is_root_vcpu());
    expects(m_vcpu->id() == dest_vcpuid);
    expects(this->is_xapic());

    /*
     * NOTE: this is only needed for xAPIC. We should restructure
     * the access_ops so that x2APIC doesn't have to pay for this
     */
    std::lock_guard lock(m_mutex);

    /*
     * Send the IPI in physical destination mode using the
     * cached local APIC ID of this lapic.
     */
    uint64_t icr = 0U;

    icr |= ((uint64_t)(this->local_id()) << 56);
    icr |= (1UL << 14);
    icr |= vector & 0xFF;

    this->write_icr(icr);
}

void lapic::write_ipi_init_all_not_self()
{
    expects(m_vcpu->is_root_vcpu());

    std::lock_guard lock(m_mutex);

    uint64_t icr = 0U;

    icr |= (icr_delivery_mode::init << 8);
    icr |= (icr_level::assert << 14);
    icr |= (icr_trigger_mode::edge << 15);
    icr |= (icr_destination_shorthand::all_not_self << 18);

    this->write_icr(icr);
}

/*
 * NOTE: this must *not* do an APIC access. MSI mapping code assumes this
 * function does not touch the actual APIC. Instead the ID value that was
 * cached at construction is returned.
 */
uint32_t lapic::local_id() const
{
    return m_local_id;
}

uint32_t lapic::logical_id() const
{
    const auto reg = this->read(LDR_REG);
    return (m_xapic_hva) ? reg >> 24 : reg;
}

int lapic::dest_model() const
{
    expects(this->is_xapic());
    return this->read(DFR_REG) >> 28;
}

bool lapic::logical_dest() const
{
    return (this->read(ICR_REG) >> 11) & 1;
}

bool lapic::is_xapic() const
{
    namespace state = ia32_apic_base::state;
    return state::get(m_base_msr) == state::xapic;
}

bool lapic::is_x2apic() const
{
    namespace state = ia32_apic_base::state;
    return state::get(m_base_msr) == state::x2apic;
}

bool lapic::emulate_wrmsr_base(base_vcpu *v, wrmsr_handler::info_t &info)
{
    namespace base = ia32_apic_base;

    const auto old_state = base::state::get(m_base_msr);
    const auto new_state = base::state::get(info.val);

    const auto old_hpa = m_xapic_hpa;
    const auto new_hpa = base::apic_base::get(info.val);

    printv("%s: old_state:%u, old_hpa:%lx, new_state:%u, new_hpa:%lx\n",
           __func__, old_state, old_hpa, new_state, new_hpa);

    switch (new_state) {
    case base::state::x2apic:
        if (old_state == base::state::xapic) {
            g_cr3->unmap(m_xapic_hva);
            g_mm->free_map(m_xapic_hva);
            m_xapic_hva = 0;
            m_xapic_hpa = 0;
            this->init_x2apic();
            m_base_msr = info.val;
            base::set(info.val);
        }
        break;
    case base::state::xapic:
        if (old_hpa != new_hpa) {
            if (m_xapic_hva) {
                m_xapic_hpa = new_hpa;
                g_cr3->unmap(m_xapic_hva);
                g_cr3->map_4k(m_xapic_hva,
                              m_xapic_hpa,
                              cr3::mmap::attr_type::read_write,
                              cr3::mmap::memory_type::uncacheable);
                ::x64::tlb::invlpg(m_xapic_hva);
                m_base_msr = info.val;
                base::set(info.val);
                ensures(m_vcpu->gpa_to_hpa(new_hpa).first == new_hpa);
            } else {
                m_base_msr = info.val;
                this->init_xapic();
                base::set(info.val);

                const auto id = this->read(ID_REG);
                printv("%s: xAPIC ID: %u, existing ID: %u\n", __func__, id >> 24, m_local_id);
                m_local_id = id;
            }
        }
        break;
    default:
        printv("%s: lapic reset\n", __func__);
        m_base_msr = info.val;
        base::set(info.val);
        break;
    }

    return true;
}

}
