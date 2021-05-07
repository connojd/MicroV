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

#ifndef MICROV_IOMMU_H
#define MICROV_IOMMU_H

#include <array>
#include <bftypes.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <hve/arch/intel_x64/domain.h>
#include <unordered_map>
#include <vector>

#include <asm/mmio.h>

#include "dmar.h"
#include "entry.h"
#include "regs.h"
#include "../pci/cfg.h"

namespace microv::intel_x64 {
class domain;
}

namespace microv {

struct pci_dev;
using namespace iommu_regs;

class iommu {
public:
    static constexpr auto table_size =
        UV_PAGE_SIZE / sizeof(struct iommu_entry);
    using entry_t = struct iommu_entry;
    using dom_t = class microv::intel_x64::domain;
    using bus_t = uint32_t;

    void ack_faults();
    void enable_dma_remapping();
    void map_bus(bus_t bus, dom_t *dom);
    void map_bdf(bus_t bus, uint32_t devfn, dom_t *dom);
    void flush_iotlb_page_range(const dom_t *dom, uint64_t gpa, uint64_t bytes);

    bool dma_remapping_enabled() const noexcept
    {
        return m_remapping_dma;
    }

    bool coherent_page_walk() const noexcept
    {
        return (m_ecap & ecap_c_mask) >> ecap_c_from;
    }

    bool snoop_ctl() const noexcept
    {
        return (m_ecap & ecap_sc_mask) >> ecap_sc_from;
    }

    bool psi_supported() const noexcept
    {
        return m_psi_supported;
    }

    void flush_iotlb_domain(const dom_t *dom)
    {
        this->flush_iotlb(dom);
    }

    bool has_catchall_scope() const noexcept
    {
        return m_scope_all;
    }

    ~iommu() = default;
    iommu(struct drhd *drhd, uint32_t id);
    iommu(iommu &&) = default;
    iommu(const iommu &) = delete;
    iommu &operator=(iommu &&) = default;
    iommu &operator=(const iommu &) = delete;

private:
    /* Invalidation granularity values */
    enum {
        IOTLB_INVG_RESERVED,
        IOTLB_INVG_GLOBAL,
        IOTLB_INVG_DOMAIN,
        IOTLB_INVG_PAGE
    };

    uint32_t m_id{};
    page_ptr<entry_t> m_root;
    std::unordered_map<domainid_t, page_ptr<entry_t>> m_dom_ctxt_map;
    std::unordered_map<bus_t, page_ptr<entry_t>> m_bdf_ctxt_map;
    struct drhd *m_drhd{};
    struct dmar_devscope *m_scope{};
    uintptr_t m_reg_hva{};
    uint32_t m_ver{};
    uint64_t m_cap{};
    uint64_t m_ecap{};
    uint8_t m_mgaw{};
    uint8_t m_sagaw{};
    uint8_t m_aw{};
    uint8_t m_did_bits{};
    uint8_t m_max_slpg_size{};
    uint8_t m_mamv{};

    size_t m_iotlb_reg_off{};
    static constexpr size_t iotlb_reg_num = 2;
    static constexpr size_t iotlb_reg_len = 8;
    static constexpr size_t iotlb_reg_bytes = iotlb_reg_num * iotlb_reg_len;

    size_t m_frcd_reg_off{};
    size_t m_frcd_reg_num{};
    size_t m_frcd_reg_bytes{};
    size_t m_reg_page_count{};
    static constexpr size_t frcd_reg_len = 16;

    std::vector<struct pci_dev *> m_pci_devs{};
    bool m_scope_all{};
    bool m_remapping_dma{};
    bool m_psi_supported{};

    uint64_t read64(size_t offset) const
    {
        uintptr_t addr = m_reg_hva + offset;
        return ::microv::read64((volatile void __iomem *)addr);
    }

    uint32_t read32(size_t offset) const
    {
        uintptr_t addr = m_reg_hva + offset;
        return ::microv::read32((volatile void __iomem *)addr);
    }

    void write64(size_t offset, uint64_t val)
    {
        uintptr_t addr = m_reg_hva + offset;
        ::microv::write64(val, (volatile void __iomem *)addr);
    }

    void write32(size_t offset, uint32_t val)
    {
        uintptr_t addr = m_reg_hva + offset;
        ::microv::write32(val, (volatile void __iomem *)addr);
    }

    uint32_t read_gcmd()
    {
        return read32(gcmd_offset);
    }
    uint32_t read_gsts()
    {
        return read32(gsts_offset);
    }
    uint64_t read_rtaddr()
    {
        return read64(rtaddr_offset);
    }
    uint64_t read_ccmd()
    {
        return read64(ccmd_offset);
    }
    uint64_t read_iotlb()
    {
        return read64(m_iotlb_reg_off + 8);
    }
    uint64_t read_iqa()
    {
        return read64(iqa_offset);
    }
    uint64_t read_iqt()
    {
        return read64(iqt_offset);
    }
    uint64_t read_iqh()
    {
        return read64(iqh_offset);
    }

    void write_gcmd(uint32_t val)
    {
        write32(gcmd_offset, val);
    }
    void write_rtaddr(uint64_t val)
    {
        write64(rtaddr_offset, val);
    }
    void write_ccmd(uint64_t val)
    {
        write64(ccmd_offset, val);
    }
    void write_iotlb(uint64_t val)
    {
        write64(m_iotlb_reg_off + 8, val);
    }
    void write_iva(uint64_t val)
    {
        write64(m_iotlb_reg_off, val);
    }

    void map_regs_into_vmm();
    void unmap_regs_from_root_dom();
    void init_regs();
    void dump_devices();
    void bind_devices();
    void bind_device(struct pci_dev *pdev);
    void bind_bus(uint32_t bus);
    void int_remap_disable();
    void dma_remap_disable();
    void qinval_disable();
    void qinval_quiesce();

    size_t nr_domains() const
    {
        return 1UL << m_did_bits;
    }

    size_t did(const dom_t *dom) const
    {
        /*
         * Remapping hardware reserves a DID of 0 if caching mode (CAP.CM) is
         * set, so we add CM to each domain::id to get the DID that goes in the
         * table entry.
         */
        return dom->id() + ((m_cap & cap_cm_mask) >> cap_cm_from);
    }

    void clflush_range(void *p, unsigned int bytes);

    void flush_ctx_cache();
    void flush_ctx_cache(const dom_t *dom);
    void flush_ctx_cache(const dom_t *dom,
                         uint32_t bus,
                         uint32_t dev,
                         uint32_t fun);

    uint64_t flush_iotlb();
    uint64_t flush_iotlb(const dom_t *dom);
    uint64_t flush_iotlb_4k(const dom_t *dom,
                            uint64_t addr,
                            bool flush_nonleaf);
    uint64_t flush_iotlb_2m(const dom_t *dom,
                            uint64_t addr,
                            bool flush_nonleaf);
    uint64_t flush_iotlb_page_order(const dom_t *dom,
                                    uint64_t addr,
                                    bool flush_nonleaf,
                                    uint64_t order);
};

extern char *mcfg_hva;
extern size_t mcfg_len;

void init_vtd();
void iommu_dump();

}

#endif
