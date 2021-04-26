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

#include <hve/arch/intel_x64/vcpu.h>
#include <printv.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>
#include <xen/domain.h>
#include <xen/evtchn.h>
#include <xen/hvm.h>
#include <xen/vcpu.h>

namespace microv {

bool xen_hvm_set_param(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto param = uvv->map_arg<xen_hvm_param_t>(uvv->rsi());

    if (param->index >= HVM_NR_PARAMS) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto domid = param->domid;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_hvm->set_param(vcpu, param.get());
    put_xen_domain(domid);

    return ret;
}

bool xen_hvm_get_param(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto param = uvv->map_arg<xen_hvm_param_t>(uvv->rsi());

    if (param->index >= HVM_NR_PARAMS) {
        uvv->set_rax(-EINVAL);
        return true;
    }

    auto domid = param->domid;
    if (domid == DOMID_SELF) {
        domid = vcpu->m_xen_dom->m_id;
    }

    auto dom = get_xen_domain(domid);
    if (!dom) {
        printv("%s: domid 0x%x not found\n", __func__, domid);
        uvv->set_rax(-ESRCH);
        return true;
    }

    auto ret = dom->m_hvm->get_param(vcpu, param.get());
    put_xen_domain(domid);

    return ret;
}

bool xen_hvm_pagetable_dying(xen_vcpu *vcpu)
{
    vcpu->m_uv_vcpu->set_rax(-ENOSYS);
    return true;
}

bool xen_hvm_set_evtchn_upcall_vector(xen_vcpu *vcpu)
{
    auto uvv = vcpu->m_uv_vcpu;
    auto arg = uvv->map_arg<xen_hvm_evtchn_upcall_vector_t>(uvv->rsi());
    auto vcpuid = arg->vcpu;
    auto vector = arg->vector;

    if (vcpuid == vcpu->m_id) {
        vcpu->m_upcall_vector = vector;
    } else {
        auto d = vcpu->m_xen_dom;
        auto v = d->get_xen_vcpu(vcpuid);
        if (!v) {
            printv("%s: xen vcpu %u not found\n", __func__, vcpuid);
            uvv->set_rax(-ESRCH);
            return true;
        }

        v->m_upcall_vector = vector;
        d->put_xen_vcpu(vcpuid);
    }

    uvv->set_rax(0);
    return true;
}

void xen_hvm::init_root_store_params()
{
    /*
     * Note both the store and console pages are accessed from this guest
     * (i.e. the root domain) and dom0. Right now, the pages are already
     * mapped into the root's EPT which is identity mapped, so no more
     * work is needed for the root to use them. The dom0 guest will map
     * in the xenstore page when the root is xs_introduce_domain()'d to
     * xenstore.
     */
    store_page = std::make_unique<uint8_t[]>(UV_PAGE_SIZE);

    evtchn_alloc_unbound_t store_chan = {
        .dom = DOMID_SELF, .remote_dom = 0, .port = 0};

    if (int rc = xen_dom->m_evtchn->alloc_unbound(&store_chan); rc) {
        printv("winpv: failed to alloc store port, rc=%d\n", rc);
        return;
    }

    const auto gpfn = xen_frame(g_mm->virtptr_to_physint(store_page.get()));
    const auto port = store_chan.port;

    printv("winpv: xenstore pfn=0x%lx, evtchn=%u\n", gpfn, port);

    params[HVM_PARAM_STORE_PFN] = gpfn;
    params[HVM_PARAM_STORE_EVTCHN] = port;

    xen_dom->m_memory->add_vmm_backed_page(
        gpfn, pg_perm_rw, pg_mtype_wb, store_page.get(), false);

    const auto gpa = xen_addr(gpfn);

    /* Add the identity mapping to the map whitelist */
    xen_dom->m_uv_dom->m_vmm_map_whitelist.try_emplace(gpa, gpa);
}

void xen_hvm::init_root_console_params()
{
    console_page = std::make_unique<uint8_t[]>(UV_PAGE_SIZE);

    evtchn_alloc_unbound_t console_chan = {
        .dom = DOMID_SELF, .remote_dom = 0, .port = 0};

    if (int rc = xen_dom->m_evtchn->alloc_unbound(&console_chan); rc) {
        printv("winpv: failed to alloc console port, rc=%d\n", rc);
        return;
    }

    const auto gpfn = xen_frame(g_mm->virtptr_to_physint(console_page.get()));
    const auto port = console_chan.port;

    printv("winpv: console pfn=0x%lx, evtchn=%u\n", gpfn, port);

    params[HVM_PARAM_CONSOLE_PFN] = gpfn;
    params[HVM_PARAM_CONSOLE_EVTCHN] = port;

    xen_dom->m_memory->add_vmm_backed_page(
        gpfn, pg_perm_rw, pg_mtype_wb, console_page.get(), false);

    const auto gpa = xen_addr(gpfn);

    /* Add the identity mapping to the map whitelist */
    xen_dom->m_uv_dom->m_vmm_map_whitelist.try_emplace(gpa, gpa);
}

xen_hvm::xen_hvm(xen_domain *dom, xen_memory *mem) : xen_dom{dom}, xen_mem{mem}
{
    if (xen_dom->m_uv_info->origin != domain_info::origin_root) {
        return;
    }

    if (xen_dom->m_id == DOMID_ROOTVM) {
        init_root_store_params();
        init_root_console_params();
    }
}

bool xen_hvm::set_param(xen_vcpu *vcpu, xen_hvm_param_t *p)
{
    int err = 0;

    switch (p->index) {
    case HVM_PARAM_CALLBACK_IRQ: {
        auto type = (p->value & HVM_PARAM_CALLBACK_IRQ_TYPE_MASK) >> 56;
        if (type != HVM_PARAM_CALLBACK_TYPE_VECTOR && type) {
            printv("%s: unsupported type: 0x%llx\n", __func__, type);
            err = -EINVAL;
            break;
        }

        auto vector = p->value & 0xFFU;
        xen_dom->m_upcall_vector = vector;

        printv("%s: domain upcall vector: 0x%lx\n", __func__, vector);

        /*
         * Go ahead and set each vcpu's m_upcall_vector to the value
         * given here if it hasn't been set yet. This allows the evtchn
         * code to reference the vcpu's m_upcall_vector in a uniform fashion.
         */
        for (auto i = 0; i < xen_dom->m_nr_vcpus; i++) {
            auto v = xen_dom->get_xen_vcpu(i);
            if (!v) {
                continue;
            }

            if (!v->m_upcall_vector) {
                v->m_upcall_vector = vector;
            }

            xen_dom->put_xen_vcpu(i);
        }

        break;
    }
    case HVM_PARAM_TIMER_MODE:
        err = xen_dom->set_timer_mode(p->value);
        break;
    case HVM_PARAM_NESTEDHVM:
    case HVM_PARAM_ALTP2M:
        if (p->value != 0) {
            err = -EINVAL;
        }
        break;
    case HVM_PARAM_PAE_ENABLED:
    case HVM_PARAM_IDENT_PT:
        break;
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_PAGING_RING_PFN:
    case HVM_PARAM_MONITOR_RING_PFN:
    case HVM_PARAM_SHARING_RING_PFN:
            try {
                xen_mem->add_page(p->value, pg_perm_rw, pg_mtype_wb, PAGE_SIZE_4K);
            } catch (std::exception &e) {
                //printv("ALERT: %s: add_page threw, what=%s\n", __func__, e.what());
            }
        break;
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_EVTCHN:
        break;
    default:
        bferror_nhex(0, "unhandled hvm set_param", p->index);
        return false;
    }

    if (!err) {
        params[p->index] = p->value;
    }

    vcpu->m_uv_vcpu->set_rax(err);
    return true;
}

uint64_t xen_hvm::get_param(uint32_t index) const
{
    expects(index < params.size());
    return params[index];
}

bool xen_hvm::get_param(xen_vcpu *vcpu, xen_hvm_param_t *p)
{
    int err = 0;
    auto uvv = vcpu->m_uv_vcpu;

    if (uvv->is_guest_vcpu()) {
        switch (p->index) {
        case HVM_PARAM_STORE_PFN:
        case HVM_PARAM_CONSOLE_PFN:
        case HVM_PARAM_PAE_ENABLED:
        case HVM_PARAM_NESTEDHVM:
        case HVM_PARAM_STORE_EVTCHN:
        case HVM_PARAM_CONSOLE_EVTCHN:
            break;
        default:
            bferror_nhex(0, "hvm get_param:", p->index);
            return false;
        }

        p->value = this->get_param(p->index);
        uvv->set_rax(err);

        return true;
    }

    if (uvv->is_root_vcpu()) {
        expects(vcpu->m_xen_dom->m_id == DOMID_ROOTVM);
        expects(this->xen_dom->m_id == DOMID_ROOTVM);

        switch (p->index) {
        case HVM_PARAM_STORE_EVTCHN:
        case HVM_PARAM_CONSOLE_EVTCHN:
            p->value = this->get_param(p->index);
            uvv->set_rax(0);
            return true;
        default:
            return false;
        }
    }

    printv("%s: ERROR invalid vcpu type\n", __func__);
    return false;
}

}
