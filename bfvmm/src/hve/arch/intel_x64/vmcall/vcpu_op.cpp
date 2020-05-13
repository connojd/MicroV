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
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/vcpu_op.h>

extern bool trace_vmexits;

struct vmexit_desc {
    uint32_t reason;
    uint64_t guest_cr3;
    uint64_t data[2];
} __attribute__((packed));

extern struct vmexit_desc exit_reason_list[64];
extern uint32_t exit_reason_head;

static void dump_vmexit_desc(const struct vmexit_desc *desc)
{
    using namespace vmcs_n::exit_reason::basic_exit_reason;

    auto pstr = (desc->reason & (1U << 31)) ? "p" : "c";
    auto reason = desc->reason;

    reason &= ~(1U << 31);

    switch (reason) {
    case cpuid:
        printf("[%s] %s: cr3=0x%lx eax=0x%lx ecx=0x%lx\n",
               pstr, basic_exit_reason_description(reason), desc->guest_cr3,
               desc->data[0], desc->data[1]);
        break;
    case external_interrupt:
        printf("[%s] %s: cr3=0x%lx exitinfo:0x%lx\n",
               pstr, basic_exit_reason_description(reason), desc->guest_cr3,
               desc->data[0]);
        break;
    case wrmsr:
        printf("[%s] %s: cr3=0x%lx msr=0x%lx val=0x%lx\n",
               pstr, basic_exit_reason_description(reason), desc->guest_cr3,
               desc->data[1], desc->data[0]);
        break;
    case vmcall:
        printf("[%s] %s: cr3=0x%lx rax=0x%lx\n",
               pstr, basic_exit_reason_description(reason), desc->guest_cr3,
               desc->data[0]);
        break;
    default:
        printf("[%s] %s: cr3=0x%lx\n",
               pstr, basic_exit_reason_description(reason), desc->guest_cr3);
        break;
    }
}

static void dump_vmexits()
{
    using namespace vmcs_n::exit_reason::basic_exit_reason;

    printf("exit reasons (most recent first):\n");

    if (exit_reason_head > 0) {
        for (int i = exit_reason_head - 1; i >= 0; --i) {
            dump_vmexit_desc(&exit_reason_list[i]);
        }

        for (int i = 63; i >= exit_reason_head; --i) {
            dump_vmexit_desc(&exit_reason_list[i]);
        }
    } else {
        for (int i = 63; i >= exit_reason_head; --i) {
            dump_vmexit_desc(&exit_reason_list[i]);
        }
    }

    printf("\n");
    printf("ia32_kernel_gs_base: 0x%lx\n", ::x64::msrs::ia32_kernel_gs_base::get());
    printf("ia32_gs_base: 0x%lx\n", ::intel_x64::msrs::ia32_gs_base::get());
    printf("ia32_fs_base: 0x%lx\n", ::intel_x64::msrs::ia32_fs_base::get());
    printf("ia32_xss_msr: 0x%lx\n", ::intel_x64::msrs::ia32_xss::get());
}

namespace boxy::intel_x64
{

vcpu_op_handler::vcpu_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
//    if (vcpu->is_domU()) {
//        return;
//    }

    vcpu->add_vmcall_handler({&vcpu_op_handler::dispatch, this});
}

void
vcpu_op_handler::vcpu_op__create_vcpu(vcpu *vcpu)
{
    vmcs_n::guest_cr4::dump(0);
    vmcs_n::cr4_guest_host_mask::dump(0);
    vmcs_n::cr4_read_shadow::dump(0);

    vmcs_n::guest_cr0::dump(0);
    vmcs_n::cr0_guest_host_mask::dump(0);
    vmcs_n::cr0_read_shadow::dump(0);

    ::intel_x64::msrs::ia32_misc_enable::dump(0);

    auto leaf7 = ::x64::cpuid::get(7, 0, 0, 0);
    bfdebug_nhex(0, "cpuid leaf 7 ebx", leaf7.rbx);
    bfdebug_nhex(0, "cpuid leaf 7 ecx", leaf7.rcx);
    bfdebug_nhex(0, "cpuid leaf 7 edx", leaf7.rdx);

    try {
        vcpu->set_rax(bfvmm::vcpu::generate_vcpuid());
        g_vcm->create(vcpu->rax(), get_domain(vcpu->rbx()));
    }
    catchall({
        vcpu->set_rax(INVALID_VCPUID);
    })
}

void
vcpu_op_handler::vcpu_op__kill_vcpu(vcpu *vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rbx());
        child_vcpu->kill();

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vcpu_op_handler::vcpu_op__destroy_vcpu(vcpu *vcpu)
{
    try {
        g_vcm->destroy(vcpu->rbx());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vcpu_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != hypercall_enum_vcpu_op) {
        return false;
    }

    switch (vcpu->rax()) {
        case hypercall_enum_vcpu_op__create_vcpu:
            this->vcpu_op__create_vcpu(vcpu);
            return true;

        case hypercall_enum_vcpu_op__kill_vcpu:
            this->vcpu_op__kill_vcpu(vcpu);
            return true;

        case hypercall_enum_vcpu_op__destroy_vcpu:
            this->vcpu_op__destroy_vcpu(vcpu);
            return true;

        case hypercall_enum_vcpu_op__start_vmexit_trace:
            trace_vmexits = true;
            vcpu->set_rax(SUCCESS);
            return true;

        case hypercall_enum_vcpu_op__stop_vmexit_trace:
            trace_vmexits = false;
            vcpu->set_rax(SUCCESS);
            return true;

        case hypercall_enum_vcpu_op__dump_kernel_fault:
	    bfalert_info(0, "FATAL SEGFAULT FROM GUEST:");

	    // Dump linux guest state
	    vmcs_n::guest_cr4::dump(0);
	    vmcs_n::cr4_guest_host_mask::dump(0);
	    vmcs_n::cr4_read_shadow::dump(0);

	    vmcs_n::guest_cr0::dump(0);
	    vmcs_n::cr0_guest_host_mask::dump(0);
	    vmcs_n::cr0_read_shadow::dump(0);

	    // Disable exit tracing
	    trace_vmexits = false;

            dump_vmexits();

            return true;

        default:
            break;
    }

    throw std::runtime_error("unknown vcpu opcode");
}

}
