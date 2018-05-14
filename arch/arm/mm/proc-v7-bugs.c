// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/smp.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/system_misc.h>

void cpu_v7_bugs_init(void);

static __maybe_unused void cpu_v7_check_auxcr_set(u32 mask, const char *msg)
{
	u32 aux_cr;

	asm("mrc p15, 0, %0, c1, c0, 1" : "=r" (aux_cr));

	if ((aux_cr & mask) != mask)
		pr_err("CPU%u: %s", smp_processor_id(), msg);
}

static void check_spectre_auxcr(u32 bit)
{
	if (IS_ENABLED(CONFIG_HARDEN_BRANCH_PREDICTOR))
		cpu_v7_check_auxcr_set(bit, "Spectre v2: firmware did not set auxiliary control register IBE bit, system vulnerable\n");
}

void cpu_v7_ca8_ibe(void)
{
	check_spectre_auxcr(BIT(6));
	cpu_v7_bugs_init();
}

void cpu_v7_ca15_ibe(void)
{
	check_spectre_auxcr(BIT(0));
	cpu_v7_bugs_init();
}

#ifdef CONFIG_HARDEN_BRANCH_PREDICTOR
void (*harden_branch_predictor)(void);

static void harden_branch_predictor_bpiall(void)
{
	write_sysreg(0, BPIALL);
}

static void harden_branch_predictor_iciallu(void)
{
	write_sysreg(0, ICIALLU);
}

void cpu_v7_bugs_init(void)
{
	const char *spectre_v2_method = NULL;

	if (harden_branch_predictor)
		return;

	switch (read_cpuid_part()) {
	case ARM_CPU_PART_CORTEX_A8:
	case ARM_CPU_PART_CORTEX_A9:
	case ARM_CPU_PART_CORTEX_A12:
	case ARM_CPU_PART_CORTEX_A17:
	case ARM_CPU_PART_CORTEX_A73:
	case ARM_CPU_PART_CORTEX_A75:
		harden_branch_predictor = harden_branch_predictor_bpiall;
		spectre_v2_method = "BPIALL";
		break;

	case ARM_CPU_PART_CORTEX_A15:
	case ARM_CPU_PART_BRAHMA_B15:
		harden_branch_predictor = harden_branch_predictor_iciallu;
		spectre_v2_method = "ICIALLU";
		break;
	}
	if (spectre_v2_method)
		pr_info("CPU: Spectre v2: using %s workaround\n",
			spectre_v2_method);
}
#endif
