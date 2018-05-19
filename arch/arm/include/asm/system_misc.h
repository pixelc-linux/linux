/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM_SYSTEM_MISC_H
#define __ASM_ARM_SYSTEM_MISC_H

#ifndef __ASSEMBLY__

#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/irqflags.h>
#include <linux/reboot.h>

extern void cpu_init(void);

void soft_restart(unsigned long);
extern void (*arm_pm_restart)(enum reboot_mode reboot_mode, const char *cmd);
extern void (*arm_pm_idle)(void);

#ifdef CONFIG_HARDEN_BRANCH_PREDICTOR
extern void (*harden_branch_predictor)(void);
#define harden_branch_predictor() \
	do { if (harden_branch_predictor) harden_branch_predictor(); } while (0)
#else
#define harden_branch_predictor() do { } while (0)
#endif

#define UDBG_UNDEFINED	(1 << 0)
#define UDBG_SYSCALL	(1 << 1)
#define UDBG_BADABORT	(1 << 2)
#define UDBG_SEGV	(1 << 3)
#define UDBG_BUS	(1 << 4)

extern unsigned int user_debug;

static inline int handle_guest_sea(phys_addr_t addr, unsigned int esr)
{
	return -1;
}

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_ARM_SYSTEM_MISC_H */
