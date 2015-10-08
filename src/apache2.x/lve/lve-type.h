#ifndef _LVE_TYPE_H_

#define _LVE_TYPE_H_

#include <unistd.h>
#include <stdint.h>

enum liblve_enter_flags {
	LVE_NO_UBC	= 1 << 0,
	LVE_NO_NAMESPACE = 1 << 1,
	LVE_NO_MAXENTER	= 1 << 2,
	LVE_SILENCE	= 1 << 3,
};

enum liblve_ve_flags {
	LVE_VE_DISABLE  = 1 << 0, /* disable to enter to that ve */
};

enum liblve_ve_fails {
	LVE_FAIL_MEM	= 1 << 0,   /**< memory limit reached */
	LVE_FAIL_MEM_PHY = 1 << 1,  /**< physical memory limit reached */
	LVE_FAIL_NPROC	= 1 << 2,   /**< number of processes limit reached */
};

/**
 * Flag indicating that ls_cpu stores hi resolution limit, used only for
 * lve_setup_enter.
 */
#define LIBLVE_SETTINGS_LS_CPU_HIRES	(1<<31)
struct liblve_settings {
	int32_t		ls_cpu;  /** < cpu power aka rate */
	int32_t		ls_cpus; /** < number vcpus */
	int32_t		ls_io;   /** < io limit */
	int32_t		ls_enters; /** < enter limit */
	int32_t		ls_memory; /** < mem limit */
	int32_t		ls_cpu_weight;
	int32_t		ls_memory_phy; /** < phy mem limit */
	int32_t		ls_nproc; /* number processes */
	int32_t		ls_iops; /* number of iops */
};

struct liblve_info {
	struct liblve_settings li_set; /* if it's put on top we have binary
	                                  compatible with old versions */
	enum liblve_ve_flags   li_flags;
};

typedef void *(*liblve_alloc)(size_t size);
typedef void (*liblve_free)(void *ptr);

#endif

