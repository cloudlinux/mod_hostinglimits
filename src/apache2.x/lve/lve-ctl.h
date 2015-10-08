#ifndef _LVE_CTL_H_

#define _LVE_CTL_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifndef _LVE_TYPE_H_
#include "lve-type.h"
#endif

#define LIBLVE_API_MAJOR 1
#define LIBLVE_API_MINOR 3

#define SIZEOF_LIBLVE (sizeof(void *) + sizeof(void *) + sizeof(int))
struct liblve;

/**
 * initializes and create instance of LVE
 * args
 *   allocator - pointer to function to allocate memory
 * returns
 *    NULL on error, errno will be set. 
 *    errno will be EINVAL if wrong version of library is used
 *    liblve otherwise
 */
struct liblve *init_lve(liblve_alloc alloc, liblve_free free);

static inline struct liblve *init_lve_generic()
{
	return init_lve(malloc, free);
}

/**
 * destroy lve library instance
 * args: 
 *   lve = instantiated liblive instance
 * return 0 on success
 *        negative number on error. errno will be set
 */
int destroy_lve(struct liblve *lve);

/**
 * enter into virutal environment
 * args:
 * lve = fully initialized liblve instance
 * lve_id = id associated with LVE
 * cookie = pointer to cookie, which returned  if task correctly migrated
 * in LVE and used to exit from this LVE
 * return codes:
 * 0 = on success, negative number means error:
 * -EPERM - don't have permission to call, or called from outside root LVE
 * -ENOMEM - don't have memory to allocate new LVE
 * -EFAULT - cookie is bad pointer
 */
int lve_enter_flags(struct liblve *lve,
		    uint32_t lve_id, uint32_t *cookie, enum liblve_enter_flags flags);

/**
 * enter lve namespace and get a copy of the original fs
 * args:
 * lve = fully initialized liblve instance
 * return codes:
 * -EINVAL - the caller hasn't entered an lve
 */
int lve_enter_fs(struct liblve *lve);


/**
 * exit from virtual environment, same as lve_leave
 * args:
 * lve = fully init liblve instance
 * cookie - pointer to cookie returned from lve_enter
 * return codes:
 * 0 = none error, all less zero is errors:
 * -ESRCH = task not in virutal environment
 * -EFAULT = bad cookie pointer
 * -EINVAL = cookie not match to stored in context
 */
int lve_exit(struct liblve *lve, uint32_t *cookie);

int lve_setup_enter(struct liblve *lve, uint32_t ve_id,
		    struct liblve_settings *set,
		    uint32_t *cookie, enum liblve_enter_flags flags);

/**
 * @brief Checks whether a current task has reached its limits.
 *
 * This call retrieve set of liblve_ve_fails flags, each of them
 * represents resource which allocation failed. This flags combined
 * via bitwise or returns through failmask parameter. Flags are
 * cleared after this call.
 *
 * @param lve - fully initialized liblve instance.
 * @param failmask - pointer to variable where fail mask will be stored.
 * @retval 0 success.
 * @retval -ESRCH task not in virutal environment.
 * @retval -EFAULT bad failmask pointer.
 */
int lve_check_fault(struct liblve *lve, uint32_t * failmask);

#ifdef LVE_DEPRICATED
#warning you need remove old functions
static inline int lve_is_available(void)
{
	struct liblve *lve;

	lve = init_lve(malloc, free);
	if (lve == NULL)
		return 0;
	destroy_lve(lve);

	return 1;
}

static inline int lve_instance_init(struct liblve *lve)
{
	struct liblve *tmp;

	if (lve == NULL)
		return SIZEOF_LIBLVE;

	tmp = init_lve(malloc, NULL);
	if (tmp == NULL)
		return -1;
	memcpy(lve, tmp, SIZEOF_LIBLVE);
	free(tmp);

	return 0;
}

static inline int lve_instance_destroy(struct liblve *lve)
{
	return destroy_lve(lve);
}
#define __unused	__attribute__((unused))
static inline int lve_enter(struct liblve *lve,
				uint32_t ve_id, __unused int32_t uid,
				__unused int32_t gid, uint32_t *cookie)
{
	return lve_enter_flags(lve, ve_id, cookie, 0);
}

static inline int lve_leave(struct liblve *lib, uint32_t *cookie)
{
	return lve_exit(lib, cookie);
}
#endif

/**
 * Return 1 if process in lve context
 * return
 * 1 -  process is in lve context
 * 0 - process is not in lve context
 */
int is_in_lve(struct liblve *lve);


/**
 * return actual api version used to communicate with kernel
 * in format major << 16 | minor
 */
uint32_t lve_kapi_ver(struct liblve *lve);

/**
 * return actual liblve api version used to communicate with
 * userland application
 * return in format major << 16 | minor
 */
uint32_t lve_get_api_version(void);

#ifdef LVE_ADMIN
/**
 * set default parameters for new created virtual enviroment.
 * args:
 * cpu - default CPU power, -1 if don't set
 * io - default IO priority, -1 if don't set
 * return codes:
 * 
 */
int lve_set_default(struct liblve *lve, struct liblve_settings *set);

/**
 * create custom configured virtual enviroment
 * args:
 * ve_id = id associated with VE
 */
int lve_create(struct liblve *lve, uint32_t ve_id);

/**
 * destroy configured virtual environment
 * args:
 * ve_id = id associated with VE
 */
int lve_destroy(struct liblve *lve, uint32_t ve_id);

/**
 * adjust parameters for virtual environment
 * args:
 * ve_id = id associated with VE
 */
int lve_setup(struct liblve *lve, uint32_t ve_id, struct liblve_settings *set);

/**
 * flush context's from kernel
 * args
 * all == true - is need all context flushed, or only default
 *               configured
 * return
 *
 */
int lve_flush(struct liblve *lve, int all);

/**
 * get info about context
 * args
 * ve_id = id associated with VE
 * cpu - pointer to return CPU power.
 * io - pointer to IO priority.
 * return
 * 0 - OK
 * any negative value say error is hit.
 */
int lve_info(struct liblve *lve, uint32_t ve_id, struct liblve_info *set);


int lve_setup_flags(struct liblve *lve, uint32_t ve_id, enum liblve_ve_flags);

/** 
 * migrate existent process into container
 *
 * args
 * ve_id = container id to migrate
 * pid = process id to migrate
 * return
 * 0 - OK
 * any negative value say error is hit.
 */
int lve_enter_pid(struct liblve *lve, uint32_t ve_id, pid_t pid);

/** 
 * migrate existent process from container
 *
 * args
 * pid = process id to migrate
 * return
 * 0 - OK
 * any negative value say error is hit.
 */
int lve_leave_pid(struct liblve *lve, pid_t pid);

/**
 * Set up the lve module
 * returns
 * 0 on success
 * -errno on error
 */
int lve_start(struct liblve *lve);

/**
 * Set fail injection place
 */

int lve_set_fail_val(struct liblve *lve, uint32_t fail_val);

/**
 * enter lve namespace and get the ORIGINAL fs
 * any changes to cwd/root will be applied to all
 * following namespace guests
 * args:
 * lve = fully initialized liblve instance
 * \retval
 * -EPERM - the call is not permitted
 * -EINVAL - the caller hasn't entered an lve
 */
int lve_setup_fs(struct liblve *lve);

/**
 * set lve root mount tree.
 * args
 * lve = fully initialized liblve instance
 * lve_id = lve identiferer to be root changed
 *
 * \retval
*/
int lve_set_root(struct liblve *lve, uint32_t lve_id, const char *root);

/**
 * take current NS and FS settrigs as default for lve.
 * args
 * lve = fully initialized liblve instance
 * lve_id = lve identifer to need assign an NS
 * \retval
 *
 */
int lve_assign_ns(struct liblve *lve, uint32_t lve_id);
#endif

struct passwd;

/**
 * CageFS definitions
 */

#include <sys/types.h>
#include <pwd.h>

#define SECURELVE_JAIL "/usr/share/cagefs-skeleton"
#define SECURELVE_BASEDIR "/var/cagefs/"
#define SECURELVE_SHELL "/usr/sbin/securelve_sh" /* deprecated */
#define SECURELVE_ETC_MP_FILE "/etc/cagefs/cagefs.mp"
#define SECURELVE_MP_FILE "/usr/share/cagefs/cagefs.mp.work" /* deprecated */

#define SECURELVE_CONFIG_DIR "/etc/cagefs"
#define SECURELVE_MIN_UID 500
#define SECURELVE_MIN_UID_FILENAME "/etc/cagefs/cagefs.min.uid"

#define HOME_REGEX_FILE "/etc/cagefs/cagefs.base.home.dirs"

/* Max count of regular expressions */
#define MAX_REXPS 100

#define DISABLE_ETCFS "/etc/cagefs/etc.safe/disable.etcfs"
#define PGSQL_SOCKET_CFG "/usr/share/cagefs/pgsql.socket.name"
#define MYSQL_SOCKET_CFG "/usr/share/cagefs/mysql.socket.name"


/*
 Function reads MIN UID value from file
 Returns -1 if error has occured
*/
int read_min_uid(unsigned int *min_uid, char *error_str);

/**
 * puts user in CageFS (jail)
 *  return 1 if succesful, -1 if error, 0 if CageFS is disabled
 */
int jail(struct passwd *pw, char * error_str);
int lve_jail(struct passwd *pw, char * error_str);
int lve_jail_uid(struct passwd *pw, unsigned int min_uid, char *error_str);


/**
 * setup namespace for CageFS (jail)
 *  return 1 if succesful, -1 if error, 0 if CageFS is disabled
 */
int lve_namespace_setup(unsigned int lve_id);

#endif
