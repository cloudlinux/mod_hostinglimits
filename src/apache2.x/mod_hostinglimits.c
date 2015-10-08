/* Copyright Cloud Linux Inc 2010-2011 All Rights Reserved                                                                                                 
 *                                                                                                                                                         
 * Licensed under CLOUD LINUX LICENSE AGREEMENT                                                                                                            
 * http://cloudlinux.com/docs/LICENSE.TXT                                                                                                                  
 *                                                                                                                                                         
 * This is the hostinglimits module for apache 2.X                                                                                                         
 * author Igor Seletskiy <iseletsk@cloudlinux.com>                                                                                                         
 * author Alexey Berezhok <alexey.berezhok@cloudlinux.com>                                                                                                 
 * author Anton Volkov <avolkov@cloudlinux.com> 
 *                                                                                                                                                         
 -/

/*
 * Set next macro-names:
 * APACHE2_2 - code for apache 2.2
 * APACHE2_0 - code for apache 2.0
 * ENVSAFE - work with mod_env
 * SUEXECBUILD - work with suexec not with apr
 */

#ifndef APACHE2_2
#ifndef APACHE2_0
#error "This source is for Apache version 2.0 or 2.2 only"
#endif
#endif

#define MOD_HOSTINGLIMITS_VERSION "1.0-23"
#define MOD_HOSTINGLIMITS_SIGNAL "/var/run/modhostinglimit.flag"
#define LVE_MIN_UID 500
#define X_LVE_ID "X-LVE-ID"

#define SUPHP_MODULE "mod_suphp.c"

#include "apr_general.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "apr_thread_proc.h"
#include "ap_config_auto.h"
#include "apr_hash.h"
#include "apr_tables.h"

#ifdef REDIS
#include "hiredis.h"
#endif

#define CORE_PRIVATE

#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"
#include <unistd.h>
#include "unixd.h"
#include "mpm_common.h"

#include "lve/lve-ctl.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <stdint.h>

#include <sys/types.h>

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>

#include <link.h>
#include <limits.h>

#ifdef APACHE2_2
#include "ap_regex.h"
#else
#ifndef _PCREPOSIX_H
#include "regex.h"
#endif
#endif


#define PREFIX "mod_hostinglimits:"

#define MOD_HOSTINGLIMITS_NEED_DEBUG 4
#define MOD_HOSTINGLIMITS_UNNEED_DEBUG 1

#define SECURE_LINKS_MIN_UID 100

#define CHECK_DEBUG if(need_debug==MOD_HOSTINGLIMITS_NEED_DEBUG)

module AP_MODULE_DECLARE_DATA hostinglimits_module;
static apr_threadkey_t *key, *debug_key;

// HTTP error code to return to client if resources limit is reached AND LVEErrorCode directive is not present in module configuration
#define DEFAULT_HTTP_ERROR_CODE 508

// HTTP error code should be in these limits
#define MAX_HTTP_SERVER_ERROR_CODE 510
#define MIN_HTTP_SERVER_ERROR_CODE 500

//Максимальная длина URL
#define MAX_ERROR_URL_LEN 128

//Внутренние ошибки
typedef enum {
	HTTPD_ERROR_LVE_COCKIE = 10000,
	HTTPD_ERROR_LVE_COCKIE_RESET
} list_lve_errors;

// configuration data
typedef struct hostinglimits_module_cfg
{
  unsigned int skip;
  unsigned int secure_links;
  uint32_t lve_id;
  apr_array_header_t *allowed_handlers;	// A list of handlers which will be put in LVE
  apr_array_header_t *denied_handlers;	// A list of handlers which will be NOT put in LVE
  unsigned int http_error_code;	// Integer HTTP error code to return to client if resources limit is reached
  int err_doc_found;		// true = "ErrorDocument 508" directive is found in Apache configuration
  const char *lve_user;
  apr_array_header_t *debug_sites;
  apr_array_header_t *debug_uids;
  uid_t ruid_uid;
  uid_t itk_uid;
  gid_t ruid_gid;
  gid_t itk_gid;
  uint32_t retryAfter;
  int mode;
  char *header;
  char *path_regex;	// Compiled regex buffer
  uid_t suphp_uid;
  uid_t suphp_gid;
} hostinglimits_module_cfg;

__thread uint32_t lve_uid_thd = 0;
__thread uint32_t p_cookie = 0;

static int registered_filter = 0;

static int lve_available = 0;
static int errno_global = 0;
struct liblve *lve = NULL;
static int found_apr_func_ver = 0;
static int use_group = 0;
static int pw_buff = 0;

#ifdef REDIS
static char *lve_redis_socket = NULL;
static int lve_redis_timeout = 60;
static int lve_redis_port = 0;

static time_t redis_timeout_check = -1;

redisContext *redis_connection = NULL;
apr_thread_mutex_t *mutex_redis = NULL;

static int redis_flag = 0;

#ifdef  REDIS_USE_MUTEX
#define redis_apr_thread_mutex_lock(x) apr_thread_mutex_lock(x)
#define redis_apr_thread_mutex_unlock(x) apr_thread_mutex_unlock(x)
#else
#define redis_apr_thread_mutex_lock(x)
#define redis_apr_thread_mutex_unlock(x)
#endif
#endif

//liblve
void *handle_liblve = NULL;

APR_DECLARE_OPTIONAL_FN (int, lve_enter_flags, (struct liblve *lve,uint32_t lve_id, uint32_t *cookie, int flags));
APR_OPTIONAL_FN_TYPE(lve_enter_flags) *lve_enter_flags_fn = NULL;
APR_DECLARE_OPTIONAL_FN (int, destroy_lve, (struct liblve *lve));
APR_OPTIONAL_FN_TYPE(destroy_lve) *destroy_lve_fn = NULL;
APR_DECLARE_OPTIONAL_FN (int, lve_exit, (struct liblve *lve, uint32_t *cookie));
APR_OPTIONAL_FN_TYPE(lve_exit) *lve_exit_fn = NULL;
APR_DECLARE_OPTIONAL_FN (struct liblve *, init_lve, (liblve_alloc alloc, liblve_free free));
APR_OPTIONAL_FN_TYPE(init_lve) *init_lve_fn = NULL;
APR_DECLARE_OPTIONAL_FN (int, lve_setup_enter, (struct liblve *lve, uint32_t ve_id, struct liblve_settings *set, uint32_t *cookie, enum liblve_enter_flags flags));
APR_OPTIONAL_FN_TYPE(lve_setup_enter) *lve_setup_enter_fn = NULL;

//apr+lve version 1
APR_DECLARE_OPTIONAL_FN (apr_status_t, apr_lve_environment_init, (int lve_no_maxenter_value, void *lve_ptr, int (*lve_enter_flags_function_ptr)(void *, ...), int (*lve_leave_function_ptr)(void *, ...), char *suexec_string));
APR_OPTIONAL_FN_TYPE(apr_lve_environment_init) *apr_lve_environment_init_fn = NULL;
//apr+lve version 2
APR_DECLARE_OPTIONAL_FN (apr_status_t, apr_lve_environment_init_group, (int lve_no_maxenter_value, void *lve_ptr, int (*lve_enter_flags_function_ptr)(void *, ...), int (*lve_leave_function_ptr)(void *, ...), char *suexec_string, int use_group));
APR_OPTIONAL_FN_TYPE(apr_lve_environment_init_group) *apr_lve_environment_init_group_fn = NULL;
//apr+lve version 2
APR_DECLARE_OPTIONAL_FN (apr_status_t, apr_lve_environment_init_group_minuid, (int lve_no_maxenter_value, void *lve_ptr, int (*lve_enter_flags_function_ptr)(void *, ...), int (*lve_leave_function_ptr)(void *, ...), char *suexec_string, int use_group, int min_uid));
APR_OPTIONAL_FN_TYPE(apr_lve_environment_init_group_minuid) *apr_lve_environment_init_group_minuid_fn = NULL;

/* Paralles */
static int io_limit = 100;
static int cpu_limit=-1;
static int mem_limit=-1;
static int ep_limit = -1;
static int ncpu_limit = 1;
/* Paralles */

/* Parallels */
typedef struct __attribute__ ((__packed__)) limits_t
{
        enum _fields
        {
                io_lim = 1L << 0
        } fields;

        unsigned int uid;
        unsigned int gid;
        unsigned int lve_cpu;
        unsigned int lve_nproc;
        unsigned int lve_io;
} limits_t;

APR_DECLARE_OPTIONAL_FN(int, poa_cgid_limits_lookup_ex,
        (conn_rec *, const char*, struct limits_t*));
static APR_OPTIONAL_FN_TYPE(poa_cgid_limits_lookup_ex) *cgid_pfn_limits_lookup_ex = NULL;
/* Parallels */

static min_uid_cfg = 0;
#define MIN_UID_FILE "/etc/cagefs/cagefs.min.uid"

static void read_cagefs_min_uid(){
    FILE *fp = fopen(MIN_UID_FILE, "rb");
    if(fp){
        int buffer = 0, rc = 0;
        rc = fread(&buffer, sizeof(int), 1, fp);
        if((rc>0) && (buffer>0)){
            min_uid_cfg = buffer;
        }
        fclose(fp);
    }
}


static int load_liblve(apr_pool_t * p){
	handle_liblve = dlopen("liblve.so.0", RTLD_LOCAL | RTLD_LAZY);
	if(handle_liblve){
		lve_enter_flags_fn = dlsym(handle_liblve, "lve_enter_flags");
		destroy_lve_fn = dlsym(handle_liblve, "destroy_lve");
		lve_exit_fn = dlsym(handle_liblve, "lve_exit");
		init_lve_fn = dlsym(handle_liblve, "init_lve");
		lve_setup_enter_fn = dlsym(handle_liblve, "lve_setup_enter");
		apr_pool_cleanup_register (p, handle_liblve, (void *) dlclose,
								    apr_pool_cleanup_null);
		if(lve_exit_fn && destroy_lve_fn && lve_enter_flags_fn && init_lve_fn && lve_setup_enter_fn){
			return 0;
		}
	}
	return -1;
}

//Расшифровка ошибок
static char *getErrorUrl(char *buffer, int error_numb){
	if(error_numb<0) error_numb=-error_numb;
	switch(error_numb){
	case EPERM:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-EPERM", MAX_ERROR_URL_LEN);
		break;
	case E2BIG:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-E2BIG", MAX_ERROR_URL_LEN);
		break;
	case ENOMEM:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-ENOMEM", MAX_ERROR_URL_LEN);
		break;
	case EFAULT:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-EFAULT", MAX_ERROR_URL_LEN);
		break;
	case EINVAL:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-EINVAL", MAX_ERROR_URL_LEN);
		break;
	case EBUSY:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-EBUSY", MAX_ERROR_URL_LEN);
		break;
	case ENOSPC:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-ENOSPC", MAX_ERROR_URL_LEN);
		break;
	case HTTPD_ERROR_LVE_COCKIE:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-HTTPD1", MAX_ERROR_URL_LEN);
		break;
	case HTTPD_ERROR_LVE_COCKIE_RESET:
		strncpy(buffer, " Read more: http://e.cloudlinux.com/MHL-HTTPD2", MAX_ERROR_URL_LEN);
		break;
	default:
		strncpy(buffer, "", MAX_ERROR_URL_LEN);
		break;
	}
	return buffer;
}

#ifdef ENVSAFE
apr_hash_t *tab;
void buildModEnvBaseConfig(apr_pool_t *p, server_rec *s);
#endif

int
get_need_debug (apr_array_header_t * list_of_sites, request_rec * r)
{
  int num_names;
  char **names_ptr;
  if (!r->hostname)
    return MOD_HOSTINGLIMITS_UNNEED_DEBUG;
  if (list_of_sites)
    {
      names_ptr = (char **) list_of_sites->elts;
      num_names = list_of_sites->nelts;
      for (; num_names; ++names_ptr, --num_names)
	{
	  if (strstr (r->hostname, *names_ptr))
	    {
	      return MOD_HOSTINGLIMITS_NEED_DEBUG;
	    }
	}

    }

  return MOD_HOSTINGLIMITS_UNNEED_DEBUG;
}

int
get_need_debug_uids (apr_array_header_t * list_of_uids, uid_t uid)
{
  int num_names;
  uid_t *names_ptr;
  if (!uid)
    return MOD_HOSTINGLIMITS_UNNEED_DEBUG;
  if (list_of_uids)
    {
      names_ptr = (uid_t*) list_of_uids->elts;
      num_names = list_of_uids->nelts;
      for (; num_names; ++names_ptr, --num_names)
	{
	  if (uid == *names_ptr)
	    {
	      return MOD_HOSTINGLIMITS_NEED_DEBUG;
	    }
	}

    }

  return MOD_HOSTINGLIMITS_UNNEED_DEBUG;
}

/**
 * This function returns directory config structure for current request
 */
static hostinglimits_module_cfg *
hostinglimits_module_dconfig (const request_rec * r)
{
  return (hostinglimits_module_cfg *) ap_get_module_config (r->per_dir_config,
							    &hostinglimits_module);
}

pid_t
gettid (void)
{
  return syscall (__NR_gettid);
}

static void *
hostinglimits_module_merge_config (apr_pool_t * p, void *BASE, void *ADD)
{
  hostinglimits_module_cfg *base = BASE;
  hostinglimits_module_cfg *add = ADD;
  hostinglimits_module_cfg *cfg =
    (hostinglimits_module_cfg *) apr_pcalloc (p,
					      sizeof
					      (hostinglimits_module_cfg));
  cfg->skip = (add->skip) ? add->skip : base->skip;
  cfg->secure_links = (add->secure_links) ? add->secure_links : base->secure_links;
  cfg->http_error_code =
    (add->http_error_code != DEFAULT_HTTP_ERROR_CODE) ? add->http_error_code : base->http_error_code;
  cfg->lve_id = (add->lve_id) ? add->lve_id : base->lve_id;
  cfg->allowed_handlers =
    (add->allowed_handlers) ? add->allowed_handlers : base->allowed_handlers;
  cfg->denied_handlers =
    (add->denied_handlers) ? add->denied_handlers : base->denied_handlers;
  cfg->err_doc_found =
    (add->err_doc_found) ? add->err_doc_found : base->err_doc_found;
  cfg->lve_user = (add->lve_user) ? add->lve_user : base->lve_user;
  cfg->debug_sites =
    (add->debug_sites) ? add->debug_sites : base->debug_sites;
  cfg->debug_uids =
      (add->debug_uids) ? add->debug_uids : base->debug_uids;
  cfg->itk_uid = (add->itk_uid) ? add->itk_uid : base->itk_uid;
  cfg->ruid_uid = (add->ruid_uid) ? add->ruid_uid : base->ruid_uid;
  cfg->itk_gid = (add->itk_gid) ? add->itk_gid : base->itk_gid;
  cfg->ruid_gid = (add->ruid_gid) ? add->ruid_gid : base->ruid_gid;
  cfg->retryAfter = (add->retryAfter) ? add->retryAfter : base->retryAfter;
  cfg->path_regex =
    (add->path_regex) ? add->path_regex : base->path_regex;
  cfg->mode = (add->mode) ? add->mode : base->mode;
  cfg->suphp_uid = (add->suphp_uid) ? add->suphp_uid : base->suphp_uid;
  cfg->suphp_gid = (add->suphp_gid) ? add->suphp_gid : base->suphp_gid;
  return cfg;
}

static void *
hostinglimits_module_create_dir_config (apr_pool_t * p, char *dirspec)
{
  hostinglimits_module_cfg *cfg =
    (hostinglimits_module_cfg *) apr_pcalloc (p,
					      sizeof
					      (hostinglimits_module_cfg));
  if (!cfg)
    {
      ap_log_error (APLOG_MARK, APLOG_ERR, OK, NULL,
		    PREFIX " not enough memory");
      return NULL;
    }
  cfg->skip = 0;
  cfg->secure_links = 0;
  cfg->http_error_code = DEFAULT_HTTP_ERROR_CODE;
  cfg->err_doc_found = 0;
  cfg->lve_id = 0;
  cfg->allowed_handlers = NULL;
  cfg->denied_handlers = NULL;
  cfg->lve_user = NULL;
  cfg->debug_sites = NULL;
  cfg->debug_uids = NULL;
  cfg->itk_uid = 0;
  cfg->ruid_uid = 0;
  cfg->itk_gid = 0;
  cfg->ruid_gid = 0;
  cfg->retryAfter = 240;
  cfg->header = NULL;
  cfg->mode = 0;
  cfg->path_regex = apr_pstrdup(p, "/home/([^/]+)/");
  cfg->suphp_uid = 0;
  cfg->suphp_gid = 0;
  return (void *) cfg;
}

static const char *
set_lve_id (cmd_parms * cmd, void *mcfg, const char *lve_id)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (lve_id)
    {
      cfg->lve_id = (uint32_t) apr_atoi64 (lve_id);
    }
  return NULL;
}

static const char *
set_lve_user (cmd_parms * cmd, void *mcfg, const char *lve_user)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (lve_user)
    {
      cfg->lve_user = lve_user;
    }
  return NULL;
}

static const char *
set_assign_user_id (cmd_parms * cmd, void *mcfg, const char *user_name,
		    const char *group_name)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (user_name)
    {
      cfg->itk_uid = ap_uname2id (user_name);
    }
  if (group_name)
    {
      cfg->itk_gid = ap_gname2id (group_name);
    }
  return NULL;
}

static const char *
set_uidgid (cmd_parms * cmd, void *mcfg, const char *user_name,
	    const char *group_name)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (user_name)
    {
      cfg->ruid_uid = ap_uname2id (user_name);
    }
  if (group_name)
    {
      cfg->ruid_gid = ap_gname2id (group_name);
    }
  return NULL;
}

static const char *
set_debug (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err = ap_check_cmd_context (cmd,
					  NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->debug_sites)
    {
      cfg->debug_sites = apr_array_make (cmd->pool, 2, sizeof (char *));
    }
  *(const char **) apr_array_push (cfg->debug_sites) = arg;
  return NULL;
}

static const char *
set_debug_uids (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err = ap_check_cmd_context (cmd,
					  NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->debug_uids)
    {
      cfg->debug_uids = apr_array_make (cmd->pool, 2, sizeof (uid_t));
    }
  uid_t uid_arg = apr_atoi64(arg);
  if (uid_arg) *(uid_t *) apr_array_push (cfg->debug_uids) = uid_arg;
  return NULL;
}

#ifndef APACHE2_0
// Function handles Apache's ErrorDocument directive
// Sets err_doc_found flag in module configuration if "ErrorDocument 508" directive is found
static const char *
error_doc_func (cmd_parms * cmd, void *mcfg, const char *par1,
		const char *par2)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (par1)
    if (strstr (par1, "508"))
      cfg->err_doc_found = 1;

  return NULL;
}
#endif

static unsigned int
get_valid_http_error_code (unsigned int code)
{
  if ((code < MIN_HTTP_SERVER_ERROR_CODE)
      || (code > MAX_HTTP_SERVER_ERROR_CODE))
    return DEFAULT_HTTP_ERROR_CODE;
  else
    return code;
}

// Function handles LVEErrorCode directive
static const char *
set_lve_error_code (cmd_parms * cmd, void *mcfg, const char *lve_error_code)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (lve_error_code)
    {
      cfg->http_error_code = get_valid_http_error_code ((unsigned int)
							apr_atoi64
							(lve_error_code));
    }
  return NULL;
}

static const char *
set_lve_retryafter (cmd_parms * cmd, void *mcfg, const char *minutes)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (minutes)
    {
      cfg->retryAfter = (uint32_t) apr_atoi64 (minutes);
    }
  return NULL;
}

static const char *
set_lve_parsemode (cmd_parms * cmd, void *mcfg, const char *mode)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (mode)
    {
      if (!apr_strnatcasecmp (mode, "CONF"))
	{
	  cfg->mode = 0;
	  return NULL;
	}
      if (!apr_strnatcasecmp (mode, "PATH"))
	{
	  cfg->mode = 1;
	  return NULL;
	}
      if (!apr_strnatcasecmp (mode, "OWNER"))
	{
	  cfg->mode = 2;
	  return NULL;
	}
    /*  if (!apr_strnatcasecmp (mode, "HEADER"))
	{
	  cfg->mode = 3;
	  return NULL;
	}*/
#ifdef REDIS
    if (!apr_strnatcasecmp (mode, "REDIS"))
    {
    	  cfg->mode = 4;
    	  redis_flag = 1;
    	  return NULL;
    }
#endif
    }
  return NULL;
}

static const char *
set_lve_pathregexp (cmd_parms * cmd, void *mcfg, const char *regexp_data)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (regexp_data)
    {
      int right_param = 1;
#ifdef APACHE2_2
      ap_regex_t rx;

      // Compile regex. Error ?
      if (ap_regcomp (&rx, regexp_data, AP_REG_EXTENDED))
	{
	  right_param = 0;
	} else {
		ap_regfree (&rx);
	}

#else
      regex_t rx;

      // Compile regex. Error ?
      if (regcomp (&rx, regexp_data, REG_EXTENDED))
	{
	  right_param = 0;
	} else {
		regfree (&rx);
	}
#endif
      if (!right_param)
	{
	  return apr_psprintf (cmd->pool,
			       "Wrong regexp expression %s in parameter LVEPathRegexp",
			       regexp_data);
	}
    }
  return NULL;
}

static const char *
set_lve_headername (cmd_parms * cmd, void *mcfg, const char *header)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (header)
    {
      cfg->header = (char *)header;
    }
  return NULL;
}

static const char *
set_handlers (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err = ap_check_cmd_context (cmd,
					  NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->allowed_handlers)
    {
      cfg->allowed_handlers = apr_array_make (cmd->pool, 2, sizeof (char *));
    }
  *(const char **) apr_array_push (cfg->allowed_handlers) = arg;
  return NULL;
}

static const char *
set_handlers_to_deny (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err = ap_check_cmd_context (cmd,
					  NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->denied_handlers)
    {
      cfg->denied_handlers = apr_array_make (cmd->pool, 2, sizeof (char *));
    }
  *(const char **) apr_array_push (cfg->denied_handlers) = arg;
  return NULL;
}

#ifndef APACHE2_0
static const char *suphp_handle_cmd_user_group_lve(cmd_parms *cmd, void *mconfig,
                                           const char *arg1, const char *arg2)
{
	hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mconfig;
	if (arg1)
	{
	    cfg->suphp_uid = ap_uname2id (arg1);
	}
	if (arg2)
	{
	    cfg->suphp_gid = ap_gname2id (arg2);
	}
	return NULL;
}
#endif

static const char *
set_lve_use_group (cmd_parms * cmd, void *mcfg, const char *arg)
{
  const char *err = ap_check_cmd_context (cmd,
		  GLOBAL_ONLY);
  if (err != NULL)
    {
      return err;
    }
  if (!apr_strnatcasecmp (arg, "On"))
  	{
  	  use_group = 1;
  	}

  return NULL;
}

static const char *
set_lve_use_filter (cmd_parms * cmd, void *mcfg, const char *arg)
{
  const char *err = ap_check_cmd_context (cmd,
		  GLOBAL_ONLY);
  if (err != NULL)
    {
      return err;
    }
  if (!apr_strnatcasecmp (arg, "On"))
  	{
	  registered_filter = 1;
  	}

  return NULL;
}

/* Parallels */
static const char *set_cpu_limit(cmd_parms *cmd, void *dummy,
                                const char *arg) {
  server_rec *s = cmd->server;
  hostinglimits_module_cfg *conf = ap_get_module_config(s->module_config,
                                                &hostinglimits_module);
  if (arg) {
    cpu_limit = atol(arg);
  }
  return NULL;
}

static const char *set_ncpu_limit(cmd_parms *cmd, void *dummy,
                                const char *arg) {
  server_rec *s = cmd->server;
  hostinglimits_module_cfg *conf = ap_get_module_config(s->module_config,
                                                &hostinglimits_module);
  if (arg) {
    ncpu_limit = atol(arg);
  }
  return NULL;
}

static const char *set_mem_limit(cmd_parms *cmd, void *dummy,
                                const char *arg) {
  server_rec *s = cmd->server;
  hostinglimits_module_cfg *conf = ap_get_module_config(s->module_config,
                                                &hostinglimits_module);
  if (arg) {
    mem_limit = atol(arg);
  }
  return NULL;
}

static const char *set_ep_limit(cmd_parms *cmd, void *dummy,
                                const char *arg) {
  server_rec *s = cmd->server;
  hostinglimits_module_cfg *conf = ap_get_module_config(s->module_config,
                                                &hostinglimits_module);
  if (arg) {
    ep_limit = atol(arg);
  }
  return NULL;
}



static const char *set_io_limit(cmd_parms *cmd, void *dummy,
                                const char *arg) {
  server_rec *s = cmd->server;
  hostinglimits_module_cfg *conf = ap_get_module_config(s->module_config,
                                                &hostinglimits_module);
  if (arg) {
    io_limit = atol(arg);
  }
  return NULL;
}
/* Parallels */

#ifdef REDIS
static const char *
set_redis_socket (cmd_parms * cmd, void *mcfg, const char *arg)
{
  const char *err = ap_check_cmd_context (cmd,
		  GLOBAL_ONLY);
  if (err != NULL)
    {
      return err;
    }

  if(arg){
  	  lve_redis_socket = apr_pstrdup(cmd->pool, arg);
  } else {
  	  return apr_psprintf (cmd->pool,
  	  		"Redis socket can not be empty");
  }

  return NULL;
}

static const char *
set_redis_timeout (cmd_parms * cmd, void *mcfg, const char *arg)
{
  const char *err = ap_check_cmd_context (cmd,
		  GLOBAL_ONLY);
  if (err != NULL)
    {
      return err;
    }

  if(arg){
	  lve_redis_timeout = (int)apr_atoi64(arg);
  } else {
  	  return apr_psprintf (cmd->pool,
  	  		"Redis timeout can not be empty");
  }

  return NULL;
}

static const char *
set_redis_addr (cmd_parms * cmd, void *mcfg, const char *addr,
		    const char *port)
{
  const char *err = ap_check_cmd_context (cmd,
			  GLOBAL_ONLY);
  if (err != NULL)
  {
    return err;
  }

  if(addr){
	  lve_redis_socket = apr_pstrdup(cmd->pool, addr);
  } else {
	  return apr_psprintf (cmd->pool,
	  		"Redis address can not be empty");
  }

  if(port){
	  lve_redis_port = (int)apr_atoi64(port);
  } else {
	  return apr_psprintf (cmd->pool,
	  		"Redis port can not be empty");
  }

  return NULL;
}
#endif

// describe used directives
static command_rec hostinglimits_module_directives[] = {
  AP_INIT_FLAG ("SkipErrors", ap_set_flag_slot, (void *)
		APR_OFFSETOF (hostinglimits_module_cfg, skip),
		RSRC_CONF,
		"Allow apache to continue even if LVE is unavalable"),
  AP_INIT_TAKE1 ("LVEId", set_lve_id, NULL, ACCESS_CONF | RSRC_CONF,
		 "LVE Id"),
  AP_INIT_TAKE1 ("LVEUser", set_lve_user, NULL, ACCESS_CONF | RSRC_CONF,
		 "LVE User"),
  AP_INIT_ITERATE ("AllowedHandlers", set_handlers, NULL, RSRC_CONF,
		   "A list of handlers which will be put in LVE"),
  AP_INIT_ITERATE ("DenyHandlers", set_handlers_to_deny, NULL, RSRC_CONF,
		   "A list of handlers which will be NOT put in LVE"),
  AP_INIT_TAKE1 ("LVEErrorCode", set_lve_error_code, NULL,
		 RSRC_CONF,
		 "Integer HTTP error code to return to client if resources limit is reached"),
#ifndef APACHE2_0
  AP_INIT_TAKE2 ("ErrorDocument", error_doc_func, NULL, OR_FILEINFO,
		 "ErrorDocument Apache configuration directive"),
  AP_INIT_FLAG ("SecureLinks", ap_set_flag_slot, (void *)
	    	APR_OFFSETOF(hostinglimits_module_cfg, secure_links),
			RSRC_CONF,
			"Make sure that files and links owned by same user as defined for VirtualHost"),
  AP_INIT_TAKE2("suPHP_UserGroup", suphp_handle_cmd_user_group_lve, NULL, RSRC_CONF | ACCESS_CONF,
			    "User and group scripts shall be run as"),
#endif
  AP_INIT_TAKE2 ("AssignUserID", set_assign_user_id, NULL,
		 RSRC_CONF | ACCESS_CONF,
		 "Tie a virtual host to a specific child process."),
  AP_INIT_TAKE2 ("RUidGid", set_uidgid, NULL, RSRC_CONF | ACCESS_CONF,
		 "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),
  AP_INIT_ITERATE ("LVESitesDebug", set_debug, NULL, RSRC_CONF,
		   "A list of sites which should be debugged"),
  AP_INIT_ITERATE ("LVEUidsDebug", set_debug_uids, NULL, RSRC_CONF,
		   		   "A list of uids which should be debugged"),
  AP_INIT_TAKE1 ("LVERetryAfter", set_lve_retryafter, NULL,
		 RSRC_CONF,
		 "Set minutes of LVE_RETRY_AFTER header, which comes with 508 error. O - disabled"),
  AP_INIT_TAKE1 ("LVEParseMode", set_lve_parsemode, NULL,
		 RSRC_CONF,
		 "Set mode of uid extraction - CONF|PATH|OWNER|HEADER"),
  AP_INIT_TAKE1 ("LVEPathRegexp", set_lve_pathregexp, NULL,
		 RSRC_CONF,
		 "Set template of path for mode PATH"),
  AP_INIT_TAKE1 ("LVEHeaderName", set_lve_headername, NULL,
		 RSRC_CONF,
		 "Set header name for uid extraction for mode Header"),
  AP_INIT_TAKE1 ("LVEUseGroupID", set_lve_use_group, NULL,
		 RSRC_CONF,
		 "Use group ID instead of UID for LVE id"),
  AP_INIT_TAKE1 ("LVEUseFilter", set_lve_use_filter, NULL,
		 RSRC_CONF,
		 "Use filter for LVE out"),
#ifdef REDIS
   AP_INIT_TAKE1 ("LVERedisSocket", set_redis_socket, NULL,
		 RSRC_CONF,
		 "Set redis socket path"),
   AP_INIT_TAKE1 ("LVERedisTimeout", set_redis_timeout, NULL,
		 RSRC_CONF,
 		 "Set redis reconnection timeout"),
   AP_INIT_TAKE2 ("LVERedisAddr", set_redis_addr, NULL, RSRC_CONF,
 		 "Set redis addr if used non socket connection"),

#endif
/* Paralles */
 		AP_INIT_TAKE1("SuCGIDIOLimit", set_io_limit, NULL, RSRC_CONF,
 		                  "IO Limit in KB/s"),
 		AP_INIT_TAKE1("OverrideCPULimit", set_cpu_limit, NULL, RSRC_CONF,
 		                  "CPU Limit"),
 		AP_INIT_TAKE1("OverrideMEMLimit", set_mem_limit, NULL, RSRC_CONF,
 		                  "MEM Limit"),
 		AP_INIT_TAKE1("OverrideEPROCLimit", set_ep_limit, NULL, RSRC_CONF,
 		                  "EP Limit"),
 		AP_INIT_TAKE1("OverrideNCPULimit", set_ncpu_limit, NULL, RSRC_CONF,
 		                  "NCPU Limit"),
/* Paralles */
  {NULL}
};

#ifdef SUEXECBUILD
static apr_status_t
lve_file_destroy (void *dummy)
{
  apr_pool_t *p = NULL;
  apr_pool_create (&p, NULL);
  apr_file_remove (MOD_HOSTINGLIMITS_SIGNAL, p);
  apr_pool_destroy (p);
  return APR_SUCCESS;
}
#endif

#ifdef REDIS

int connect_to_redis_db(server_rec *s){
	if((redis_timeout_check!=0)&&
			((redis_timeout_check<0)
					||((time(NULL)-redis_timeout_check)>=lve_redis_timeout))){
		struct timeval timeout = { 0, 500000 };
		if(lve_redis_port>0){
			if(lve_redis_socket)
			 redis_connection = redisConnectWithTimeout((char*)lve_redis_socket, lve_redis_port, timeout);
			else
			 redis_connection = redisConnectWithTimeout((char*)"127.0.0.1", lve_redis_port, timeout);
		} else {
			if(lve_redis_socket)
			 redis_connection = redisConnectUnixWithTimeout((char*)lve_redis_socket, timeout);
			else
			 redis_connection = redisConnectUnixWithTimeout((char*)"/tmp/redis.sock", timeout);
		}

		if (redis_connection == NULL || redis_connection->err) {
			if (redis_connection) {
				ap_log_error (APLOG_MARK,
				    			  	  	APLOG_WARNING,
				    	      		    0, s,
				    	      		    PREFIX " redis connection error %s", redis_connection->errstr);
		        redisFree(redis_connection);
		        redis_connection = NULL;
		    } else {
		    	ap_log_error (APLOG_MARK,
		    		APLOG_WARNING,
		    		0, s,
		    		PREFIX " connection error: can't allocate redis context");
		    }
			redis_timeout_check= time(NULL);
		} else {
                        ap_log_error(APLOG_MARK,
                                APLOG_WARNING,
                                0, s,
                                PREFIX " connected to redis");
			redis_timeout_check = 0;
                        //redisSetTimeout(redis_connection, timeout);
		}
	}
	if (!redis_timeout_check)
		return 0;
	else
		return 1;
}

int32_t get_redis_value(redisReply *reply, int index){
	int32_t ret = -1;
	if(reply->element[index]->type == REDIS_REPLY_INTEGER){
			ret = (int32_t) reply->element[index]->integer;
	} else if (reply->element[index]->type == REDIS_REPLY_ARRAY) {
				if(reply->element[index]->elements>0){
					ret = (int32_t)apr_atoi64(reply->element[index]->element[0]->str);
				}
	} else if (reply->element[index]->type == REDIS_REPLY_STRING) {
				ret = (int32_t)apr_atoi64(reply->element[index]->str);
	}
	return ret;
}

#define CHECK_LVE_DATA(x,y) lve_data->x = get_redis_value(reply, y); \
							if (lve_data->x < 0) status--

int get_redis_command(request_rec * r, hostinglimits_module_cfg * cfg, const char *hostname, struct liblve_settings *lve_data, char *pw_dir){
	int ret = -1;
	int status = 0;
	redisReply *reply;
        ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
                                        PREFIX "REDIS: GET %s - %s", hostname, r->hostname);
	/*reply = redisCommand(redis_connection,"HMGET %s id cpu vmem pmem ep nproc io", hostname);
	if(reply && (reply->type == REDIS_REPLY_ARRAY)){
		ret = (int)get_redis_value(reply, 0);
		if(ret<=0) ret = -1;
		else {

				CHECK_LVE_DATA(ls_cpu,1);
				lve_data->ls_cpus = 0;
				CHECK_LVE_DATA(ls_memory,2);
				if(lve_data->ls_memory > 0) lve_data->ls_memory = lve_data->ls_memory  * 256;
				CHECK_LVE_DATA(ls_memory_phy,3);
				if(lve_data->ls_memory_phy > 0) lve_data->ls_memory_phy = lve_data->ls_memory_phy * 256;
				CHECK_LVE_DATA(ls_enters,4);
				CHECK_LVE_DATA(ls_nproc,5);
				CHECK_LVE_DATA(ls_io,6);
				if(lve_data->ls_io) lve_data->ls_io = lve_data->ls_io * 1024;
				lve_data->ls_cpu_weight = 100;

				if(status<0){
					if(status!=-6){
						ret = -1;
					}
				}
		}
		freeReplyObject(reply);*/

    //Get brand and platform fro SetEnv

    const char *brand = NULL;
    const char *platform = NULL;
    if(r->subprocess_env){
       brand = apr_table_get(r->subprocess_env, (const char *)"BRAND");
       platform = apr_table_get(r->subprocess_env, (const char *)"PLATFORM");
    }
    if(!brand || !platform){
    	ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
    						  PREFIX "Can't find BRAND or PLATFORM parameter");
    	return ret;
    }
    reply = redisCommand(redis_connection,"HGET %s %s:%s:lve_id", hostname, brand, platform);
    if(reply){
    	if(reply->type == REDIS_REPLY_INTEGER){
    		ret = (int32_t) reply->integer;
    	} else if (reply->type == REDIS_REPLY_ARRAY) {
    		if(reply->elements>0){
    			ret = (int32_t)apr_atoi64(reply->element[0]->str);
    		}
    	} else if (reply->type == REDIS_REPLY_STRING) {
    		ret = (int32_t)apr_atoi64(reply->str);
    	}
    	freeReplyObject(reply);
	} else {
		redisFree(redis_connection);
		redis_connection = NULL;
		redis_timeout_check= time(NULL);
		ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
					  PREFIX "Can't allocate reply data, reconnect affter %d seconds", lve_redis_timeout);
		ret = -2;
	}

    /*reply = redisCommand(redis_connection,"HGET %s %s:%s:home_dir", hostname, brand, platform);
    if(reply){
    	strncpy(pw_dir, reply->element[0]->str, PATH_MAX * 2);
       	freeReplyObject(reply);
    } else {
    	strncpy(pw_dir, "", PATH_MAX * 2);
    	ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
    					  PREFIX "Can't get user HOME dir %d", ret);
    }*/
	return ret;
}

int get_redis_id(request_rec * r, hostinglimits_module_cfg * cfg, struct liblve_settings *lve_data, char *pw_dir){
	if  (redis_timeout_check){
		if(!connect_to_redis_db(r->server)){
			ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
					PREFIX "reconnected to redis successfull");
		}
	}

	if(!redis_timeout_check && r->hostname && redis_connection) {
		const char *try=r->hostname;
	        const char *next=index(try, '.');	
		while (try) {
			int result = get_redis_command(r, cfg, try, lve_data, pw_dir);
			if(result>0) {
				return result;
                        } else {
                if(result==-2) break;
				if (next && *next) {
					try = next + 1;
                                } else {
					return -1;
				}
			 	next = index(try, '.'); 
				if (!next) return -1;
			}
                }
        } else {
		ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
			PREFIX "redis db not connected, or empty domain %s", r->hostname);
	}
	return -1;
}

static apr_status_t
destroy_redis_pool (void *dummy)
{
                         //ap_log_error (APLOG_MARK, APLOG_ERR, OK, 0,
                         //                               PREFIX "destroy_redis_pool");
  if(mutex_redis){
   redis_apr_thread_mutex_lock(mutex_redis);
   if(redis_connection){
	  redisFree(redis_connection);
	  redis_connection = NULL;
   }
   redis_apr_thread_mutex_unlock(mutex_redis);
   apr_thread_mutex_destroy(mutex_redis);
   mutex_redis = NULL;
  }
                           //ap_log_error (APLOG_MARK, APLOG_ERR, OK, 0,
                           //                             PREFIX "destroy redis pool done");
  return APR_SUCCESS;
}
#endif

static int check_for_event_or_worker(){
	module *worker_event_c = NULL;
	worker_event_c = ap_find_linked_module("worker.c");
	if(worker_event_c){
		return 1;
	} else {
		worker_event_c = ap_find_linked_module("event.c");
		if(worker_event_c){
			return 1;
		}
	}
	return 0;
}

static int
init_post_config (apr_pool_t * pconf, apr_pool_t * plog,
		  apr_pool_t * ptemp, server_rec * s)
{

  /*
   * check if need force lve exit on filter
   */
   
  ap_log_error (APLOG_MARK,
      	  		    APLOG_NOTICE,
      	  		    0,
      	  		    s,
      	  		    PREFIX " use Min UID %d", min_uid_cfg);

  if(!registered_filter){
	  registered_filter = check_for_event_or_worker();
  }
  if(registered_filter) {
	  ap_log_error (APLOG_MARK,
      	  		    APLOG_NOTICE,
      	  		    0,
      	  		    s,
      	  		    PREFIX " use filter for LVE exit");
  } else {
	  ap_log_error (APLOG_MARK,
	        	  	APLOG_NOTICE,
	        	  	0,
	        	  	s,
	        	  	PREFIX " use old style for LVE exit");
  }

  /* Parallels */
  cgid_pfn_limits_lookup_ex = APR_RETRIEVE_OPTIONAL_FN(poa_cgid_limits_lookup_ex);
  /* Parallels */

  if (lve_available)
    {
      ap_log_error (APLOG_MARK,
		    APLOG_NOTICE,
		    0,
		    s,
		    PREFIX " version " MOD_HOSTINGLIMITS_VERSION
		    ". LVE mechanism enabled");
      if (use_group){
    	  ap_log_error (APLOG_MARK,
    	  		    APLOG_NOTICE,
    	  		    0,
    	  		    s,
    	  		    PREFIX " use GroupID instead of UID");
      }
      if(found_apr_func_ver){
    	  ap_log_error (APLOG_MARK,
    	      	      	APLOG_NOTICE,
    	      	      	0,
    	      	      	s,
    	      	      	PREFIX " found apr extention version %d", found_apr_func_ver);
    	  if(apr_lve_environment_init_group_minuid_fn){
    		  apr_lve_environment_init_group_minuid_fn ((int)((1<<2)|(1<<3)), //LVE_NO_MAXENTER|LVE_SILENCE
    		      		        		(void *) lve,
    		      		        		(void *) lve_enter_flags_fn,
    		      		        		(void *) lve_exit_fn,
    		      		        		SUEXEC_BIN,
    		      		        		use_group,
    		      		        		min_uid_cfg);
    		  ap_log_error (APLOG_MARK,
    		      		      	      APLOG_NOTICE,
    		      		      	      0,
    		      		      	      s,
    		      		      	      PREFIX " apr_lve_environment_init_group_minuid check ok");
    	  } else if(apr_lve_environment_init_group_fn){
    		  apr_lve_environment_init_group_fn ((int)((1<<2)|(1<<3)), //LVE_NO_MAXENTER|LVE_SILENCE
    		        				    (void *) lve,
    		        				    (void *) lve_enter_flags_fn,
    		        				    (void *) lve_exit_fn,
    		        				    SUEXEC_BIN,
    		        				    use_group);
    		  ap_log_error (APLOG_MARK,
    		      	      	      	APLOG_NOTICE,
    		      	      	      	0,
    		      	      	      	s,
    		      	      	      	PREFIX " apr_lve_environment_init_group check ok");
    	  } else if(apr_lve_environment_init_fn){
    		  apr_lve_environment_init_fn ((int)((1<<2)|(1<<3)), //LVE_NO_MAXENTER|LVE_SILENCE
    		        				    (void *) lve,
    		        				    (void *) lve_enter_flags_fn,
    		        				    (void *) lve_exit_fn,
    		        				    SUEXEC_BIN);
    		  ap_log_error (APLOG_MARK,
    		      		      	    APLOG_NOTICE,
    		      		      	    0,
    		      		      	    s,
    		      		      	    PREFIX " apr_lve_environment_init check ok");
    	  }
      } else {
    	  ap_log_error (APLOG_MARK,
    			  	  	APLOG_WARNING,
    	      		    0,
    	      		    s,
    	      		    PREFIX " apr_lve_* not found!!!");
      }
#ifdef REDIS
          if(redis_flag){
                  redis_connection = NULL;
                  apr_status_t mrv = apr_thread_mutex_create(&mutex_redis, APR_THREAD_MUTEX_DEFAULT, s->process->pool);
                  if(mrv==APR_SUCCESS){
                          apr_pool_cleanup_register (s->process->pool, NULL, (void *) destroy_redis_pool,
                                             (void *)destroy_redis_pool);
                  }
#ifdef REDIS_USE_MUTEX
                  ap_log_error (APLOG_MARK,
                                        APLOG_NOTICE,
                                        0,
                                        s,
                                        PREFIX " enabled mutex mode");
#else
                  ap_log_error (APLOG_MARK,
                                        APLOG_NOTICE,
                                        0,
                                        s,
                                        PREFIX " disabled mutex mode");
#endif
          }
#endif

    }
  else
    {
      ap_log_error (APLOG_MARK,
		    APLOG_ERR,
		    0,
		    s,
		    PREFIX " version " MOD_HOSTINGLIMITS_VERSION
		    ". LVE mechanism disabled, LVE is unavailable. Errno %d", errno_global);
    }

#ifdef ENVSAFE
  buildModEnvBaseConfig(pconf, s);
#endif

  //Create special file for suexec signaling about mod_hostinglimits presence
#ifdef SUEXECBUILD
  apr_status_t rv;
  apr_file_t *fp;
  rv = apr_file_open (&fp, MOD_HOSTINGLIMITS_SIGNAL,
		      APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE | APR_FOPEN_WRITE,
		      APR_OS_DEFAULT, ptemp);
  if (rv != APR_SUCCESS)
    {
      ap_log_error (APLOG_MARK,
		    APLOG_ERR,
		    errno,
		    s,
		    PREFIX " version " MOD_HOSTINGLIMITS_VERSION
		    ". mod_hostinglimits: can't create indicator file "
		    MOD_HOSTINGLIMITS_SIGNAL
		    ". Suexec will work in non-LVE mode");
    }
  else
    {
      apr_file_printf (fp, "%d", getpid ());
      apr_file_flush (fp);
      apr_file_close (fp);
      /*
       * Почему выбран именно pconf пул, а не s->process->pool?
       * Выписка из документации:
       * Освобождение пула должно производиться до момента выгрузки модуля, в противном
       * случае процедура освобождения ресурсов, являющаяся одной из процедур модуля, к моменту
       * освобождения пула окажется выгруженной из памяти вместе с остальными процедурами и
       * функциями модуля и освобождение ресурсов системы не произойдет (более того, попытка
       * передачи управления по "не действительному" адресу процедуры освобождения ресурсов
       * приведет к некорректному завершению всего процесса сервера Apache).
       * Это подтвердилось экспериметально, процесс apache падает при выходе,
       * если lve_file_destroy регистрировать в process->pool
       */
      apr_pool_cleanup_register (pconf, NULL, (void *) lve_file_destroy,
				 apr_pool_cleanup_null);
    }
#endif

  return OK;
}

#define MAX_REGEX_LEN 255

// Function searches handler in handler_list
// returns 1 if found, 0 if not
static int
match_handler (apr_array_header_t * handlers_list, const char *handler)
{
  int num_names;
  char **names_ptr;
  char *regex_begin_ptr;	// Pointer to "%" character in the beginning of regex
  char *regex_end_ptr;		// Pointer to "%" character in the end of regex
  char regex_str[MAX_REGEX_LEN + 1];	// Buffer to copy regex from handler_list
  int regex_len;		// Length of regex

#ifdef APACHE2_2
  ap_regex_t compiled_regex;	// Compiled regex buffer
#else
  regex_t compiled_regex;	// Compiled regex buffer
#endif

  if (handlers_list && handler)
    {
      names_ptr = (char **) handlers_list->elts;
      num_names = handlers_list->nelts;

      // Scan handlers_list
      for (; num_names; ++names_ptr, --num_names)
	{			// Match all the handlers ?
	  if (!strcmp ("*", *names_ptr))
	    return 1;

	  // Current string in handlers_list is regex ?
	  if (regex_begin_ptr = strchr (*names_ptr, '%'))
	    {
	      // Get pointer to "%" character in the end of regex
	      regex_end_ptr = strchr (*names_ptr + 1, '%');

	      // End of regex is not found ?
	      if (!regex_end_ptr)
		continue;

	      // Calculate regex length
	      regex_len = regex_end_ptr - regex_begin_ptr - 1;

	      // Regex is too short or too long ?
	      if ((regex_len < 1) || (regex_len > MAX_REGEX_LEN))
		continue;

	      // Make copy of regex
	      strncpy (regex_str, regex_begin_ptr + 1, regex_len);
	      regex_str[regex_len] = '\0';

#ifdef APACHE2_2
	      // Compile regex. Error ?
	      if (ap_regcomp
		  (&compiled_regex, regex_str,
		   AP_REG_EXTENDED | AP_REG_NOSUB))
		continue;

	      // Match handler against compiled regex. Match is found ?
	      if (!ap_regexec (&compiled_regex, handler, 0, NULL, 0))
		{
		  ap_regfree (&compiled_regex);
		  return 1;
		}
	      else
		{
		  ap_regfree (&compiled_regex);
		  continue;
		}
#else
	      // Compile regex. Error ?
	      if (regcomp (&compiled_regex, regex_str,
			   REG_EXTENDED | REG_NOSUB))
		continue;

	      // Match handler against compiled regex. Match is found ?
	      if (!regexec (&compiled_regex, handler, 0, NULL, 0))
		{
		  regfree (&compiled_regex);
		  return 1;
		}
	      else
		{
		  regfree (&compiled_regex);
		  continue;
		}
#endif
	    }

	  // Compare strings literally
	  if (!strcmp (handler, *names_ptr))
	    return 1;
	}
    }

  return 0;
}

#ifdef APACHE2_0
/**
 * Find DocumentError from mod_core
 */
int readErrorDocument(request_rec * r, hostinglimits_module_cfg * cfg){
	core_dir_config *conf = ap_get_module_config(r->per_dir_config,
	                                                 &core_module);
	if (conf){
		if (conf->response_code_strings){
			int index_number, idx500 = ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);
			if ((index_number = ap_index_of_response(508)) == idx500) {
			        return 0;
			}
			if (!conf->response_code_strings[index_number]){
				return 0;
			}
			return 1;
		}
	}
	return 0;
}
#endif

static int
process_lve_error (request_rec * r, hostinglimits_module_cfg * cfg)
{
  //Set out header LVE_RETRY_AFTER
  if (cfg->retryAfter)
    {
      apr_table_setn (r->err_headers_out, "Retry-After",
		      apr_ltoa (r->pool, cfg->retryAfter * 60));
    }
#ifdef APACHE2_0
  // LVEErrorCode is NOT 508 or "ErrorDocument 508" directive is present in Apache configuration ?
    if ((cfg->http_error_code != 508) || (readErrorDocument(r, cfg)))
      return cfg->http_error_code;
#else
  // LVEErrorCode is NOT 508 or "ErrorDocument 508" directive is present in Apache configuration ?
  if ((cfg->http_error_code != 508) || (cfg->err_doc_found))
    return cfg->http_error_code;
#endif

  int i;
  r->status = 508;
  r->content_type = "text/html";
  apr_bucket_brigade *bb = apr_brigade_create (r->pool,
					       r->connection->bucket_alloc);
  ap_basic_http_header (r, bb);

  // Send header information only (HEAD request) ?
  if (r->header_only)
    return DONE;

  ap_rvputs (r, "\n"
	     DOCTYPE_HTML_2_0
	     "<HTML><HEAD>\n<TITLE>508 Resource Limit Is Reached</TITLE>\n"
	     "</HEAD><BODY>\n" "<H1>Resource Limit Is Reached</H1>\n", NULL);
  for (i = 0; i < 1000; i++)
    ap_rvputs (r, "      \n", NULL);
  ap_rputs
    ("The website is temporarily unable to service your request as it exceeded resource limit.\n"
     "Please try again later.\n", r);
  ap_rputs (ap_psignature ("<HR>\n", r), r);
  ap_rputs ("</BODY></HTML>\n", r);
  ap_finalize_request_protocol (r);
  ap_rflush (r);
  return DONE;
}


char *
get_regexp_match (
		apr_pool_t *pool,
#ifdef APACHE2_2
		ap_regex_t *rx,
#else
		regex_t * rx,
#endif
		char *buf,
		int match)
{
  int result;
#ifdef APACHE2_2
  ap_regmatch_t *matches;
#else
  regmatch_t *matches;
#endif
  char *bbuf;
  if (rx->re_nsub < match)
    {
      return NULL;
    }
#ifdef APACHE2_2
  matches = (ap_regmatch_t *) apr_palloc (pool, (rx->re_nsub + 1) * sizeof (ap_regmatch_t));
#else
  matches = (regmatch_t *) apr_palloc (pool, (rx->re_nsub + 1) * sizeof (regmatch_t));
#endif
  if (!matches)
    {
      return NULL;
    }
  if (!buf || !buf[0])
    return NULL;
#ifdef APACHE2_2
  result = ap_regexec (rx, buf, rx->re_nsub + 1, matches, 0);
#else
  result = regexec (rx, buf, rx->re_nsub + 1, matches, 0);
#endif
  if (!result)
    {
      int i;
      for (i = 0; i <= rx->re_nsub; i++)
	{
	  if ((matches[i].rm_so != -1) && (i == match))
	    {
	      bbuf = apr_psprintf (pool, "%.*s", matches[i].rm_eo - matches[i].rm_so,
		       buf + matches[i].rm_so);
	      return bbuf;
	    }
	}
    }
  return NULL;
}

#ifdef ENVSAFE
typedef struct {
    apr_table_t *vars;
    apr_table_t *unsetenv;
} env_dir_config_rec_copy;

#define MOD_ENVC "mod_env.c"

void buildModEnvBaseConfig(apr_pool_t *p, server_rec *s){
	int res;
	tab = apr_hash_make(p);
	if(tab){
		module *modenv_c = NULL;
		modenv_c = ap_find_linked_module(MOD_ENVC);
		if(modenv_c){
			for (s = s->next; (res == OK) && s; s = s->next) {
				env_dir_config_rec_copy *pconf = (env_dir_config_rec_copy*)ap_get_module_config(s->module_config, modenv_c);
				hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) ap_get_module_config (s->module_config, &hostinglimits_module);
				if(pconf&&pconf->vars){
					const apr_array_header_t *tarr = apr_table_elts(pconf->vars);
					const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
					int i;
					char *need_header = NULL;
					if(cfg->header){
						need_header = cfg->header;
					} else {
						need_header = apr_pstrdup(p, X_LVE_ID);
					}

					for (i = 0; i < tarr->nelts; i++) {
						if(!apr_strnatcasecmp(telts[i].key, need_header)){
							server_rec **key = apr_palloc(p, sizeof(server_rec *));
							if(key){
								*key = s;
								apr_hash_set(tab, key, sizeof(server_rec **), (const void *)apr_pstrdup(p, telts[i].val));
							}
						}

					}

				}
			}


		}
	}
}

int getEnvironmentValue(request_rec * r, hostinglimits_module_cfg * cfg){
	server_rec *s = r->server;
	int find_uid = 0;
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(NULL, tab); hi; hi = apr_hash_next(hi)){
	    	const server_rec **k;
	    	const char *v;

	    	apr_hash_this(hi, (const void**)&k, NULL, (void**)&v);
	    	if(s==*k){
	    		if(v){
	    			find_uid = (int) ap_uname2id(v);
	    		}
	    		break;
	    	}
	}
	if(find_uid)
	 return find_uid;
	else
	 return -1;
}

#else
int getEnvironmentValue(request_rec * r, hostinglimits_module_cfg * cfg){
	const char *result = NULL;
	if(r->subprocess_env){
	  if(cfg->header){
		  result = apr_table_get(r->subprocess_env, (const char *)cfg->header);
	  } else {
		  result = apr_table_get(r->subprocess_env, (const char *)X_LVE_ID);
	  }
	}
	if(result){
		return (int)ap_uname2id(result);
	} else {
		return 0;
	}
}
#endif

#ifdef APACHE2_0
typedef struct {
    int engine; // Status of suPHP_Engine
    char *php_config;
    int cmode;  // Server of directory configuration?
    char *target_user;
    char *target_group;
    apr_table_t *handlers;
    char *php_path;
} suphp_conf_lve;
#endif

uid_t get_suphp_uid(request_rec * r, hostinglimits_module_cfg * cfg, int use_grp){
#ifndef APACHE2_0
	if(use_grp)
		return (uid_t)cfg->suphp_gid;
	else
		return cfg->suphp_uid;
#else
	module *suphp_c = NULL;
	suphp_c = ap_find_linked_module(SUPHP_MODULE);
	if(suphp_c){
		suphp_conf_lve *pconf = (suphp_conf_lve*)ap_get_module_config(r->per_dir_config, suphp_c);
		if(pconf && pconf->target_user && pconf->target_group){
			if(use_grp)
				return ap_gname2id(pconf->target_group);
			else
				return ap_uname2id(pconf->target_user);
		}
	}
	return 0;
#endif
}


/* Use group ID
 * LVEId/LVEUser + UseGroupID - not work (always standard mode)
 * Suexec, Ruid2, itk, SuPHP + UseGroupID - work (UID/GID)
 * PATH + UseGroupID - not work (always standard mode)
 * OWNER + UseGroupID - work (user or group of file)
 * HEADER + UseGroupID - not work (always standard mode)
 */
int
get_lve_id (request_rec * r, hostinglimits_module_cfg * cfg
#ifdef REDIS
		, struct liblve_settings *lve_data, char *pw_dir
#endif
)
{
  int lve_id;
  uid_t uid = 0;
  //Priority steps
  // 1) LVEId
  // 2) LVEUser

  //enter into lve
  //1) check if set LVEId
  lve_id = cfg->lve_id;
  if (lve_id > 0) return lve_id;
  //2) if LVEId is unset and set LVEUser, get id here

  if (cfg->lve_user)
  {
  	  //if LVEUser set on, read it
    lve_id = (int) ap_uname2id (cfg->lve_user);
    if (lve_id < 1) return 0;
    return lve_id;
  }

  switch (cfg->mode)
    {
    case 0:
    {
        //Priority steps
        // 3) SuexecUserGroup
        // 4) RUidGid
        // 5) AssignUserID
    	// 6) suPHP_UserGroup

    	//Get uid from suexec
      ap_unix_identity_t *ugid = ap_run_get_suexec_identity (r);
      if (ugid != NULL)
    	  if(use_group)
    		  return ugid->gid;
    	  else
    		  return ugid->uid;

	  //4) still less then need, than check ruid2
	  //check for ruid2
	  if (cfg->ruid_uid > 0)
		  if(use_group)
		      return cfg->ruid_gid;
		  else
			  return cfg->ruid_uid;

	  //5) still less then need, than check itk
	  //check for itk, if lve_id still less then 0
	  if (cfg->itk_uid > 0)
		  if(use_group)
		  	  return cfg->itk_gid;
		  else
			  return cfg->itk_uid;

	  //6) still less then need, than check suPHP
	  uid_t tmp_suphp = get_suphp_uid(r, cfg, use_group);
	  if (tmp_suphp > 0)
		  return tmp_suphp;
    }
	  return 0;

    case 1:			//PATH
    {
    	char *user_name = NULL;
    	//Parse path
    	apr_finfo_t st;
    	//Check if file exists
    	if(apr_stat(&st, r->filename, APR_FINFO_NORM, r->pool)==APR_SUCCESS){
    		int need_prcd = 1;
#ifdef APACHE2_2
    		ap_regex_t rx;
    		if (ap_regcomp (&rx, cfg->path_regex, AP_REG_EXTENDED)){
    			need_prcd=0;
    		}
#else
    		regex_t rx;
    		if (regcomp (&rx, cfg->path_regex, REG_EXTENDED)){
    			need_prcd=0;
    		}
#endif
    		//Get user name from path
    		if (need_prcd) {
    			user_name = get_regexp_match(r->pool, &rx, r->filename, 1);
#ifdef APACHE2_2
    			ap_regfree (&rx);
#else
    			regfree (&rx);
#endif
    		}
    		int find_uid = 0;
    		if(user_name){
    			//Find user id
    		    find_uid = (int) ap_uname2id(user_name);
    		    if (find_uid > 0) return find_uid;
    		}
    	}
    }
    return 0;
    case 2:			//OWNER
    {
    	apr_finfo_t st;
    	if(apr_stat(&st, r->filename, APR_FINFO_NORM, r->pool)==APR_SUCCESS){
    		if(use_group)
    			return (int)st.group;
    		else
    			return (int)st.user;
    	}
    }
      return 0;
    case 3:			//HEADER
    {
    	/*
    	 * There are exists to ways
    	 * 1) one way - to read environment variables, safeless way
    	 * because variable can be set into .htaccess
    	 * 2) on the beginning of the process - to read mod_env
    	 * configuration into array per vhost. We lost per-dir configuration
    	 * in this case
    	 */

    	return getEnvironmentValue(r, cfg);

    }
      break;
#ifdef REDIS
    case 4:			//REDIS
        {
        	/*
        	 * There are exists to ways
        	 * 1) one way - to read environment variables, safeless way
        	 * because variable can be set into .htaccess
        	 * 2) on the beginning of the process - to read mod_env
        	 * configuration into array per vhost. We lost per-dir configuration
        	 * in this case
        	 */

        	return get_redis_id(r, cfg, lve_data, pw_dir);

        }
     break;
#endif
    }
  return -1;
}

#ifndef strnlen
size_t strnlen(const char *s, size_t maxlen)
{
	size_t len;
	for (len = 0; len < maxlen; len++, s++) {
        if (!*s)
          break;
    }
    return (len);
}
#endif

static int mod_hostinglimits_file_exist (char *filename)
{
  struct stat   buffer;
  if(filename){
      return (stat (filename, &buffer) == 0);
  } else {
	  return 0;
  }
}

static char * get_redis_home_path_from_file_name(char *path, apr_pool_t *p){
	char *result = NULL;
	int len = 0, i = 0, j = 0;
	if(path){
		result = apr_pstrdup(p, path);
		if(result){
			len = strnlen(result, PATH_MAX);
			for(i=0;i<len;i++){
				if(result[i]=='/'){
					j++;
					if(j==8){
						result[i]=0;
						return result;
					}
				}
			}
		}
	}
	if(j==7) {
		result[len - 1] = 0;
		return result;
	}
	else return NULL;
}

#define X_LVE_ID_HEADER "X_LVE_ID_HEADER"

/**
 * Where are main functionality in this function.
 * This funcion performs after reading request headers
 * and before other processing.
 *
 *
 */
static int
enter_lve_handler (request_rec * r)
{
  char err_message_url[MAX_ERROR_URL_LEN];
  // get directory config info
  apr_status_t st;

  int is_in_lve_flag = 0;

  intptr_t need_debug = MOD_HOSTINGLIMITS_UNNEED_DEBUG;

  hostinglimits_module_cfg *cfg = hostinglimits_module_dconfig (r);

  if (!lve_available || !cfg)
    {
      return DECLINED;
    }

  //register filter everey time for checking LVE
  if(registered_filter) {
	  ap_add_output_filter("MODHOST_LVE_FILTER", NULL, r, r->connection);
  }

  struct passwd pd;
  struct passwd *pwdptr;
  char pwdbuffer[pw_buff];
  int found_home_dir = 0;

  int lve_id = 0;
  struct liblve_settings lve_data = { -1, -1, -1, -1, -1, -1, -1, -1 };
  struct limits_t limits_data;
  /* Parallels */
  int is_paralles = 0;
  enum liblve_enter_flags p_flags = 0;
  /* Pralllels */
#ifdef REDIS
  lve_id = get_lve_id (r, cfg, &lve_data, pwdbuffer);
#else
  /* Paralles */
  if(cgid_pfn_limits_lookup_ex && !cgid_pfn_limits_lookup_ex(r->connection, r->hostname, &limits_data)) {
	  core_dir_config *CORE_conf = ap_get_module_config(r->per_dir_config, &core_module);
	  lve_id = limits_data.uid;
	  lve_data = (struct liblve_settings){
		  ((cpu_limit==-1)?limits_data.lve_cpu:cpu_limit),
		  ((ncpu_limit==-1)?0:ncpu_limit),
		  ((limits_data.fields & io_lim)?limits_data.lve_io:io_limit),
		  (ep_limit==-1?limits_data.lve_nproc:ep_limit),
		  0,
		  100,
		  ((CORE_conf->limit_mem)?(CORE_conf->limit_mem->rlim_max/ 1024 / 4):((mem_limit != -1)?(mem_limit * 256):-1)), //256 = (1024 * 1024)/1024/4
		  (ep_limit==-1?limits_data.lve_nproc:ep_limit) };
	  if(cfg->lve_id>0){
		  lve_id = cfg->lve_id;
	  }
	  if((ep_limit==-1?limits_data.lve_nproc:ep_limit) <= 0)
		  p_flags |= LVE_NO_MAXENTER;
	  is_paralles = 1;
  }
  /* Parallels */

  if(!is_paralles){
	  lve_id = get_lve_id (r, cfg);
  }
#endif

  apr_threadkey_private_get ((void *) &need_debug, debug_key);
  if (!need_debug)
    {
      need_debug = get_need_debug (cfg->debug_sites, r);
      if (need_debug == MOD_HOSTINGLIMITS_UNNEED_DEBUG) {
    	  need_debug = get_need_debug_uids (cfg->debug_uids, lve_id);
      }
      st = apr_threadkey_private_set (NULL, debug_key);
      apr_threadkey_private_set ((void *) need_debug, debug_key);
    }

  CHECK_DEBUG
    {
      ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, PREFIX
  		  "[DEBUG] STEP#0001 LVE(%d) PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno %d, POOL %d",
  		  lve_id, p_cookie, r->handler, r->hostname, r->uri,
  		  gettid (), errno, r->pool ? r->pool : 0);
    }

    //lets find handlers for which HostingLimits should NOT run...
  // Check if handler is NOT in allowed_handlers list or if handler is in denied_handlers list
  if ((!match_handler (cfg->allowed_handlers, r->handler))
      || match_handler (cfg->denied_handlers, r->handler))
    {
      return DECLINED;
    }

  //enter into lve

  CHECK_DEBUG
  {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, PREFIX
		  "[DEBUG] STEP#0002 LVE(%d) PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno %d, POOL %d",
		  lve_id, p_cookie, r->handler, r->hostname, r->uri,
		  gettid (), errno, r->pool ? r->pool : 0);
  }

  /* decline if cookie is set ( p_cookie != 0) */

	  /*st = apr_threadkey_private_get ((void *) &p_cookie, key);

	  CHECK_DEBUG
	  {
		  ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, PREFIX
  		  "[DEBUG] STEP#0002.1 PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno %d POOL %d",
  		  p_cookie, r->handler, r->hostname, r->uri, gettid (), errno,
  		  r->pool ? r->pool : 0);
	  }
	  if (st != APR_SUCCESS)
	  {
		  return DECLINED;
	  }
	  */

  	  char *tmp_res = (char *)apr_table_get(r->notes, X_LVE_ID_HEADER);
  	  if(!tmp_res){
  		 char *tmp_lve_id = apr_psprintf(r->pool, "%d",
  		                                 lve_id);
  		  apr_table_set(r->notes, X_LVE_ID_HEADER, tmp_lve_id);
  	  } else {
  		char *tmp_lve_id = apr_psprintf(r->pool, "%d",
  		  		                                 lve_id);
  		if(strcmp(tmp_res, tmp_lve_id)){
  			apr_table_set(r->notes, X_LVE_ID_HEADER, tmp_lve_id);
  		}
  	  }


	  //We already in LVE (try to exit before entering)
	  if (p_cookie != 0) {
		  if(lve_uid_thd != lve_id){
			  int rc = (*lve_exit_fn) (lve, &p_cookie);
			  p_cookie = 0;
			  if (rc){
				  CHECK_DEBUG
				  {
					  ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, PREFIX
							  "[DEBUG] STEP#0002.2 PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno %d POOL %d",
							  p_cookie, r->handler, r->hostname, r->uri, gettid (), errno,
							  r->pool ? r->pool : 0);
				  }
				  ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server, PREFIX
                             "Can't leave old LVE: LVE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d)",
                             lve_id, r->handler, r->hostname, r->uri,
                             gettid ());
				  return DECLINED;
			  }
		  } else {
			  is_in_lve_flag = 1;
		  }
	  }




  if ((lve_id > min_uid_cfg) && (!is_in_lve_flag) && (lve_id>0))
    {

	  int rc = 0;
#ifdef REDIS
	  if ((cfg->mode==4) && (lve_data.ls_cpu>=0))
		 rc = (*lve_setup_enter_fn) (lve, lve_id, &lve_data, &p_cookie, 0);
	  else
      {
#endif
		  if(is_paralles){

			  rc = (*lve_setup_enter_fn)(lve, lve_id, &lve_data, &p_cookie, p_flags);
		  } else {
			  rc = (*lve_enter_flags_fn) (lve, lve_id, &p_cookie, 0);
		  }
#ifdef REDIS
      }
#endif
      int keep_errno = errno;
      CHECK_DEBUG
      {
	ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server, PREFIX
		      "[DEBUG] STEP#0003 LVE(%d) PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno %d POOL %d",
		      lve_id, p_cookie, r->handler, r->hostname, r->uri,
		      gettid (), errno, r->pool ? r->pool : 0);
      }

      if (rc)
	{
	  if (keep_errno == EPERM)
	    {			//if already inside LVE
	      ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server, PREFIX
			    "Already inside LVE: LVE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno (%d)%s min_uid (%d)",
			    lve_id, r->handler, r->hostname, r->uri,
			    gettid (), keep_errno, getErrorUrl(err_message_url, keep_errno), min_uid_cfg);
	      return DECLINED;
	    }

	  ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
			PREFIX
			"Error on LVE enter: LVE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) TID(%d) errno (%d)%s min_uid (%d)",
			lve_id, r->handler, r->hostname, r->uri, gettid (),
			keep_errno, getErrorUrl(err_message_url, keep_errno), min_uid_cfg);
	  return process_lve_error (r, cfg);
	}


    lve_uid_thd = lve_id;
    /*st = apr_threadkey_private_set ((void *)(intptr_t) p_cookie, key);
    if (st != APR_SUCCESS)
    {
    	ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
    		PREFIX "Unable to set LVE cookie %d%s", st, getErrorUrl(err_message_url, (int)HTTPD_ERROR_LVE_COCKIE));
    }*/

    }

  return DECLINED;
}

static int
leave_lve_handler (request_rec * r)
{
  char err_message_url[MAX_ERROR_URL_LEN];
  apr_status_t st;

  if (!lve_available)
    {
      return DECLINED;
    }

  if(registered_filter) {
	  return DECLINED;
  }

  hostinglimits_module_cfg *cfg = hostinglimits_module_dconfig (r);

  intptr_t need_debug;
  apr_threadkey_private_get ((void *) &need_debug, debug_key);
  if (need_debug != MOD_HOSTINGLIMITS_NEED_DEBUG)
    {
      need_debug = MOD_HOSTINGLIMITS_UNNEED_DEBUG;
    }
  apr_threadkey_private_set (NULL, debug_key);

  //st = apr_threadkey_private_get ((void *) &p_cookie, key);
  CHECK_DEBUG
  {
    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server,
		  PREFIX "[DEBUG] STEP#0004 PCOOKIE(%d) TID(%d) POOL %d",
		  p_cookie, gettid (), r->pool ? r->pool : 0);
  }

  /* if cookie is not initialized or if it is not 0 -- don't try to leave */
  if (p_cookie == 0)
    {
      return DECLINED;
    }

  int rc = (*lve_exit_fn) (lve, &p_cookie);
  p_cookie = 0;
  if (!rc)
    {
      /* reset cookie to 0 */
      //st = apr_threadkey_private_set (NULL, key);
      lve_uid_thd = 0;

     /* if (st != APR_SUCCESS)
	{
	  ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
			PREFIX "Unable to reset LVE cookie %d", st, getErrorUrl(err_message_url, (int)HTTPD_ERROR_LVE_COCKIE_RESET));
	}*/
      return DECLINED;
    }
  ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
		PREFIX "Error exiting %d", rc);
  return DECLINED;
}

static apr_status_t ap_lve_out_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
	request_rec * r = f->r;

	  char err_message_url[MAX_ERROR_URL_LEN];
	  apr_status_t st;

	  if (!lve_available)
	    {
		  ap_remove_output_filter(f);
		  return ap_pass_brigade(f->next, in);
	    }

	  if(!registered_filter) {
		  ap_remove_output_filter(f);
		  return ap_pass_brigade(f->next, in);
	  }

	  hostinglimits_module_cfg *cfg = hostinglimits_module_dconfig (r);

	  intptr_t need_debug;
	  apr_threadkey_private_get ((void *) &need_debug, debug_key);
	  if (need_debug != MOD_HOSTINGLIMITS_NEED_DEBUG)
	    {
	      need_debug = MOD_HOSTINGLIMITS_UNNEED_DEBUG;
	    }
	  apr_threadkey_private_set (NULL, debug_key);

	  CHECK_DEBUG
	  {
	    ap_log_error (APLOG_MARK, APLOG_NOTICE, 0, r->server,
			  PREFIX "[DEBUG] STEP#0004.11 PCOOKIE(%d) TID(%d) POOL %d",
			  p_cookie, gettid (), r->pool ? r->pool : 0);
	  }

	  /* if cookie is not initialized or if it is not 0 -- don't try to leave */
	  if (p_cookie == 0)
	    {
		  ap_remove_output_filter(f);
		  return ap_pass_brigade(f->next, in);
	    }

	  int rc = (*lve_exit_fn) (lve, &p_cookie);
	  p_cookie = 0;
	  if (!rc)
	    {
	      /* reset cookie to 0 */
	      lve_uid_thd = 0;
	      ap_remove_output_filter(f);
	      return ap_pass_brigade(f->next, in);
	    } else {
	    	ap_log_error (APLOG_MARK, APLOG_ERR, OK, r->server,
	    			PREFIX "Error exiting %d", rc);
	    }

	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next, in);
}

static apr_status_t
destroy_key_pool (void *dummy)
{
  apr_threadkey_private_delete (key);
  apr_threadkey_private_delete (debug_key);
  return APR_SUCCESS;
}

static void
hostinglimits_child_init (apr_pool_t * p, server_rec * s)
{
  apr_pool_cleanup_register (p, 0, destroy_key_pool, destroy_key_pool);
  apr_threadkey_private_create (&key, NULL, p);
  apr_threadkey_private_create (&debug_key, NULL, p);

}

apr_pool_t *lve_pool;
void *lve_alloc(int size) {
	return apr_palloc(lve_pool, size);
}

static char * strnstr(s, find, slen)
        const char *s;
        const char *find;
        size_t slen;
{
        char c, sc;
        size_t len;

        if ((c = *find++) != '\0') {
                len = strlen(find);
                do {
                        do {
                                if (slen-- < 1 || (sc = *s++) == '\0')
                                        return (NULL);
                        } while (sc != c);
                        if (len > slen)
                                return (NULL);
                } while (strncmp(s, find, len) != 0);
                s--;
        }
        return ((char *)s);
}

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	apr_pool_t *p = (apr_pool_t *)data;
#ifdef APACHE2_2
    if (strnstr(info->dlpi_name, "libapr-1.so", PATH_MAX)){
#else
    if (strnstr(info->dlpi_name, "libapr-0.so", PATH_MAX)){
#endif
        void* library = dlopen (info->dlpi_name, RTLD_LAZY);
        apr_lve_environment_init_fn = dlsym(library, "apr_lve_environment_init");
        apr_lve_environment_init_group_fn = dlsym(library, "apr_lve_environment_init_group");
        apr_lve_environment_init_group_minuid_fn = dlsym(library, "apr_lve_environment_init_group_minuid");
        apr_pool_cleanup_register (p, library, (void *) dlclose,
        				     apr_pool_cleanup_null);
        return 1;
    }

   return 0;
}


static void get_lve_func_names(apr_pool_t * p){
	dl_iterate_phdr(callback, (void*)p);
}

void lve_var_log_config_register(apr_pool_t *p);

static int lve_hook_pre_config(apr_pool_t *pconf,
                               apr_pool_t *plog,
                               apr_pool_t *ptemp)
{


    /* Register us to handle mod_log_config %c/%x variables */
    lve_var_log_config_register(pconf);

    return OK;
}

// function for hook register
static void
hostinglimits_module_register_hooks (apr_pool_t * p)
{
  int rc = -1;
  errno = 0;
  pw_buff = sysconf(_SC_GETPW_R_SIZE_MAX);
  /* hostinglimits_module_register_hooks called twice */

  if (lve == NULL)
    {

	  if(load_liblve(p)>=0){

		  lve_pool = p;
		  lve = (*init_lve_fn)((liblve_alloc)lve_alloc, NULL);
		  errno_global = errno;
		  lve_pool = NULL;

		  if (lve != NULL)
		  {
			  lve_available = 1;
			  // register clean up LVE
			  apr_pool_cleanup_register (p, lve, (void *) destroy_lve_fn,
				     apr_pool_cleanup_null);
#ifndef SUEXECBUILD

			  get_lve_func_names(p);
			  if(apr_lve_environment_init_group_minuid_fn){
				  found_apr_func_ver = 3;
			  } else if(apr_lve_environment_init_group_fn){
				  found_apr_func_ver = 2;
			  } else if(apr_lve_environment_init_fn){
				  found_apr_func_ver = 1;
			  }

#endif
		  } else {
			  lve_available = 0;
		  }
	  } else {
	  	  lve_available = 0;
	  }
    }
    
    read_cagefs_min_uid();

  static const char *const aszPre[] = { "mod_include.c", "mod_php.c",
    "mod_cgi.c", NULL
  };
#ifdef APACHE2_2
  static const char *const defaultPre[] =
      {"mod_core.c", "core.c", NULL };
#endif

  ap_hook_post_config (init_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
  ap_hook_handler (enter_lve_handler, NULL, aszPre, APR_HOOK_REALLY_FIRST);
  ap_hook_log_transaction (leave_lve_handler, NULL, NULL, APR_HOOK_LAST);
  ap_hook_child_init (hostinglimits_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_pre_config (lve_hook_pre_config,    NULL,NULL, APR_HOOK_MIDDLE);

  ap_register_output_filter("MODHOST_LVE_FILTER", ap_lve_out_filter,
                                NULL, AP_FTYPE_CONTENT_SET);

}

/*  _________________________________________________________________
**
**  LVE Extension to mod_log_config
**  _________________________________________________________________
*/

#include "mod_log_config.h"

static const char *lve_var_log_handler_y(request_rec *r, char *a);


void lve_var_log_config_register(apr_pool_t *p)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "y", lve_var_log_handler_y, 0);
    }
    return;
}

static char *ap_get_lve(request_rec *r){
	return (char *)apr_table_get(r->notes, X_LVE_ID_HEADER);;
}

char *lve_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var)
{
	hostinglimits_module_cfg *mp = (hostinglimits_module_cfg *) ap_get_module_config (r->per_dir_config,
								    &hostinglimits_module);
    const char *result;
    int resdup;

    result = NULL;

    /*
     * When no pool is given try to find one
     */
    if (p == NULL) {
        if (r != NULL)
            p = r->pool;
        else {
        	result = NULL;
        }
    }

    /*
     * Request dependent stuff
     */
    if (r != NULL) {
        if (!strcmp(var, "LVE_ID"))
           result = ap_get_lve(r);
    }

    if (result == NULL)
        result = "";
    return (char *)result;
}


static const char *lve_var_log_handler_y(request_rec *r, char *a)
{
    char *result;

    result = lve_var_lookup(r->pool, r->server, r->connection, r, a);
    if (result != NULL && result[0] == NULL)
        result = NULL;
    return result;
}


/**
 * Describing structure of Apache module
 */
module AP_MODULE_DECLARE_DATA hostinglimits_module =
  { STANDARD20_MODULE_STUFF,
  hostinglimits_module_create_dir_config,	/* create directory config */
  hostinglimits_module_merge_config,	/* merging directory config */
  NULL,				/* create server config */
  NULL,				/* merging server config */
  hostinglimits_module_directives,	/* mapping configuration directives */
  hostinglimits_module_register_hooks	/* registering hooks */
};
