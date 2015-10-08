/* Copyright Cloud Linux Inc 2010-2011 All Rights Reserved                                                                                                 
 *                                                                                                                                                         
 * Licensed under CLOUD LINUX LICENSE AGREEMENT                                                                                                            
 * http://cloudlinux.com/docs/LICENSE.TXT                                                                                                                  
 *                                                                                                                                                         
 * This is the hostinglimits module for apache 1.3.X                                                                                                       
 * author Igor Seletskiy <iseletsk@cloudlinux.com>                                                                                                         
 * author Alexey Berezhok <alexey.berezhok@cloudlinux.com>                                                                                                 
 * author Anton Volkov <avolkov@cloudlinux.com>
 *                                                                                                                                                         
 */

#ifndef APACHE1_3
#error "This source is for Apache version 1.3 only"
#endif

#define LVE_DEPRICATED

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "hsregex.h"

#include <stdio.h>

#include <lve/lve-ctl.h>

#define PREFIX "mod_hostinglimits:"

module MODULE_VAR_EXPORT hostinglimits_module;

//static APR_OPTIONAL_FN_TYPE(vh_info_lookup) *pfn_vh_info_lookup = NULL;

static int lve_available = 0;
struct liblve *lve = NULL;
static uint32_t p_cookie = 0;

// HTTP error code to return to client if resources limit is reached AND LVEErrorCode directive is not present in module configuration
#define DEFAULT_HTTP_ERROR_CODE 508

// HTTP error code should be in these limits
#define MAX_HTTP_SERVER_ERROR_CODE 510
#define MIN_HTTP_SERVER_ERROR_CODE 500

// configuration data
typedef struct hostinglimits_module_cfg
{
  unsigned int skip;
  uint32_t lve_id;
  array_header *allowed_handlers;	// A list of handlers which will be put in LVE
  array_header *denied_handlers;	// A list of handlers which will be NOT put in LVE
  unsigned int http_error_code;	// Integer HTTP error code to return to client if resources limit is reached
  array_header *debug_uid;
} hostinglimits_module_cfg;

static hostinglimits_module_cfg *
hostinglimits_module_dconfig (request_rec * r)
{
  return (hostinglimits_module_cfg *) ap_get_module_config (r->per_dir_config,
							    &hostinglimits_module);
}

static void *
hostinglimits_module_create_dir_config (pool * p, char *dirspec)
{

  hostinglimits_module_cfg *cfg =
    (hostinglimits_module_cfg *) ap_pcalloc (p,
					     sizeof
					     (hostinglimits_module_cfg));
  if (!cfg)
    {
      ap_log_error (APLOG_MARK, APLOG_ERR, NULL, PREFIX " not enough memory");
      return NULL;
    }
  cfg->skip = 0;
  cfg->lve_id = 0;
  cfg->allowed_handlers = NULL;
  cfg->denied_handlers = NULL;
  cfg->http_error_code = DEFAULT_HTTP_ERROR_CODE;
  cfg->debug_uid = NULL;
  return (void *) cfg;

}

static void *
hostinglimits_module_merge_config (pool * p, void *BASE, void *ADD)
{

  hostinglimits_module_cfg *base = BASE;
  hostinglimits_module_cfg *add = ADD;
  hostinglimits_module_cfg *cfg =
    (hostinglimits_module_cfg *) ap_pcalloc (p,
					     sizeof
					     (hostinglimits_module_cfg));
  cfg->skip = (add->skip) ? add->skip : base->skip;
  cfg->lve_id = (add->lve_id) ? add->lve_id : base->lve_id;
  cfg->allowed_handlers =
    (add->allowed_handlers) ? add->allowed_handlers : base->allowed_handlers;
  cfg->denied_handlers =
    (add->denied_handlers) ? add->denied_handlers : base->denied_handlers;
  cfg->http_error_code =
    (add->http_error_code) ? add->http_error_code : base->http_error_code;
  cfg->debug_uid =
      (add->debug_uid) ? add->debug_uid : base->debug_uid;
  return (void *) cfg;

}

static const char *
set_lve_id (cmd_parms * cmd, void *mcfg, const char *lve_id)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (lve_id)
    {
      cfg->lve_id = (uint32_t) atoi (lve_id);
    }
  return NULL;
}

static const char *
set_debug_uid (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err =
    ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->debug_uid)
    {
	  cfg->debug_uid = ap_make_array (cmd->pool, 2, sizeof (uid_t));
    }
  uid_t muid = (uid_t) atoi (arg);
  if(muid) *(uid_t*) ap_push_array (cfg->debug_uid) = muid;
  return NULL;
}

static const char *
set_skip (cmd_parms * cmd, void *mcfg, const char *skip)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  if (skip)
    {
      cfg->skip = (unsigned int) atoi (skip);
    }
  return NULL;
}

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
      cfg->http_error_code =
	get_valid_http_error_code ((unsigned int) atoi (lve_error_code));
    }
  return NULL;
}

static const char *
set_handlers (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err =
    ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->allowed_handlers)
    {
      cfg->allowed_handlers = ap_make_array (cmd->pool, 2, sizeof (char *));
    }
  *(const char **) ap_push_array (cfg->allowed_handlers) = arg;
  return NULL;
}

static const char *
set_handlers_to_deny (cmd_parms * cmd, void *mcfg, const char *arg)
{
  hostinglimits_module_cfg *cfg = (hostinglimits_module_cfg *) mcfg;
  const char *err =
    ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);
  if (err != NULL)
    {
      return err;
    }
  if (!cfg->denied_handlers)
    {
      cfg->denied_handlers = ap_make_array (cmd->pool, 2, sizeof (char *));
    }
  *(const char **) ap_push_array (cfg->denied_handlers) = arg;
  return NULL;
}

static int
hostinglimits_module_exit (request_rec * r)
{
  if (!p_cookie)
    {
      return DECLINED;
    }
  if (lve_available)
    {
      hostinglimits_module_cfg *cfg = hostinglimits_module_dconfig (r);

      if (!cfg)
	{
	  return DECLINED;
	}
      int rc = lve_exit (lve, &p_cookie);
      if (!rc)
	{
	  p_cookie = 0;
	  return DECLINED;
	}
      ap_log_error (APLOG_MARK, APLOG_ERR, r->server,
		    PREFIX "Error exiting %d", rc);
      //error exiting, lets kill it
      exit (-1);
    }

  return DECLINED;
}

pool *lve_pool;
void *lve_alloc(int size) {
	return ap_palloc(lve_pool, size);
}

static void
hostinglimits_initializer (server_rec * s, pool * p)
{
  int rc = -1;
  errno = 0;
  if (lve == NULL)
    {
	  lve_pool = p;
	  lve = init_lve(lve_alloc, NULL);
	  lve_pool = NULL;

      if (lve != NULL)
	{
	  lve_available = 1;
	  // register clean up LVE                                                                                                                               
	  ap_register_cleanup (p, lve, (void *) lve_instance_destroy,
			       ap_null_cleanup);
	}
      else
	{
	  lve_available = 0;
	}
    }
  //pfn_vh_info_lookup = APR_RETRIEVE_OPTIONAL_FN(vh_info_lookup);
  //i can't find APR_RETRIEVE_OPTIONAL_FN analog for apache 1.3.
  //it comes from apr_utils, will be apr_utils correct work with apache 1.3?
  //i disabled this function
  if (lve_available)
    {
      ap_log_error (APLOG_MARK, APLOG_NOTICE, s, "LVE mechanism enabled");
      //printf("LVE mechanism enabled\n");
    }
  else
    {
      ap_log_error (APLOG_MARK, APLOG_ERR, s,
		    "LVE mechanism disabled, LVE is unavailable");
      //printf("LVE mechanism disabled, LVE is unavailable\n");
    }
}

static int
match_uids (array_header * uids_list, uid_t uid_n){
	int num_names;
	uid_t * names_ptr;

	if (uids_list){
		names_ptr = (uid_t*) uids_list->elts;
		num_names = uids_list->nelts;

		for (; num_names; ++names_ptr, --num_names){
			if(*names_ptr == uid_n) return 1;
		}
	}
	return 0;
}

#define MAX_REGEX_LEN 255

// Function searches handler in handler_list
// returns 1 if found, 0 if not
static int
match_handler (array_header * handlers_list, const char *handler)
{
  int num_names;
  char **names_ptr;
  char *regex_begin_ptr;	// Pointer to "%" character in the beginning of regex
  char *regex_end_ptr;		// Pointer to "%" character in the end of regex
  char regex_str[MAX_REGEX_LEN + 1];	// Buffer to copy regex from handler_list
  int regex_len;		// Length of regex
  regex_t compiled_regex;	// Compiled regex buffer

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

	      // Compile regex. Error ?
	      if (regcomp
		  (&compiled_regex, regex_str, REG_EXTENDED | REG_NOSUB))
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
	    }

	  // Compare strings literally
	  if (!strcmp (handler, *names_ptr))
	    return 1;
	}
    }

  return 0;
}

static int
process_lve_error (request_rec * r, hostinglimits_module_cfg * cfg)
{
  // LVEErrorCode is NOT 508 ?
  if (cfg->http_error_code != 508)
    return cfg->http_error_code;

  r->status = 508;
  r->content_type = "text/html";
  ap_send_http_header (r);

  // Send header information only (HEAD request) ?
  if (r->header_only)
    return DONE;

  // Now send our actual output ("error 508" html-page)
  ap_rputs (DOCTYPE_HTML_3_2, r);
  ap_rputs ("<HTML>\n", r);
  ap_rputs (" <HEAD>\n", r);
  ap_rputs ("  <TITLE>508 Resource Limit Is Reached", r);
  ap_rputs ("  </TITLE>\n", r);
  ap_rputs (" </HEAD>\n", r);
  ap_rputs (" <BODY>\n", r);
  ap_rputs ("  <H1>Resource Limit Is Reached", r);
  ap_rputs ("  </H1>\n", r);
  ap_rputs
    ("The website is temporarily unable to service your request as it exceeded resource limit.\n"
     "Please try again later.\n", r);
  ap_rputs (" </BODY>\n", r);
  ap_rputs ("</HTML>\n", r);
  ap_finalize_request_protocol (r);
  ap_rflush (r);
  exit (1);
}

static int
enter_lve_fixups (request_rec * r)
{
  // get directory config info
  hostinglimits_module_cfg *cfg = hostinglimits_module_dconfig (r);
  if (p_cookie || !cfg || !lve_available)
    {
      // we are already in lve, or config not initiated - request declined
      return DECLINED;
    }
  if (lve_available)
    {
      //lets find handlers for which HostingLimits should run...

      // Check if handler is NOT in allowed_handlers list
      if ((!match_handler (cfg->allowed_handlers, r->handler))
	  && (!match_handler (cfg->allowed_handlers, r->content_type)))
	{
	  return DECLINED;
	}

      // Check if handler is in denied_handlers list
      if (match_handler (cfg->denied_handlers, r->handler)
	  || match_handler (cfg->denied_handlers, r->content_type))
	{
	  return DECLINED;
	}

      //enter into lve
      uid_t uid = 0;
      int lve_id = cfg->lve_id;

      uid = r->server->server_uid;
      if (lve_id < 1)
	{
	  lve_id = uid;
	}
      if (lve_id > 0)
	{
      if (match_uids(cfg->debug_uid, lve_id)) {
    	  ap_log_error (APLOG_MARK, APLOG_NOTICE, r->server, PREFIX
    	  		  "[DEBUG] STEP#0001 LVE (%d) PCOOKIE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s) errno %d POOL %d",
    	  		  lve_id, p_cookie, r->handler?r->handler:"NULL", r->hostname?r->hostname:"NULL", r->uri?r->uri:"NULL", errno,
    	  		  r->pool ? r->pool : 0);
      }
	  int rc = lve_enter_flags (lve, lve_id, &p_cookie, 0);	//todo add limits
	  if (rc)
	    {
	      if (errno == EPERM)
		{		//if already inside LVE
		  ap_log_error (APLOG_MARK, APLOG_ERR, r->server,
				PREFIX
				"Already inside LVE: LVE(%d) HANDLER(%s) HOSTNAME(%s) URL(%s)",
				lve_id, r->handler, r->hostname, r->uri);
		  return DECLINED;
		}

	      ap_log_error (APLOG_MARK, APLOG_ERR, r->server,
			    PREFIX "Error on LVE enter %d", errno);
	      p_cookie = 0;
	      return process_lve_error (r, cfg);
	    }
	}
    }
  return DECLINED;
}

static command_rec hostinglimits_module_directives[] = {
  {"SkipErrors", set_skip, NULL, RSRC_CONF, TAKE1,
   "Allow apache to continue even if LVE is unavalable"},
  {"LVEId", set_lve_id, NULL, ACCESS_CONF | RSRC_CONF, TAKE1, "LVE Id"},
  {"LVEUidsDebug", set_debug_uid, NULL, ACCESS_CONF | RSRC_CONF, ITERATE, "LVE Id for debug"},
  {"AllowedHandlers", set_handlers, NULL, RSRC_CONF, ITERATE,
   "A list of handlers which will be put in LVE"},
  {"DenyHandlers", set_handlers_to_deny, NULL, RSRC_CONF, ITERATE,
   "A list of handlers which will be NOT put in LVE"},
  {"LVEErrorCode", set_lve_error_code, NULL, RSRC_CONF, TAKE1,
   "Integer HTTP error code to return to client if resources limit is reached"},
  {NULL}
};


module hostinglimits_module = {
  STANDARD_MODULE_STUFF,
  hostinglimits_initializer,	/* initializer */
  hostinglimits_module_create_dir_config,	/* dir config creator */
  hostinglimits_module_merge_config,	/* dir merger --- default is to override */
  NULL,				/* server config */
  NULL,				/* merge server config */
  hostinglimits_module_directives,	/* command table */
  NULL,				/* handlers */
  NULL,				/* filename translation */
  NULL,				/* check_user_id */
  NULL,				/* check auth */
  NULL,				/* check access */
  NULL,				/* type_checker */
  enter_lve_fixups,		/* fixups */
  hostinglimits_module_exit,	/* logger */
  NULL,				/* header parser */
  NULL,				/* [3] header parser */
  NULL,				/* process initializer */
  NULL,				/* process exit/cleanup */
  NULL				/* [1] post read_request handling */
};

#undef CORE_PRIVATE
