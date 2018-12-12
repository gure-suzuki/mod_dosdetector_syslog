/*
 * Copyright (C) 2007 Hatena Inc.
 * The author is Shinji Tanaka <stanaka@hatena.ne.jp>.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice, and the
 * following disclaimer shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <arpa/inet.h>
//#include <netinet/in.h>
#define SYSLOG_NAMES
#include <sys/types.h>
//#include <unistd.h>
#include <time.h>
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "ap_config.h"
#include "ap_regex.h"
#include "apr_strings.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_sha1.h"
#include "apr_date.h"
#ifdef AP_NEED_SET_MUTEX_PERMS
#   include "unixd.h"
#endif

#if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
    static const char *DefaultContentType = "application/octet-stream";
#   define SERVER_CONF ap_server_conf
#   define LOG_MODULENAME
    APLOG_USE_MODULE(dosdetector_syslog);
#else
#   define SERVER_CONF NULL
#   define LOG_MODULENAME "dosdetector_syslog: "
#endif

//Don't forget change httpd.conf's LogLevel to `notice' and to set ErrorLog
//#define _DEBUG

#ifdef _DEBUG
#   define DEBUGLOG(...) ap_log_error(APLOG_MARK, \
                             APLOG_NOERRNO|APLOG_NOTICE, 0, SERVER_CONF, \
                             LOG_MODULENAME __VA_ARGS__)
#else
#   define DEBUGLOG(...) //
#endif

#define TRACELOG(...) ap_log_error(APLOG_MARK, \
                          APLOG_NOERRNO|APLOG_NOTICE, 0, SERVER_CONF, \
                          LOG_MODULENAME __VA_ARGS__)

#define MUTEX_LOCK(m,s) if ((rc = apr_global_mutex_lock(m)) != APR_SUCCESS) \
                            ap_log_error(APLOG_MARK, APLOG_WARNING, rc, s, \
                            LOG_MODULENAME "failed to lock mutex")
#define MUTEX_UNLOCK(m,s) if ((rc = apr_global_mutex_unlock(m)) != APR_SUCCESS) \
                              ap_log_error(APLOG_MARK, APLOG_WARNING, rc, s, \
                              LOG_MODULENAME "failed to unlock mutex")

#define MODULE_NAME "mod_dosdetector_syslog"
#define MODULE_VERSION "0.2"

#define USER_DATA_KEY "DoSDetecterUserDataKey"

#define DEFAULT_THRESHOLD 10000
#define DEFAULT_PERIOD 10
#define DEFAULT_BAN_PERIOD 300
#define DEFAULT_TABLE_SIZE 100

module AP_MODULE_DECLARE_DATA dosdetector_syslog_module;

#ifndef INET6_ADDRSTRLEN
#   define INET6_ADDRSTRLEN 46
#endif

struct s_client {
    char   addr[INET6_ADDRSTRLEN];
    unsigned int count;
    signed   int ban_period;
    time_t last;
    time_t suspected;
    time_t hard_suspected;
    struct s_client* next;
};
typedef struct s_client client_t;

typedef struct {
    client_t *head;
    client_t  base[1];
} client_list_t;

typedef struct {
    signed int detection_set;
    signed int threshold;
    signed int threshold_set;
    signed int ban_threshold;
    signed int ban_threshold_set;
    signed int period;
    signed int period_set;
    signed int ban_period;
    signed int ban_period_set;
    signed int forwarded;
    signed int forwarded_set;
    signed int allow_reconfig;
    signed int allow_reconfig_set;
    signed int ignore_contenttype_set;
    signed int illegal_settings;
    signed int illegal_settings_set;
    const char         *path;
    const char         *detection;
    //apr_array_header_t *ignore_contenttype;
    apr_array_header_t *contenttype_regexp;
} dosdetector_dir_config;

typedef struct {
    long        table_size;
    signed int  table_size_set;
    signed int  forwarded_header_set;
    signed int  forwarded_count;
    signed int  forwarded_count_set;
    signed int  slog_selector;
    signed int  slog_selector_set;
    signed int  hlog_selector;
    signed int  hlog_selector_set;
    const char *shmname;
    apr_shm_t  *shm;
    apr_global_mutex_t *lock;
    apr_array_header_t *forwarded_header;
} dosdetector_server_config;

//static long table_size  = DEFAULT_TABLE_SIZE;
//const char *shmname;
//static client_list_t *client_list;
//static char lock_name[L_tmpnam];
//static char shm_name[L_tmpnam];
//static apr_global_mutex_t *lock = NULL;
//static apr_shm_t *shm = NULL;

static apr_status_t cleanup_shm(void *s)
{
    server_rec    *ps = (server_rec *) s;
    dosdetector_server_config *cfg;
    //ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, LOG_MODULENAME "cleaning up shared memory");
    //fflush(stderr);

    do {
        cfg = (dosdetector_server_config *)
            ap_get_module_config(ps->module_config, &dosdetector_syslog_module);

        if (cfg->shm) {
            //ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, LOG_MODULENAME "Cleaning up... shmem name: `%s'", cfg->shmname);
            apr_shm_destroy(cfg->shm);
            cfg->shm = NULL;
        }

        if (cfg->lock) {
            apr_global_mutex_destroy(cfg->lock);
            cfg->lock = NULL;
        }

    } while ((ps = ps->next) != NULL);

    return APR_SUCCESS;
}

static void log_and_cleanup(char *msg, apr_status_t status, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, status, s, LOG_MODULENAME "Error: %s", msg);
    cleanup_shm(s);
}

static apr_status_t create_mutex(server_rec *s, apr_pool_t *p)
{
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(s->module_config, &dosdetector_syslog_module);

    apr_status_t rc = APR_SUCCESS;

    // bugzilla id=30385
    rc = apr_global_mutex_create(&cfg->lock, NULL, APR_LOCK_DEFAULT, p);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, LOG_MODULENAME "could not create mutex");
        return rc;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
#   if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
    rc = ap_unixd_set_global_mutex_perms(cfg->lock);
#   else
    rc = unixd_set_global_mutex_perms(cfg->lock);
#   endif

    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, LOG_MODULENAME "could not set permission on mutex");
        return rc;
    }
#endif

    return rc;
}

static apr_status_t create_shm(server_rec *s, apr_pool_t *p)
{
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(s->module_config, &dosdetector_syslog_module);

    client_list_t *client_list;
    apr_status_t rc = APR_SUCCESS;

    apr_size_t size;
    size =  sizeof(client_list_t) + cfg->table_size * sizeof(client_t);

    MUTEX_LOCK(cfg->lock, s);
    DEBUGLOG("creating shared memory %s, size: %" APR_SIZE_T_FMT, cfg->shmname, size);
    apr_shm_remove(cfg->shmname, p); // for SEGV before in process

    rc = apr_shm_create(&cfg->shm, size, cfg->shmname, p);
    if (APR_SUCCESS != rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, LOG_MODULENAME "failed to create shared memory %s", cfg->shmname);
        return rc;
    } else {
        client_list = apr_shm_baseaddr_get(cfg->shm);
        memset(client_list, 0, size);
    }

    apr_shm_remove(cfg->shmname, p); // Just to set destroy flag.

    client_list->head = client_list->base;
    client_t *c = client_list->base;
    int i;

    for (i = 1; i < cfg->table_size; i++) {
        c->next = (c + 1);
        c++;
    }
    c->next = NULL;
    MUTEX_UNLOCK(cfg->lock, s);

    return rc;
}

static client_t *get_client(apr_pool_t *p, client_list_t *client_list, const char *clientip, int period, time_t now)
{
    client_t *index, **prev = &client_list->head;

    int is_empty = 0;
    for(index = client_list->head; index->next != (client_t *) 0; index = index->next){
        if((is_empty = !index->addr[0]) || !ap_strcmp_match(index->addr, clientip))
            break;
        prev = &index->next;
    }

    *prev = index->next;
    index->next = client_list->head;
    client_list->head = index;

    index->last = now;
    if(is_empty || ap_strcmp_match(index->addr, clientip)){
        index->count = 0;
        index->suspected = 0;
        index->hard_suspected = 0;
        index->ban_period = 0;
        apr_cpystrn(index->addr, clientip, sizeof(index->addr));
    }

    return index;
}

static void *dosdetector_create_server_config(apr_pool_t *p, server_rec *s)
{
    DEBUGLOG("create server is called");
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        apr_pcalloc(p, sizeof (*cfg));

    cfg->table_size     = DEFAULT_TABLE_SIZE;
    cfg->slog_selector  = INTERNAL_NOPRI;
    cfg->hlog_selector  = INTERNAL_NOPRI;
    cfg->forwarded_count = -1;
    cfg->forwarded_header = apr_array_make(p, 0, sizeof(char *));

    return (void *) cfg;
}

static void *dosdetector_merge_server_config(apr_pool_t *p, void *basev, void *overridesv)
{
    DEBUGLOG("merge server is called");
    dosdetector_server_config *cfg, *base, *overrides;
    cfg = (dosdetector_server_config *) apr_pcalloc(p, sizeof (*cfg));
    base = (dosdetector_server_config *)basev;
    overrides = (dosdetector_server_config *)overridesv;

    cfg->shmname              = overrides->shmname;
    cfg->table_size           = (overrides->table_size_set == 0) ? base->table_size : overrides->table_size;
    cfg->table_size_set       = base->table_size_set || overrides->table_size_set;
    cfg->slog_selector        = (overrides->slog_selector_set == 0) ? base->slog_selector : overrides->slog_selector;
    cfg->slog_selector_set    = base->slog_selector_set || overrides->slog_selector_set;
    cfg->hlog_selector        = (overrides->hlog_selector_set == 0) ? base->hlog_selector : overrides->hlog_selector;
    cfg->hlog_selector_set    = base->hlog_selector_set || overrides->hlog_selector_set;
    cfg->forwarded_header     = (overrides->forwarded_header_set == 0) ? base->forwarded_header : overrides->forwarded_header;
    cfg->forwarded_header_set = base->forwarded_header_set || overrides->forwarded_header_set;
    cfg->forwarded_count      = (overrides->forwarded_count_set == 0) ? base->forwarded_count : overrides->forwarded_count;
    cfg->forwarded_count_set  = base->forwarded_count_set || overrides->forwarded_count_set;

    return (void *) cfg;
}

static void *dosdetector_create_dir_config(apr_pool_t *p, char *path)
{
    DEBUGLOG("create dir is called path: %s", path);
    dosdetector_dir_config *cfg = (dosdetector_dir_config *)
        apr_pcalloc(p, sizeof (*cfg));

    /* default configuration: no limit, and both arrays are empty */
    cfg->threshold       = DEFAULT_THRESHOLD;
    cfg->ban_threshold   = DEFAULT_THRESHOLD;
    cfg->period          = DEFAULT_PERIOD;
    cfg->ban_period      = DEFAULT_BAN_PERIOD;
    cfg->allow_reconfig  = 1;
    if (path != NULL) cfg->path = apr_pstrdup(p, path);
    //cfg->ignore_contenttype = apr_array_make(p, 0, sizeof(char *));
    cfg->contenttype_regexp = apr_array_make(p, 0, sizeof(char *));

    return (void *) cfg;
}

static void *dosdetector_merge_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    DEBUGLOG("merge dir is called");
    dosdetector_dir_config *cfg, *base, *overrides;
    cfg = (dosdetector_dir_config *) apr_pcalloc(p, sizeof (*cfg));
    base = (dosdetector_dir_config *)basev;
    overrides = (dosdetector_dir_config *)overridesv;

    // merge direction is child -> parent, and overrides always child
    if (overrides->illegal_settings == 1) {
        cfg->illegal_settings = 1;
        cfg->path = overrides->path;

        return (void *) cfg;
    }

    cfg->detection              = (overrides->detection_set == 0) ? base->detection : overrides->detection;
    cfg->detection_set          = base->detection_set || overrides->detection_set;
    cfg->threshold              = (overrides->threshold_set == 0) ? base->threshold : overrides->threshold;
    cfg->threshold_set          = base->threshold_set || overrides->threshold_set;
    cfg->ban_threshold          = (overrides->ban_threshold_set == 0) ? base->ban_threshold : overrides->ban_threshold;
    cfg->ban_threshold_set      = base->threshold_set || overrides->threshold_set;
    cfg->period                 = (overrides->period_set == 0) ? base->period : overrides->period;
    cfg->period_set             = base->period_set || overrides->period_set;
    cfg->ban_period             = (overrides->ban_period_set == 0 && overrides->ban_period < base->ban_period) ? base->ban_period : overrides->ban_period;
    cfg->ban_period_set         = base->ban_period_set || overrides->ban_period_set;
    cfg->forwarded              = (overrides->forwarded_set == 0) ? base->forwarded : overrides->forwarded;
    cfg->forwarded_set          = base->forwarded_set || overrides->forwarded_set;
    cfg->allow_reconfig         = (overrides->allow_reconfig_set == 0) ? base->allow_reconfig : overrides->allow_reconfig;
    cfg->allow_reconfig_set     = base->allow_reconfig_set || overrides->allow_reconfig_set;

    if (overrides->ignore_contenttype_set == 0) {
        //cfg->ignore_contenttype = base->ignore_contenttype;
        cfg->contenttype_regexp = base->contenttype_regexp;
    } else {
        //cfg->ignore_contenttype = overrides->ignore_contenttype;
        cfg->contenttype_regexp = overrides->contenttype_regexp;
    }
    cfg->ignore_contenttype_set = base->ignore_contenttype_set || overrides->ignore_contenttype_set;
    cfg->illegal_settings       = (overrides->illegal_settings_set == 0) ? base->illegal_settings : overrides->illegal_settings;
    cfg->path                   = overrides->path;

    if (overrides->illegal_settings_set == 0
        && overrides->allow_reconfig_set == 0) {
        if (cfg->allow_reconfig == 0)
            cfg->illegal_settings = 1;
        else
            cfg->illegal_settings = 0;

        cfg->illegal_settings_set = 1;
    }

    return (void *) cfg;
}

static const char *get_address(request_rec *r, int is_forwarded)
{
    const char *address = NULL;

    if (is_forwarded) {

        dosdetector_server_config *cfg = (dosdetector_server_config *) ap_get_module_config(r->server->module_config, &dosdetector_syslog_module);

        struct in_addr v4;
        struct in6_addr v6;
        const char *address_tmp;
        char *address_split;
        int i, is_empty;

        if ((is_empty = apr_is_empty_array(cfg->forwarded_header))
            && (address_tmp = apr_table_get(r->headers_in, "X-Forwarded-For"))){

            address = address_tmp;

        } else if (is_empty == FALSE) {
            for (i = 0; i < cfg->forwarded_header->nelts; i++) {
                if ((address_tmp = apr_table_get(r->headers_in, APR_ARRAY_IDX(cfg->forwarded_header, i, char *)))){

                    address = address_tmp;

                    break;
                }
                //ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, LOG_MODULENAME "name: %s", ((char **)(cfg->forwarded_header)->elts)[i]);
            }
        }
        if (address != NULL) {
            if (cfg->forwarded_count == -1) {
                if ((address_tmp = ap_strchr(address_tmp, ',')) != NULL)
                    address = apr_pstrndup(r->pool, address, address_tmp - address);
                else
                    address = apr_pstrdup(r->pool, address);
            } else {

                address = apr_pstrdup(r->pool, address_tmp);

                i = cfg->forwarded_count;
                while ((address_split = ap_strrchr(address, ','))
                        && (i-- >= 0)) {
                    *address_split = '\0';
                }
                if (address_split != NULL) {
                    address_split ++;
                    while (*address_split == ' ') address_split ++;
                    address = address_split;
                }
            }
            if (!inet_aton(address, &v4) && !inet_pton(AF_INET6, address, &v6)) {
#if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
                TRACELOG("`%s' is not a valid IP address, so used `%s'", address, r->useragent_ip);
#else
                TRACELOG("`%s' is not a valid IP address, so used `%s'", address, r->connection->remote_ip);
#endif

                address = NULL;
            }
        }
    }
    if (address == NULL) {
#if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
        address = apr_pstrdup(r->pool, r->useragent_ip);
#else
        address = apr_pstrdup(r->pool, r->connection->remote_ip);
#endif
    }
    return address;
}

static int content_is_not_modified(request_rec *r)
{
    if (r->finfo.fname == NULL
        || r->method_number != M_GET) return FALSE;

    const char *em, *es, *gz, *nm, *ms;
    em  = apr_psprintf(r->pool, "%" APR_UINT64_T_HEX_FMT, r->finfo.mtime);
    es  = apr_psprintf(r->pool, "\"%" APR_UINT64_T_HEX_FMT "\"", r->finfo.size);
    gz  = apr_psprintf(r->pool, "\"%" APR_UINT64_T_HEX_FMT "-gzip\"", r->finfo.size);
    nm  = apr_table_get(r->headers_in, "If-None-Match");
    ms  = apr_table_get(r->headers_in, "If-Modified-Since");

    return (nm != NULL && (ap_strstr_c(nm, em) || !ap_strcmp_match(nm, es)
        || !ap_strcmp_match(nm, gz)))
        || (ms != NULL && apr_time_sec(r->finfo.mtime) <= apr_time_sec(apr_date_parse_http(ms)));
}

static int dosdetector_setenv(request_rec *r)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) ap_get_module_config(r->per_dir_config, &dosdetector_syslog_module);
    dosdetector_server_config *cfgs = (dosdetector_server_config *) ap_get_module_config(r->server->module_config, &dosdetector_syslog_module);

    const char *address = get_address(r, cfg->forwarded);
    client_list_t *client_list;
    client_t *index;
    int is_empty = 0;
    apr_status_t rc;

    MUTEX_LOCK(cfgs->lock, r->server);
    client_list = apr_shm_baseaddr_get(cfgs->shm);
    for(index = client_list->head; index != (client_t *) 0; index = index->next){
        if((is_empty = !index->addr[0]) || !ap_strcmp_match(index->addr, address))
            break;
    }
    MUTEX_UNLOCK(cfgs->lock, r->server);
    if (is_empty || !index) return DECLINED;

    time_t now = time((time_t *) 0);

    if (index->suspected + index->ban_period > now) {
        if (index->suspected > 0)
            apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
        if (index->hard_suspected > 0)
            apr_table_setn(r->subprocess_env, "SuspectHardDoS", "1");
    }

    return DECLINED;
}

static int dosdetector_handler(request_rec *r)
{
    //DEBUGLOG("dosdetector_handler is called");

    dosdetector_dir_config *cfg = (dosdetector_dir_config *) ap_get_module_config(r->per_dir_config, &dosdetector_syslog_module);
    dosdetector_server_config *cfgs = (dosdetector_server_config *) ap_get_module_config(r->server->module_config, &dosdetector_syslog_module);

    if (!ap_is_initial_req(r)) return DECLINED;
    if (cfg->illegal_settings) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, LOG_MODULENAME "DoS* is not allowed in `%s'", cfg->path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (cfg->detection == NULL || !ap_strcasecmp_match("off", cfg->detection))
        return DECLINED;

    if (ap_strcasecmp_match("on", cfg->detection)){
        int rev = (cfg->detection[0] == '!') ? 1 : 0;
        const char *env = apr_table_get(r->subprocess_env, cfg->detection+rev);
        if (rev == 0 && env == NULL) return DECLINED;
        if (rev == 1 && env != NULL) return DECLINED;
        /*
         * Set to `DoSDetection !var' and then ${var} is not defined, it follows `on'.
         */
    }
    if (content_is_not_modified(r)) return DECLINED;

    const char *content_type = NULL;
    int i;
    //char **ignore_contenttype = (char **) cfg->ignore_contenttype->elts;

    if (cfg->contenttype_regexp->nelts > 0) {
        content_type = ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
        if (!content_type) {
#if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
            content_type = DefaultContentType;
#else
            content_type = ap_default_type(r);
#endif
        }

        ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
        ap_regex_t **contenttype_regexp = (ap_regex_t **) cfg->contenttype_regexp->elts;
        for (i = 0; i < cfg->contenttype_regexp->nelts; i++) {
            if(!ap_regexec(contenttype_regexp[i], content_type, AP_MAX_REG_MATCH, regmatch, 0)){
                //ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, LOG_MODULENAME "ignoring content-type: %s", content_type);
                return DECLINED;
            }
        }
    }
#ifdef _DEBUG
    if (!content_type)
        content_type = ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
    if (!content_type) {
#   if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER, AP_SERVER_MINORVERSION_NUMBER) >= 2004
        content_type = DefaultContentType;
#   else
        content_type = ap_default_type(r);
#   endif
    }
    DEBUGLOG("processing content-type: %s", content_type);
#endif

    const char *address = get_address(r, cfg->forwarded);
    time_t now = time((time_t *) 0);
    apr_status_t rc;

    MUTEX_LOCK(cfgs->lock, r->server);
    client_list_t *client_list = apr_shm_baseaddr_get(cfgs->shm);
    client_t *client = get_client(r->pool, client_list, address, cfg->period, now);
    client->count ++;
    if (client->count == 0) client->count = -1;
    MUTEX_UNLOCK(cfgs->lock, r->server);

    if (client->ban_period > cfg->ban_period) {
        cfg->ban_period = client->ban_period;
    } else {
        client->ban_period = cfg->ban_period;
    }

#ifdef _DEBUG
    int last_count = client->count;
#endif

    DEBUGLOG("%s, count: %d -> %d, period: %d, ban_period: %d, threshold: %d, ban_threshold: %d, server: %s", address,
            last_count, client->count, cfg->period, cfg->ban_period, cfg->threshold, cfg->ban_threshold, r->server->server_hostname);

    if(client->suspected > 0 && client->suspected + cfg->ban_period > now){
        DEBUGLOG("'%s' has been still suspected as DoS attack! (suspected %d sec ago)", address, now - client->suspected);

        if(client->hard_suspected > 0 || client->count > cfg->ban_threshold){
            TRACELOG("'%s' is suspected as Hard DoS attack! (counter: %d)", address, client->count);
            if((client->hard_suspected % cfg->ban_threshold) == 0) {
                apr_table_setn(r->subprocess_env, "SuspectHardDoS", "1");
                if(cfgs->hlog_selector != INTERNAL_NOPRI){
                    DEBUGLOG("Suspect Hard DoS logging, fac: %d, pri: %d", LOG_FAC(cfgs->hlog_selector), LOG_PRI(cfgs->hlog_selector));
                    openlog("httpd", LOG_PID, (LOG_FACMASK & cfgs->hlog_selector));
                    syslog(cfgs->hlog_selector, "dosdetector: suspected as Hard DoS attack! [%s] from %s", r->server->server_hostname, address);
                    closelog();
                }
            }

            client->hard_suspected = now;

        }

        client->suspected = now;

    } else {
        if(client->suspected > 0){
            client->suspected = 0;
            client->hard_suspected = 0;
            client->count = 0;
        }

        if(client->count > cfg->threshold){
            client->suspected = now;
            apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
            TRACELOG("'%s' is suspected as DoS attack! (counter: %d)", address, client->count);
            if(cfgs->slog_selector != INTERNAL_NOPRI){
                DEBUGLOG("Suspect DoS logging, fac: %d, pri: %d", LOG_FAC(cfgs->slog_selector), LOG_PRI(cfgs->slog_selector));
                openlog("httpd", LOG_PID, (LOG_FACMASK & cfgs->slog_selector));
                syslog(cfgs->slog_selector, "dosdetector: suspected as DoS attack! [%s] from %s", r->server->server_hostname, address);
                closelog();
            }
        }
    }

    return DECLINED;
}

static const char *set_detection_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    DEBUGLOG("detection_config is called");
    dosdetector_server_config *cfgs = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    if (*arg == '!' && *(arg+1) == '\0')
        return "Invalid argument";

    cfg->detection = apr_pstrdup(parms->pool, arg);
    cfg->detection_set = 1;

    return NULL;
}

static const char *set_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int threshold = strtol(arg, (char **) NULL, 10);
    if ((threshold > 65535) || (threshold < 1)) return "Integer overflow or invalid number";

    cfg->threshold = threshold;
    cfg->threshold_set = 1;

    return NULL;
}

static const char *set_hard_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_threshold = strtol(arg, (char **) NULL, 10);
    if ((ban_threshold > 65535) || (ban_threshold < 1)) return "Integer overflow or invalid number";

    cfg->ban_threshold = ban_threshold;
    cfg->ban_threshold_set = 1;

    return NULL;
}

static const char *set_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int period = strtol(arg, (char **) NULL, 10);
    if ((period > 65535) || (period < 1)) return "Integer overflow or invalid number";

    cfg->period = period;
    cfg->period_set = 1;

    return NULL;
}

static const char *set_ban_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_period = strtol(arg, (char **) NULL, 10);
    if ((ban_period > 65535) || (ban_period < 1)) return "Integer overflow or invalid number";

    cfg->ban_period = ban_period;
    cfg->ban_period_set = 1;

    return NULL;
}

static const char *set_shmem_name_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    DEBUGLOG("set_shmem_name_config is called");
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);

    cfg->shmname = apr_pstrdup(parms->pool, arg);

    return NULL;
}

static const char *set_table_size_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);
    signed long int size = strtol(arg, (char **) NULL, 10);
    if ((size > 65535) || (size < 1)) return "Integer overflow or invalid number";

    cfg->table_size = size;

    return NULL;
}

static const char *set_forwarded_config(cmd_parms *parms, void *mconfig, int on)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    cfg->forwarded = on;
    cfg->forwarded_set = 1;
    //ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, parms->server, LOG_MODULENAME "forwarded: %d", cfg->forwarded);

    return NULL;
}

static const char *set_forwarded_count_config(cmd_parms *parms, void *mconfig, const char* arg)
{
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);
    signed long int count = strtol(arg, (char **) NULL, 10);
    if ((count > 65535) || (count < -1)) return "Integer overflow or invalid number";

    cfg->forwarded_count = count;
    cfg->forwarded_count_set = 1;

    return NULL;
}

static const char *set_forwarded_header_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);

    if (ap_strcasecmp_match("none", arg))
        *(char **) apr_array_push(cfg->forwarded_header) = apr_pstrdup(parms->pool, arg);

    cfg->forwarded_header_set = 1;

    return NULL;
}

static const char *set_ignore_contenttype_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    if (ap_strcasecmp_match("none", arg)){
        //*(char **) apr_array_push(cfg->ignore_contenttype) = apr_pstrdup(parms->pool, arg);
        *(ap_regex_t **)apr_array_push(cfg->contenttype_regexp)
            = ap_pregcomp(parms->pool, arg, AP_REG_EXTENDED|AP_REG_ICASE);
    }
    cfg->ignore_contenttype_set = 1;

    return NULL;
}

static const char *set_slog_selector_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    DEBUGLOG("set_slog_selector_config is called: %s", arg);
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);

    const char* p;
    if ((p = ap_strchr(arg, '.')) != NULL) {
        int fac_val = 0, pri_val = 0;
        int i = 0;
        while (facilitynames[i].c_name != NULL) {
            if (!strncmp(arg, facilitynames[i].c_name, p - arg)) {
                fac_val = facilitynames[i].c_val;
                break;
            }
            i ++;
        }
        if (facilitynames[i].c_name == NULL) return "Invalid argument";

        i = 0;
        while (prioritynames[i].c_name != NULL) {
            if (!strncmp(p + 1, prioritynames[i].c_name, strlen(p + 1))) {
                pri_val = prioritynames[i].c_val;
                break;
            }
            i ++;
        }
        if (prioritynames[i].c_name == NULL) return "Invalid argument";

        cfg->slog_selector = LOG_MAKEPRI(fac_val, pri_val);

    } else if (ap_strcasecmp_match("none", arg)){
        return "Invalid argument";
    }

    cfg->slog_selector_set = 1;

    return NULL;
}

static const char *set_hlog_selector_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    DEBUGLOG("set_hlog_selector_config is called: %s", arg);
    dosdetector_server_config *cfg = (dosdetector_server_config *)
        ap_get_module_config(parms->server->module_config, &dosdetector_syslog_module);

    const char* p;
    if ((p = ap_strchr(arg, '.')) != NULL) {
        int fac_val = 0, pri_val = 0;
        int i = 0;
        while (facilitynames[i].c_name != NULL) {
            if (!strncmp(arg, facilitynames[i].c_name, p - arg)) {
                fac_val = facilitynames[i].c_val;
                break;
            }
            i ++;
        }
        if (facilitynames[i].c_name == NULL) return "Invalid argument";

        i = 0;
        while (prioritynames[i].c_name != NULL) {
            if (!strncmp(p + 1, prioritynames[i].c_name, strlen(p + 1))) {
                pri_val = prioritynames[i].c_val;
                break;
            }
            i ++;
        }
        if (prioritynames[i].c_name == NULL) return "Invalid argument";

        cfg->hlog_selector = LOG_MAKEPRI(fac_val, pri_val);

    } else if (ap_strcasecmp_match("none", arg)){
        return "Invalid argument";
    }

    cfg->hlog_selector_set = 1;

    return NULL;
}

static const char *set_allow_reconfig_config(cmd_parms *parms, void *mconfig, const int on)
{
    DEBUGLOG("set_allow_reconfig_config is called: %d", on);
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    cfg->allow_reconfig = on;
    cfg->allow_reconfig_set = 1;

    return NULL;
}

static command_rec dosdetector_cmds[] = {
    AP_INIT_TAKE1("DoSDetection", set_detection_config, NULL, OR_FILEINFO,
     "Enable to detect DoS Attack or not"),
    AP_INIT_TAKE1("DoSThreshold", set_threshold_config, NULL, OR_FILEINFO,
     "Threshold of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSHardThreshold", set_hard_threshold_config, NULL, OR_FILEINFO,
     "Hard Threshold for DoS Attack"),
    AP_INIT_TAKE1("DoSPeriod", set_period_config, NULL, OR_FILEINFO,
     "Period of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSBanPeriod", set_ban_period_config, NULL, OR_FILEINFO,
     "Period of banning client"),
    AP_INIT_TAKE1("DoSShmemName", set_shmem_name_config, NULL, RSRC_CONF,
     "The name of shared memory to allocate for keeping track of clients"),
    AP_INIT_TAKE1("DoSTableSize", set_table_size_config, NULL, RSRC_CONF,
     "The size of table for tracking clients"),
    AP_INIT_FLAG("DoSForwarded", set_forwarded_config, NULL, OR_FILEINFO,
     "Use X-Forwarded-For header for Remote Address"),
    AP_INIT_TAKE1("DoSForwardedCount", set_forwarded_count_config, NULL, RSRC_CONF,
     "The count of back steps in X-Forwarded-For for assign Remote Address, "
     "a way of counting is as follows `-1,...5,4,3,2,1,0', or -1 for defaults"),
    AP_INIT_ITERATE("DoSForwardedHeader", set_forwarded_header_config, NULL, RSRC_CONF,
     "The names of header for detecting as proxy access"),
    AP_INIT_ITERATE("DoSIgnoreContentType", set_ignore_contenttype_config, NULL, OR_FILEINFO,
     "The names of ignoring Content Type"),
    AP_INIT_TAKE1("DoSSLogSelector", set_slog_selector_config, NULL, RSRC_CONF,
     "The name of selector for syslog to report `Suspect DoS'"),
    AP_INIT_TAKE1("DoSHLogSelector", set_hlog_selector_config, NULL, RSRC_CONF,
     "The name of selector for syslog to report `Suspect Hard DoS'"),
    AP_INIT_FLAG("DoSAllowReconfig", set_allow_reconfig_config, NULL, RSRC_CONF|ACCESS_CONF,
     "The permission of re-configuration per parent directories"),
    {NULL},
};

static int initialize_module(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    DEBUGLOG("initialize_module is called");
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 MODULE_NAME " " MODULE_VERSION " started.");

    void *user_data;
    apr_status_t rc;
    apr_pool_userdata_get(&user_data, USER_DATA_KEY, s->process->pool);
    if (user_data == NULL) {
        apr_pool_userdata_set((const void *)(1), USER_DATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    dosdetector_server_config *cfgm = (dosdetector_server_config *)
        ap_get_module_config(s->module_config, &dosdetector_syslog_module);
    dosdetector_server_config *cfg;

    // This is main server
    DEBUGLOG("main server create:%s", s->server_hostname);
    cfgm->shmname = apr_psprintf(p, "dosdetector:%s", cfgm->shmname ? cfgm->shmname : s->server_hostname);

    rc = create_mutex(s, p);
    if (rc != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = create_shm(s, p);
    if (rc != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    server_rec* ps = s->next;
    char *sha1 = apr_pcalloc(p, 28 + APR_SHA1PW_IDLEN + 1);

    while (ps != NULL) {
        // This is vhost
        cfg = (dosdetector_server_config *)
            ap_get_module_config(ps->module_config, &dosdetector_syslog_module);
        if (cfg == cfgm) {// Not configured
            ps = ps->next;
            continue;
        }
        DEBUGLOG("vhost server create:%s", ps->server_hostname);
        apr_sha1_base64(ps->defn_name, strlen(ps->defn_name), sha1);
        cfg->shmname = apr_psprintf(p, "dosdetector:%s:%s", cfg->shmname ? cfg->shmname : ps->server_hostname, sha1 + APR_SHA1PW_IDLEN);

        rc = create_mutex(ps, p);
        if (rc != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        rc = create_shm(ps, p);
        if (rc != APR_SUCCESS) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        ps = ps->next;
    }

    apr_pool_cleanup_register(p, s, cleanup_shm, apr_pool_cleanup_null);

    return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
    DEBUGLOG("initialize_child is called");
    dosdetector_server_config *cfg, *cfgm = (dosdetector_server_config *)
        ap_get_module_config(s->module_config, &dosdetector_syslog_module);
    server_rec  *ps = (server_rec *) s->next;
    apr_status_t rc;

    if (cfgm->lock != NULL) {
        rc = apr_global_mutex_child_init(&cfgm->lock, NULL, p);
        if (rc != APR_SUCCESS) {
            log_and_cleanup("failed to attach mutex in child process", rc, s);
            return;
        }
    }
    while (ps != NULL) {
        cfg = (dosdetector_server_config *)
            ap_get_module_config(ps->module_config, &dosdetector_syslog_module);
        if (cfg == cfgm) {// Not configured
            ps = ps->next;
            continue;
        }
        if (cfg->lock != NULL) {
            rc = apr_global_mutex_child_init(&cfg->lock, NULL, p);
            if (rc != APR_SUCCESS) {
                log_and_cleanup("failed to attach mutex in child process", rc, ps);
                return;
            }
        }
        ps = ps->next;
    }
}

static const char * const pre_handler[] = {
    "mod_setenvif.c",
    //"mod_include.c",
    NULL,
};

static const char * const post_setenv[] = {
    "mod_setenvif.c",
    NULL,
};

static void register_hooks(apr_pool_t *p)
{
    //tmpnam(shm_name);
    //shmname    = shm_name;

    ap_hook_header_parser(dosdetector_handler, pre_handler, NULL, APR_HOOK_MIDDLE);
    //ap_hook_fixups(dosdetector_handler, pre_handler, NULL, APR_HOOK_MIDDLE);
    //ap_hook_handler(dosdetector_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_read_request(dosdetector_setenv, NULL, post_setenv, APR_HOOK_MIDDLE);
    ap_hook_post_config(initialize_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA dosdetector_syslog_module = {
    STANDARD20_MODULE_STUFF,
    dosdetector_create_dir_config, /* create per-dir config structures */
    dosdetector_merge_dir_config,  /* merge  per-dir    config structures */
    dosdetector_create_server_config, /* create per-server config structures */
    dosdetector_merge_server_config,  /* merge  per-server config structures */
    dosdetector_cmds,                 /* table of config file commands       */
    register_hooks
};

