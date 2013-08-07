/*
 * Copyright 2000, F.W. Dillema, University of Tromso, Norway
 * $Id: www6to4.h,v 1.18 2003/11/26 09:49:06 dillema Exp $
 *
 * Distributed under the GNU General Public License; see the README file.
 *
 * Based on code with the following license:
 *
 * Written and copyright 1997 Anonymous Coders and Junkbusters Corporation.
 * Distributed under the GNU General Public License; see the README file.
 * This code comes with NO WARRANTY. http://www.junkbusters.com/ht/en/gpl.html
 */

#ifndef WWW6TO4_H
#define WWW6TO4_H

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include <syslog.h>

#ifndef FD_ZERO
#include <select.h>
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define MAXADDRESSES  32
#define NLOADERS 8
#define freez(X)        if(X) free(X); X = NULL
#define SZ(X)        (sizeof(X) / sizeof(*X))

#define UNDEF_PROTO 0
#define HTTP_PROTO 1
#define HTTPS_PROTO 2
#define FTP_PROTO 3

struct gateway {
        char *forward_host;
        char *forward_port;
};

struct iob {
        char *buf;
        char *cur;
        char *eod;
};

struct http_request {
        char *cmd;
        char *gpc;
        char *host;
        char *port;
        char *path;
        char *ver;
        char *hostport; /* "host[:port]" */
        int   ssl;
        int proto;
};

struct list {
        char *str;
        struct list *last;
        struct list *next;
};

struct client_state {
        int  cfd;
        int  sfd;

        struct gateway gw[1];
        struct http_request http[1];
        struct iob iob[1];
        struct list headers[1];
        /* files associated with this client */
        struct file_list *flist;

        struct client_state *next;
};

struct url_spec {
        char  *spec;
        char  *domain;
        char  *dbuf;
        char **dvec;
        int    dcnt;
        int    toplevel;
        int    proto;
        char *path;
        int   pathlen;
        char *port;
};

struct file_list {
        void *f; /* this is a pointer to the data structures
                  * associated with the file
                  */
        void (*unloader)();
        int active;
        struct file_list *next;
};

struct forward_spec {
        struct url_spec url[1];
        struct gateway gw[1];
        struct forward_spec *next;
};

extern int (*loaders[])();
extern int run_loader();
extern void add_loader(), destroy_list();
extern int bind_port(), accept_conn();

extern int add_to_iob();
extern void fperror(), enlist();
extern char *safe_strerror(), *strsav(), *get_header();
extern void parse_http_request();
extern void free_http_request();
extern int parse_content_length(char *p);

extern int domaincmp(), ssplit();
extern struct url_spec dsplit();

extern int connect_to();
extern int flush_socket();
extern char *list_to_text (struct list * h);
extern int load_forwardfile();
extern int direct_connect();
int open_server_socket (char *, char *, int);
extern struct gateway     *forward_url();

extern struct file_list *current_forwardfile;
extern char   *forwardfile;
extern struct gateway gw_default, gw_none;
extern int forwardv4only;

extern char   CFAIL[];
extern char   CNXDOM[];
extern char   CSUCCEED[];
extern char   CHEADER[];
extern char   SHEADER[];

#endif /* WWW6TO4_H */
