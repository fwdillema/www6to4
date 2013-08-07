/*
 * Copyright 2000,2001 F.W. Dillema, University of Tromso, Norway
 * $Id: loaders.c,v 1.13 2001/12/17 15:10:58 dillema Exp $
 *
 * Distributed under the GNU General Public License; see the README file.
 *
 * Based on code with the following license:
 *
 * Written and copyright 1997 Anonymous Coders and Junkbusters Corporation.
 * Distributed under the GNU General Public License; see the README file.
 * This code comes with NO WARRANTY. http://www.junkbusters.com/ht/en/gpl.html
 */

#include "www6to4.h"

void unload_forwardfile (struct forward_spec *b) {

    if (!b)
        return;

    unload_forwardfile (b->next);

    if (b->url) {
        struct url_spec *url = b->url;

        freez (url->spec);
        freez (url->domain);
        freez (url->dbuf);
        freez (url->dvec);
        freez (url->path);
    }

    freez (b->gw->forward_host);
    freez (b);
}

int load_forwardfile (struct client_state *csp) {
    static struct stat prev[1], curr[1];
    struct forward_spec *b, *bl;
    char buf[BUFSIZ], *p, *q, *tmp;
    char *vec[2], *port;
    int n;
    struct file_list *fs;
    struct url_spec url[1];
    FILE *fp;

    if (stat (forwardfile, curr) < 0)
        goto load_forwardfile_error;

    if (current_forwardfile && (prev->st_mtime == curr->st_mtime)) {
        /* ok, the forwardfile hasn't changed a bit */
        csp->flist = current_forwardfile;
        return (0);
    }

    fs = (struct file_list *) calloc (1, sizeof (*fs));
    bl = (struct forward_spec *) calloc (1, sizeof (*bl));
    if (!fs || !bl)
        goto load_forwardfile_error;

    fs->f = bl;
    *prev = *curr;
    if (csp)
        csp->flist = fs;

    fp = fopen (forwardfile, "r");
    if (!fp)
        goto load_forwardfile_error;

    tmp = NULL;
    while (fgets (buf, sizeof (buf), fp)) {

        freez (tmp);

        p = strpbrk (buf, "\r\n");
        if (p)
            *p = '\0';

        /* comments */
        p = strchr (buf, '#');
        if (p)
            *p = '\0';
        /* skip blank lines */
        if (*buf == '\0')
            continue;

        tmp = strdup (buf);
        n = ssplit (tmp, " \t", vec, SZ (vec), 1, 1);
        if (n != 2) {
            syslog (LOG_ERR, "error in forwardfile: %s\n", buf);
            continue;
        }

        strcpy (buf, vec[0]);

        /* skip blank lines */
        if (*buf == '\0')
            continue;

        /* allocate a new node */
        b = calloc (1, sizeof (*b));
        if (!b) {
            fclose (fp);
            goto load_forwardfile_error;
        }
        /* add it to the list */
        b->next = bl->next;
        bl->next = b;

        p = strstr (buf, "://");
        if (p) {
            if (!strncmpic (buf, "http://", 7)) {
                b->url->proto = HTTP_PROTO;
                memmove(buf, buf+7, BUFSIZ-7);
            } else if (!strncmpic (buf, "https://", 8)) {
                b->url->proto = HTTPS_PROTO;
                memmove(buf, buf+8, BUFSIZ-8);
            } else if (!strncmpic (buf, "ftp://", 6)) {
                /* we do not support ftp proxying, but we may forward */
                b->url->proto = FTP_PROTO;
                memmove(buf, buf+6, BUFSIZ-6);
            } else {
                b->url->proto = UNDEF_PROTO;
            }
        }

        p = strchr (buf, '/');
        if (p) {
            b->url->path = strdup (p);
            b->url->pathlen = strlen (b->url->path);
            *p = '\0';
        } else {
            b->url->path = NULL;
            b->url->pathlen = 0;
        }

        p = strchr (buf, ':');
        if (!p)
            port = "0";
        else {
            *p++ = '\0';
            port = strdup (p);
        }

        b->url->port = port;
        b->url->domain = strdup (buf);
        if (!b->url->domain) {
            fclose (fp);
            goto load_forwardfile_error;
        }
        /* split domain into components */
        *url = dsplit (b->url->domain);
        b->url->dbuf = url->dbuf;
        b->url->dcnt = url->dcnt;
        b->url->dvec = url->dvec;

        /* now parse the forwarding spec */
        p = vec[1];

        if (strcmp (p, ".") != 0) {
            b->gw->forward_host = strdup (p);

            p = strchr (b->gw->forward_host, ':');
            if (p) {
                *p++ = '\0';
                b->gw->forward_port = strdup (p);
            }
            if (b->gw->forward_port <= 0)
                b->gw->forward_port = "8000";
        }
    }

    freez (tmp);
    fclose (fp);

    /* the old one is now obsolete */
    if (current_forwardfile)
        current_forwardfile->unloader = unload_forwardfile;

    current_forwardfile = fs;
    return (0);

load_forwardfile_error:
    syslog(LOG_ERR, "Can't load forwardfile '%s': ", forwardfile);
    syslog (LOG_ERR, "%s", safe_strerror (errno));
    return (-1);
}


/*
 * strsav() takes a pointer to a string stored in a dynamically allocated
 * buffer and a pointer to a string and returns a pointer to a new
 * dynamically allocated space that contains the concatenation of the two
 * input strings the previous space is free()'d by realloc().
 */
char *strsav (char *old, char *text_to_append) {
    int old_len, new_len;
    char *p;

    if (!text_to_append || (*text_to_append == '\0'))
        return (old);

    if (old)
        old_len = strlen (old);
    else
        old_len = 0;

    new_len = old_len + strlen (text_to_append) + 1;

    if (old) {
        p = realloc (old, new_len);
        if (!p) {
            syslog(LOG_ERR, "Realloc(%d) bytes failed!\n", new_len);
            exit (1);
        }
    }
    else {
        p = malloc (new_len);
        if (!p) {
            syslog(LOG_ERR, "Realloc(%d) bytes failed!\n", new_len);
            exit (1);
        }
    }

    strcpy (p + old_len, text_to_append);
    return (p);
}

void add_loader (int (*loader) ()) {
    int i;

    for (i = 0; i < NLOADERS; i++) {
        if (!loaders[i]) {
            loaders[i] = loader;
            break;
        }
    }
}

int run_loader (struct client_state *csp) {
    int ret = 0;
    int i;

    for (i = 0; i < NLOADERS; i++) {
        if (!loaders[i])
            break;

        ret |= (loaders[i]) (csp);
    }
    return (ret);
}
