/*
 * Copyright 2000,2001 F.W. Dillema, University of Tromso, Norway
 * $Id: parsers.c,v 1.14 2003/11/26 09:49:05 dillema Exp $
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

/* case insensitive string comparison */
int strcmpic (char *s1, char *s2) {
    while (*s1 && *s2) {
        if ((*s1 != *s2)
            && (tolower (*s1) != tolower (*s2))) {
            break;
        }
        s1++, s2++;
    }
    return (tolower (*s1) - tolower (*s2));
}

int strncmpic (char *s1, char *s2, size_t n) {
    if (n <= 0)
        return (0);

    while (*s1 && *s2) {
        if ((*s1 != *s2)
            && (tolower (*s1) != tolower (*s2))) {
            break;
        }
        if (--n <= 0)
            break;

        s1++, s2++;
    }
    return (tolower (*s1) - tolower (*s2));
}

/*
 * Append buf to the current csp->iob reallocating it if necessary.
 */
int add_to_iob (struct client_state *csp, char *buf, int n) {
    struct iob *iob = csp->iob;
    int have, need;
    char *p;
    have = iob->eod - iob->cur;

    if (n <= 0)
        return (have);

    need = have + n;

    p = malloc (need + 1);
    if (!p) {
        syslog (LOG_ERR, "Malloc() iob failed");
	syslog (LOG_ERR, "%s", safe_strerror (errno));
        return (-1);
    }

    if (have) {
        /* there is something in the buffer - save it */
        memcpy (p, iob->cur, have);

        /* replace the buffer with the new space */
        freez (iob->buf);
        iob->buf = p;

        /* point to the end of the data */
        p += have;
    } else {
        /* the buffer is empty, free it and reinitialize */
        freez (iob->buf);
        iob->buf = p;
    }

    /* copy the new data into the iob buffer */
    memcpy (p, buf, n);

    /* point to the end of the data */
    p += n;

    /* null terminate == cheap insurance */
    *p = '\0';

    /* set the pointers to the new values */
    iob->cur = iob->buf;
    iob->eod = p;

    return (need);
}

/*
 * this (odd) routine will parse the csp->iob and return one of the
 * following:
 *
 * 1) a pointer to a dynamically allocated string that contains a
 * header line 2) NULL indicating that the end of the header was
 * reached 3) "" indicating that the end of the iob was reached before
 * finding a complete header line.  
 */
char *get_header (struct client_state *csp) {
    struct iob *iob = csp->iob;
    char *p, *q, *ret;

    /* If we don't have it we don't have it */
    if (!iob->cur)
        return ("");
    p = strchr (iob->cur, '\n');
    if (!p)
        return ("");                /* couldn't find a complete header */

    /* Null terminate the header line and duplicate it */
    *p = '\0';
    ret = strdup (iob->cur);
    if ((q = strchr (ret, '\r'))) /* Snip that annoyin character... */
        *q = '\0';

    /* Move the start of the buffer to point at the next header data. */
    iob->cur = p + 1;

    /* Is this a blank linke (i.e. the end of the header) ? */
    if (*ret == '\0') {
        freez (ret);
        return (NULL);
    }
    return (ret);
}

void free_http_request (struct http_request *http) {
    freez (http->cmd);
    freez (http->gpc);
    freez (http->host);
    freez (http->hostport);
    freez (http->path);
    freez (http->ver);
}

/* parse out the host and port from the URL */
void parse_http_request (char *req, struct http_request *http, struct client_state *csp) {
    char *buf, *v[10], *url, *p;
    int n;

    memset (http, '\0', sizeof (*http));
    /* Store the request as http->cmd */
    http->cmd = strdup (req);
    /* Copy the request to buf */
    buf = strdup (req);

    n = ssplit (buf, " \r\n", v, SZ (v), 1, 1);
    if (n == 3) {
        /* this could be a CONNECT request */
        if (!strcmpic (v[0], "connect")) {
            http->ssl = 1;
            http->gpc = strdup (v[0]);
            http->hostport = strdup (v[1]);
            http->ver = strdup (v[2]);
        }
        /* or it could be a GET or a POST */
        if (!strcmpic (v[0], "get")
            || !strcmpic (v[0], "head")
            || !strcmpic (v[0], "post")) {

            http->ssl = 0;
            http->gpc = strdup (v[0]);
            url = v[1];
            http->ver = strdup (v[2]);

            if (!strncmpic (url, "http://", 7)) {
                http->proto = HTTP_PROTO;
                url += 7;
            } else if (!strncmpic (url, "https://", 8)) {
                http->proto = HTTPS_PROTO;
                url += 8;
            } else if (!strncmpic (url, "ftp://", 6)) {
                /* we do not support ftp proxying, but we may forward */
                http->proto = FTP_PROTO;
                url += 6;
            } else {
                http->proto = UNDEF_PROTO;
                url = NULL;
            }

            if (url && (p = strchr (url, '/'))) {
                http->path = strdup (p);
                *p = '\0';
                http->hostport = strdup (url);
            }
        }
    }
    freez (buf);

    if (!http->hostport) {
        free_http_request (http);
        return;
    }

    buf = strdup (http->hostport);
    n = ssplit (buf, ":", v, SZ (v), 1, 1);
    if (n == 1) {
        http->host = strdup (v[0]);
        http->port = "80";
    }
    if (n == 2) {
        http->host = strdup (v[0]);
        http->port = strdup (v[1]);
    }
    freez (buf);

    if (!http->host)
        free_http_request (http);

    if (!http->path)
        http->path = strdup ("");
}

/*
 * ssplit() - split a string (in-place) into fields s = string to split c =
 * list of characters to be used as field separators (if NULL, use default
 * separators of space, tab, and newline)
 *
 * v = vector into which field pointers are placed n = number of fields in
 * vector
 *
 * m = flag indicating whether to treat strings of field separators as
 * indicating multiple fields
 *
 * l = flag indicating whether to ignore leading field separators
 */

int ssplit (char *s, char *c, char *v[], int n, int m, int l) {
    char t[256];
    char **x = NULL;
    int xsize = 0;
    unsigned char *p, b;
    int xi = 0;
    int vi = 0;
    int i;
    int last_was_null;
    if (!s)
        return (-1);

    memset (t, '\0', sizeof (t));

    p = (unsigned char *) c;

    if (!p)
        p = (unsigned char *) " \t";        /* default field separators */

    while (*p)
        t[*p++] = 1;                /* separator  */

    t['\0'] = 2;                /* terminator */
    t['\n'] = 2;                /* terminator */

    p = (unsigned char *) s;

    if (l) {                        /* are we to skip leading separators ? */
        while ((b = t[*p]) != 2) {
            if (b != 1)
                break;
            p++;
        }
    }
    xsize = 256;

    x = (char **) calloc (xsize, sizeof (char *));
    x[xi++] = (char *) p;        /* first pointer is the beginning of string */

    /* first pass:  save pointers to the field separators */
    while ((b = t[*p]) != 2) {
        if (b == 1) {                /* if the char is a separator ... */
            *p++ = '\0';        /* null terminate the substring */

            if (xi == xsize) {
                /* get another chunk */
                int new_xsize = xsize + 256;
                char **new_x = (char **)
                calloc (new_xsize, sizeof (char *));
                for (i = 0; i < xsize; i++)
                    new_x[i] = x[i];

                free (x);
                xsize = new_xsize;
                x = new_x;
            }
            x[xi++] = (char *) p;        /* save pointer to beginning of next
                                         * string */
        } else
            p++;
    }
    *p = '\0';                        /* null terminate the substring */

    /* second pass: copy the relevant pointers to the output vector */
    last_was_null = 0;
    for (i = 0; i < xi; i++) {
        if (m) {
            /* there are NO null fields */
            if (*x[i] == 0)
                continue;
        }
        if (vi < n)
            v[vi++] = x[i];
        else {
            free (x);
            return (-1);        /* overflow */
        }
    }
    free (x);

    return (vi);
}

struct gateway *forward_url (struct http_request *http, struct client_state *csp) {
    struct file_list *fl;
    struct forward_spec *b;
    struct url_spec url[1];
    struct hostent *h;

    fl = csp->flist;
    if (!fl)
        return (&gw_default);

    b = fl->f;
    if (!b)
        return (&gw_default);

    *url = dsplit (http->host);

    /* if splitting the domain fails, punt */
    if (!url->dbuf)
        return (&gw_default);

    if (forwardv4only) {
        h = gethostbyname2(http->host,AF_INET6);
        if (h) {
            return (&gw_none);
        }
    }

    for (b = b->next; b; b = b->next) {
        if (!b->url->proto || b->url->proto == http->proto) {
            if (!atoi (b->url->port) || atoi(b->url->port) == atoi(http->port)) {
                if ((b->url->domain[0] == '\0') || !domaincmp(b->url, url)) {
                    if (!b->url->path || !strncmp (b->url->path, http->path, b->url->pathlen)) {
                        freez (url->dbuf);
                        freez (url->dvec);
                        return (b->gw);
                     }
                }
            }
        }
    }
    freez (url->dbuf);
    freez (url->dvec);
    return (&gw_default);
}

/*
 * dsplit() takes a domain and returns a pointer to a url_spec structure
 * populated with dbuf, dcnt and dvec.  the other fields in the structure
 * that is returned are zero.
 *
 */
struct url_spec dsplit (char *domain) {
    struct url_spec ret[1];
    char *v[BUFSIZ];
    int size;
    char *p;
    memset (ret, '\0', sizeof (*ret));

    if ((p = strrchr (domain, '.'))) {
        if (*(++p) == '\0')
            ret->toplevel = 1;
    }
    ret->dbuf = strdup (domain);

    /* map to lower case */
    for (p = ret->dbuf; *p; p++)
        *p = tolower (*p);

    /* split the domain name into components */
    ret->dcnt = ssplit (ret->dbuf, ".", v, SZ (v), 1, 1);

    if (ret->dcnt <= 0) {
        memset (ret, '\0', sizeof (ret));
        return (*ret);
    }
    /* save a copy of the pointers in dvec */
    size = ret->dcnt * sizeof (*ret->dvec);

    ret->dvec = malloc (size);
    if (ret->dvec)
        memcpy (ret->dvec, v, size);

    return (*ret);
}

/*
 * the "pattern" is a domain that may contain a '*' as a wildcard. the "fqdn"
 * is the domain name against which the patterns are compared.
 *
 * domaincmp("a.b.c" , "a.b.c") => 0 (MATCH) 
 * domaincmp("a*.b.c", "a.b.c") => 0 (MATCH)
 * domaincmp("b.c"   , "a.b.c") => 0 (MATCH)
 * domaincmp(""      , "a.b.c") => 0 (MATCH)
 */
int domaincmp (struct url_spec * pattern, struct url_spec * fqdn) {
    char **pv, **fv;    /* vectors  */
    int pn, fn;         /* counters */
    char *p, *f;        /* chars    */
    pv = pattern->dvec;
    pn = pattern->dcnt;

    fv = fqdn->dvec;
    fn = fqdn->dcnt;

    while ((pn > 0) && (fn > 0)) {
        p = pv[--pn];
        f = fv[--fn];

        while (*p && *f && (*p == tolower (*f)))
            p++, f++;

        if ((*p != tolower (*f)) && (*p != '*'))
            return (1);
    }

    if (pn > 0)
        return (1);

    return (0);
}

/*
 * Parse content-length header
 * Added by Frank Ronny Larsen
 */
int parse_content_length(char *p) {
    char *number;
    long length;

    number = strrchr(p, ':');
    if (!number) /* No ':'? Return 0 */
        return 0;

    number++;
    length = strtol(number, (char **)NULL, 0);

    return (int) length;
}

/*
 * h = pointer to list 'dummy' header
 * s = string to add to the list
 */
void enlist (struct list * h, char *s) {
    struct list *n = (struct list *) malloc (sizeof (*n));
    struct list *l;
    if (n) {
        n->str = strdup (s);
        n->next = NULL;

        if ((l = h->last)) {
            l->next = n;
        }
        else {
            h->next = n;
        }

        h->last = n;
    }
}

void destroy_list (struct list * h) {
    struct list *p, *n;
    for (p = h->next; p; p = n) {

        n = p->next;

        freez (p->str);

        freez (p);
    }

    memset (h, '\0', sizeof (*h));
}

char *list_to_text (struct list * h) {
    struct list *p;
    char *ret = NULL;
    char *s;
    int size;
    size = 0;

    for (p = h->next; p; p = p->next) {
        if (p->str) {
            size += strlen (p->str) + 2;
        }
    }

    ret = malloc (size + 1);
    if (!ret)
        return (NULL);

    ret[size] = '\0';

    s = ret;

    for (p = h->next; p; p = p->next) {
        if (p->str) {
            strcpy (s, p->str);
            s += strlen (s);
            *s++ = '\r';
            *s++ = '\n';
        }
    }

    return (ret);
}

