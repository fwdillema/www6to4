/*
 * Copyright 2000,2001 F.W. Dillema, University of Tromso, Norway
 * $Id: www6to4.c,v 1.38 2003/11/26 09:49:06 dillema Exp $
 *
 * Distributed under the GNU General Public License; see the README file.
 *
 * Based on code with the following license:
 *
 * Written and copyright 1997 Anonymous Coders and Junkbusters Corporation.
 * Distributed under the GNU General Public License; see the README file.
 * This code comes with NO WARRANTY. http://www.junkbusters.com/ht/en/gpl.html
 */

#define SYSLOG_NAMES
#include "www6to4.h"

#define VERSION "www6to4 v1.6"
#define BANNER  "<strong>"VERSION"</strong>"

char CFAIL[] = "HTTP/1.0 503 Connect failed\r\n"
"Content-Type: text/html\r\n\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>WWW6to4 Proxy: Connect failed</title>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1><center>"
BANNER
"</center></h1>\r\n"
"TCP connection to '%s' failed: %s.\r\n<br>"
"</body>\r\n"
"</html>\r\n";

char CNXDOM[] = "HTTP/1.0 404 Non-existent domain\r\n"
"Content-Type: text/html\r\n\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>WWW6to4 Proxy: Non-existent domain</title>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1><center>"
BANNER
"</center></h1>\r\n"
"No such domain: %s\r\n"
"</body>\r\n"
"</html>\r\n";

char CHEADER[] = "HTTP/1.0 400 Invalid header received from browser\r\n\r\n";
char SHEADER[] = "HTTP/1.0 502 Invalid header received from server\r\n\r\n";
char CSUCCEED[] = "HTTP/1.0 200 Connection established\r\n"
"Proxy-Agent: WWW6to4/" "\r\n\r\n";

#define MAXHOST 255
#define MAXPORT 32
#define MAXPATTERNS 255
char hostname[MAXHOST] = "127.0.0.1,::1";
char hostport[MAXPORT] = "8000";
char *patterns[MAXPATTERNS];
int lastpattern = -1;

char *default_configfile = "/etc/www6to4.conf";
char *configfile = NULL;
char *forwardfile = NULL;
int debug = 0;
int forwardv4only = 0;
int quiet = 1;
int tfactor = 1;
int potential_add;
int logfacility = LOG_DAEMON;
struct gateway gw_default = {NULL, NULL};
struct gateway gw_none = {NULL, NULL};

struct file_list *current_forwardfile;
int (*loaders[NLOADERS]) ();

void chat (struct client_state * csp) {
    char buf[BUFSIZ], *hdr, *p, *req;
    fd_set rfds;
    int i, n, maxfd, server_body;
    struct gateway *gw;
    struct http_request *http;
    struct timeval timeout;
    int bodylen, bodyrecv;
    int sent, length;
    char *bodybuf;

    http = csp->http;

    for (;;) {
        FD_ZERO (&rfds);
        FD_SET (csp->cfd, &rfds);
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        n = select (csp->cfd + 1, &rfds, NULL, NULL, &timeout);
        if (!n) {
            syslog (LOG_NOTICE, "Timeout reading from client");
            return;
        }
        if (n < 0) {
            syslog (LOG_ERR, "%s", safe_strerror (errno));
            return;
        }
        n = read (csp->cfd, buf, sizeof (buf));
        if (n <= 0)
            break;
        add_to_iob (csp, buf, n);

        req = get_header (csp);
        if (!req)
            break;                /* no HTTP request! */
        if (*req == '\0')
            continue;                /* more to come! */

        parse_http_request (req, http, csp);
        freez (req);
        break;
    }

    if (!http->cmd) {
        strcpy (buf, CHEADER);
        write (csp->cfd, buf, strlen (buf));
        return;
    }

    /* decide how to route the HTTP request */
    syslog (LOG_INFO, "Requesting: %s", http->cmd);
    gw = forward_url (http, csp);

    potential_add = 0;
    for (i = lastpattern; i >= 0; i--) {
        if (strstr(http->path, patterns[i])) {
            if (debug)
                syslog (LOG_INFO, "Pattern: *%s*", patterns[i]);
            potential_add = 1;
            break;
        }
    }

    /* if forwarding, just pass the request as is */
    if (gw->forward_host)
        enlist (csp->headers, http->cmd);
    else if (!http->ssl) {
            /* otherwise elide the host information from the url */
            p = NULL;
            p = strsav (p, http->gpc);
            p = strsav (p, " ");
            p = strsav (p, http->path);
            p = strsav (p, " ");
            p = strsav (p, http->ver);
            enlist (csp->headers, p);
            freez (p);
    }

    /* grab the rest of the client's headers */
    bodylen = 0;
    for (;;) {
        p = get_header (csp);
        if (p && (*p == '\0')) {
            n = read (csp->cfd, buf, sizeof (buf));
            if (n < 0) {
                syslog (LOG_ERR, "%s", safe_strerror (errno));
                return;
            }
            add_to_iob (csp, buf, n);
            continue;
        }

        /* get_header returned NULL, means empty line */
        if (!p)
            break;

        enlist (csp->headers, p);

        /* Check for Content-length. If a content-length header is
           present we have content data that needs to be read as well */
        if (!strncasecmp ("Content-length", p, 14)) {        /* found */
            bodylen = parse_content_length(p);
            syslog (LOG_INFO, "Content-length: %d", bodylen);
        }

        /* Finally, free up p */
        freez (p);
    }

    /* add the blank line at the end of the header */
    enlist (csp->headers, "");

    /* make hdr out of list */
    hdr = list_to_text (csp->headers);
    destroy_list (csp->headers);
    length = strlen(hdr);

    /* Do we need to read the body as well? */
    if (bodylen > 0) {                /* Yepp! */
        bodybuf = calloc(bodylen + length, 1);

        memcpy(bodybuf, hdr, length);

        /* Set hdr to be the new buffer */
        freez (hdr);
        hdr = bodybuf;

        bodybuf = hdr+length;

        bodyrecv = csp->iob->eod - csp->iob->cur;
        memcpy(bodybuf, csp->iob->cur, bodyrecv);

        while (bodyrecv < bodylen) {
            n = read (csp->cfd, bodybuf+bodyrecv, bodylen-bodyrecv);
            if (n < 0) {
                syslog (LOG_ERR, "%s", safe_strerror (errno));
                return;
            }
            bodyrecv += n;
        }
        length += bodylen;
    }

    /* here we connect to the server, gateway, or the forwarder */
    csp->sfd = direct_connect (gw, http, csp);
    if (csp->sfd < 0) {
        if (errno == EINVAL)
            syslog (LOG_NOTICE, "No Such Domain.");
        else
            syslog (LOG_ERR, "%s", safe_strerror (errno));

        freez (hdr);
        return;
    }

    if (gw->forward_host || !http->ssl) {
        /*
         * write the client's (modified) header to the server (along
         * with anything else that may be in the buffer)
         */
        sent = 0;
        while (sent < length) {
            n = write (csp->sfd, hdr+sent, length-sent);
            if (n < 0) {
                syslog (LOG_NOTICE, "Failed to send header data to server");
                freez(hdr);
                return;
            }
            sent += n;
        }
    } else {
        /*
         * we're running an SSL tunnel and we're not forwarding, so
         * just send the "connect succeeded" message to the client,
         * flush the rest, and get out of the way.
         */
        if (write (csp->cfd, CSUCCEED, sizeof (CSUCCEED) - 1) < 0) {
            freez (hdr);
            return;
        }
    }

    freez (csp->iob->buf);
    memset(csp->iob, '\0', sizeof(csp->iob));
    /* we're finished with the client's header */
    freez (hdr);
    maxfd = (csp->cfd > csp->sfd) ? csp->cfd : csp->sfd;

    /*
     * Pass data between the client and server until one or the other
     * shuts down the connection.
     *
     * FWD: This is quite a violation of the HTTP-1.1
     * standard; it does not properly implement presistent connections.
     * This is no problem however when using netscape as client, but e.g. links
     * causes troubles (because it does the correct thing ;). Doing the right
     * thing is looking for multiple client requests on a single connection
     * that may be to multiple servers. The quick, dirty and easy but wrong way
     * implemented now is to shutdown the connection for reads after the first
     * request has been read. Brrr...
     */

    server_body = 0;

    for (;;) {
        FD_ZERO (&rfds);
        FD_SET (csp->cfd, &rfds);
        FD_SET (csp->sfd, &rfds);
        timeout.tv_usec = 0;
        if (potential_add)
                timeout.tv_sec = 5*tfactor;
        else
                timeout.tv_sec = 60*tfactor;

        n = select (maxfd + 1, &rfds, NULL, NULL, &timeout);

        if (!n) {
            syslog (LOG_NOTICE, "Timed out after %d seconds", timeout.tv_sec);
            return;
        }
        if (n < 0) {
            syslog (LOG_ERR, "%s", safe_strerror (errno));
            return;
        }

        /*
         * this is the body of the browser's request just read it and
         * write it.
         */
        if (FD_ISSET (csp->cfd, &rfds)) {
            n = read (csp->cfd, buf, sizeof (buf));
            if (n <= 0)
                break;

            if (write (csp->sfd, buf, n) != n) {
                syslog (LOG_NOTICE, "Write to: %s failed", http->host);
                return;
            }
            /* Arf, depending on your browser you may need this */
            if (0 && !http->ssl)
                shutdown (csp->cfd, SHUT_RD);

            continue;
        }

        /*
         * the server wants to talk. it could be the header or the
         * body. if `hdr' is null, then it's the header otherwise
         * it's the body
         */
        if (FD_ISSET (csp->sfd, &rfds)) {
            n = read (csp->sfd, buf, sizeof (buf));
            if (n < 0) {
                syslog (LOG_NOTICE, "Read from: %s failed: ", http->host);
                syslog (LOG_ERR, "%s", safe_strerror (errno));
                return;
            }
            if (!n)
                break;                /* "game over, man" */

            /*
             * if this is an SSL connection or we're in the body
             * of the server document, just write it to the
             * client.
             */

            if (server_body || http->ssl) {
                /* just write */
                if (write (csp->cfd, buf, n) != n) {
                    syslog (LOG_NOTICE, "Write to client failed");
                    syslog (LOG_ERR, "%s", safe_strerror (errno));
                    return;
                }
                continue;
            } else {
                /*
                 * we're still looking for the end of the
                 * server's header ...
                 */

                add_to_iob (csp, buf, n);
                while ((p = get_header (csp))) {
                    /* see following note */
                    if (*p == '\0')
                        break;
                    enlist (csp->headers, p);
                    freez (p);
                }

                /*
                 * NOTE: there are no "empty" headers so if
                 * the pointer `p' is not NULL we must assume
                 * that we reached the end of the buffer
                 * before we hit the end of the header.
                 *
                 * Since we have to wait for more from the
                 * server before we can parse the headers we
                 * just continue here.
                 */

                if (p)
                    continue;

                /*
                 * add the blank line at the end of the
                 * header
                 */
                enlist (csp->headers, "");
                hdr = list_to_text (csp->headers);
                n = strlen (hdr);

                /*
                 * write the server's (modified) header to
                 * the client (along with anything else that
                 * may be in the buffer)
                 */
                if ((n && write (csp->cfd, hdr, n) != n)
                    || (flush_socket (csp->cfd, csp) < 0)) {
                    /*
                     * the write failed, so don't bother
                     * mentioning it to the client... it
                     * probably can't hear us anyway.
                     */
                    freez (hdr);
                    return;
                }
                /* we're finished with the server's header */

                freez (hdr);
                server_body = 1;
            }
            continue;
        }
        return;                        /* huh? we should never get here */
    }
}

void serve (struct client_state *csp) {

    chat (csp);
    shutdown (csp->cfd, SHUT_RDWR);
    close (csp->cfd);

    if (csp->sfd >= 0)
        close (csp->sfd);
}

int main (int argc, char *argv[]) {
    char buf[BUFSIZ];
    int bfd[MAXADDRESSES + 1];
    char *addr;
    int i;

    configfile = default_configfile;
    for (i = 1; i < argc; i++) {
        if (!strcmp (argv[i], "-d") )
            debug = 1;
        else if (!strcmp (argv[i], "-forwardv4only"))
                forwardv4only = 1;
        else if (!strcmp (argv[i], "-c"))
            configfile = strdup(argv[++i]);
        else if (!strcmp (argv[i], "-l")) {
                int j;

                i++;
                j = 0;
                while (facilitynames[j].c_name) {
                    if (!strcmp(argv[i], facilitynames[j].c_name))
                        logfacility = facilitynames[j].c_val;
                    j++;
                }
        }
        else if (!strcmp (argv[i], "-q"))
                quiet = 1;
        else if (!strcmp (argv[i], "-v"))
                quiet = -1;
        else if (!strcmp (argv[i], "-h")) {
                fprintf (stdout, "www6to4 -q -v -h  -d -c <configfile> -l <syslogfacility>\n");
                fprintf (stdout, "-forwardv4only: never forward requests for IPv6 hosts\n");
                fprintf (stdout, "-q: quiet (less logging)\n");
                fprintf (stdout, "-v: verbose (more logging)\n");
                fprintf (stdout, "-d: debug mode (do not fork)\n");
        }
    }

    if (debug)
        openlog("www6to4", LOG_PID | LOG_NDELAY | LOG_CONS | LOG_PERROR, logfacility);
    else
        openlog("www6to4", LOG_PID | LOG_NDELAY | LOG_CONS, logfacility);

    syslog (LOG_NOTICE, "%s", VERSION);
    if (quiet > 0)
            setlogmask (LOG_UPTO (LOG_ERR));
    else if (!quiet)
        setlogmask (LOG_UPTO (LOG_NOTICE));
    else if (quiet < 0)
        setlogmask (LOG_UPTO (LOG_INFO));

    if (configfile) {
        FILE *configfp = fopen (configfile, "r");

        if (!configfp) {
            syslog (LOG_ERR, "can't open configuration file '%s': ", configfile);
            syslog (LOG_ERR, "%s", safe_strerror (errno));
            exit (1);
        } else {
            int line_num = 0;

            while (fgets (buf, sizeof (buf), configfp)) {
                char cmd[BUFSIZ], arg[BUFSIZ], tmp[BUFSIZ];
                    char *p, *q;

                line_num++;

                strcpy (tmp, buf);
                p = strpbrk (tmp, "#\r\n");
                if (p)
                    *p = '\0';
                p = tmp;

                /* leading skip whitespace */
                while (*p && ((*p == ' ') || (*p == '\t')))
                    p++;

                q = cmd;
                while (*p && (*p != ' ') && (*p != '\t'))
                    *q++ = *p++;
                *q = '\0';

                while (*p && ((*p == ' ') || (*p == '\t')))
                    p++;

                strcpy (arg, p);
                p = arg + strlen (arg) - 1;

                /* ignore trailing whitespace */
                while (*p && ((*p == ' ') || (*p == '\t')))
                    *p-- = '\0';

                if (*cmd == '\0')
                    continue;

                /* insure the command field is lower case */
                for (p = cmd; *p; p++)
                    if (isupper (*p))
                        *p = tolower (*p);

                if (!strcmp (cmd, "listen-to")) {
                    strncpy (hostname, arg, MAXHOST);
                    continue;
                }
                if (!strcmp (cmd, "pattern")) {
                    if (++lastpattern >= MAXPATTERNS)
                        syslog (LOG_ERR, "Too many patterns, more than %d.", MAXPATTERNS);
                    else
                        patterns[lastpattern] = strdup(arg);
                    continue;
                }
                if (!strcmp (cmd, "listen-port")) {
                    strncpy (hostport, arg, MAXPORT);
                    continue;
                }
                if (!strcmp (cmd, "forwardfile")) {
                    forwardfile = strdup (arg);
                    continue;
                }
                if (!strcmp (cmd, "timeout-factor")) {
                    tfactor = atoi (arg);
                    if (tfactor < 0 || tfactor > 10) {
                        tfactor = 1;
                        syslog (LOG_ERR, "Illegal Timeout factor.");
                    }
                    continue;
                }
                syslog (LOG_ERR,
                         "Unrecognized directive in configuration file "
                         "at line number %d", line_num);
                exit(1);
            }
            fclose (configfp);
        }
    }

    if (forwardfile)
        add_loader (load_forwardfile);

    addr = strtok (hostname, ",");
    if (!strcmp (addr, "*")) {
        bfd[0] = open_server_socket (NULL, hostport, AF_INET);
        bfd[1] = open_server_socket (NULL, hostport, AF_INET6);
        bfd[2] = 0;
    } else {
        for (i = 0; i < MAXADDRESSES; i++) {
            bfd[i] = open_server_socket (addr, hostport, AF_UNSPEC);
            addr = strtok (NULL, ",");
            if (!addr)
                break;
        }
        bfd[i + 1] = 0;
    }

    for (i = 0; (i < MAXADDRESSES) && bfd[i]; i++) {
        if (bfd[i] < 0) {
            syslog (LOG_ERR, "Can't bind %s:%s: ",
                     hostname ? hostname : "INADDR_ANY", hostport);
            syslog (LOG_ERR, "%s", safe_strerror (errno));
            syslog (LOG_ERR, "There may be another www6to4 or some other "
                     "proxy running on port %s", hostport);
            exit (1);
        }
    }

    signal (SIGPIPE, SIG_IGN);
    signal (SIGCHLD, SIG_IGN);

    for (;;) {
        int cfd;
        struct client_state *csp;

#ifdef DMALLOC
        dmalloc_log_unfreed();
#endif

        /* cleanup zombie children */
        while (waitpid (-1, NULL, WNOHANG) > 0) {}

        cfd = accept_conn (bfd);
        if (cfd < 0)
            continue;

        csp = (struct client_state *) calloc (1, sizeof (*csp));
        if (!csp) {
            syslog (LOG_ERR, "malloc(%d) for csp failed: ", sizeof (*csp));
            syslog (LOG_ERR, "%s", safe_strerror (errno));
            close (cfd);
            sleep (3);
            continue;
        }

        csp->cfd = cfd;
        csp->sfd = -1;

        if (run_loader (csp)) {
            syslog (LOG_ERR, "A loader failed - must exit");
            exit (1);
        }

        if (!debug) {
            int child_id;
            child_id = fork ();

            if (child_id < 0) {        /* failed */
                syslog (LOG_ERR, "Can't fork");
                syslog (LOG_ERR, "%s", safe_strerror (errno));
                sprintf (buf, "%s: can't fork: errno = %d", VERSION, errno);
                write (csp->cfd, buf, strlen (buf));
                close (csp->cfd);
                sleep (5);
                continue;
            }

            if (!child_id) { /* child */
                    if (setpgid (0, getpid ()) == -1) {
                    syslog (LOG_ERR, "setpgid() failed with %d", errno);
                    syslog (LOG_ERR, "%s", safe_strerror (errno));
                    exit(1);
                }
                serve (csp);
                freez (csp);
                exit (0);
            } else {         /* parent */
                close (csp->cfd);
                freez (csp);
            }
        } else {
            serve (csp);
            freez (csp);
        }
    }
    /* NOTREACHED */
}


char *safe_strerror (int err) {
    char buf[BUFSIZ];
    char *s = NULL;

#ifndef   NOSTRERROR
    s = strerror (err);
#endif                                /* NOSTRERROR */

    if (!s) {
        sprintf (buf, "(errno = %d)", err);
        s = buf;
    }
    return s;
}

int flush_socket (int fd, struct client_state * csp) {
    struct iob *iob = csp->iob;
    int n = iob->eod - iob->cur;

    if (n <= 0)
        return (0);

    n = write (fd, iob->cur, n);
    iob->eod = iob->cur = iob->buf;

    return (n);
}
