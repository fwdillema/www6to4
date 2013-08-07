/*
 * Copyright 2000,2001 F.W. Dillema, University of Tromso, Norway
 * $Id: socket.c,v 1.18 2001/12/17 15:10:58 dillema Exp $
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

int open_server_socket (char *hostname, char *port, int af) {
    struct addrinfo hints, *r, *res;
    int s = -1, error;
    int reuse_addr = 1;

    memset (&hints, 0, sizeof (hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    error = getaddrinfo (hostname, port, &hints, &res);
    if (!error) {
        for (r = res; r; r = r->ai_next) {
            s = socket (r->ai_family, r->ai_socktype, r->ai_protocol);
            if (s < 0)
                continue;

            setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof (reuse_addr));

            if (bind (s, r->ai_addr, r->ai_addrlen) < 0) {
                close (s);
                s = -1;
                continue;
            }
            if (listen (s, 10) < 0) {
                close (s);
                s = -1;
                continue;
            }
            break;
        }
    }

    if (res)
        freeaddrinfo (res);

    if (s < 0)
        return (-1);

    if (!hostname)
        syslog (LOG_INFO, "Listening to wildcard address for family %d on port %s.\n", af, port);
    else
        syslog (LOG_INFO, "Listening to %s for family %d on port %s.\n", hostname, af, port);

    return s;
}

int accept_conn (int *fds) {
    struct sockaddr_storage ra;
    int fd, afd, ralen, i, last;
    fd_set rfds;
    struct timeval tv[1];
    char remote_ip_str[NI_MAXHOST];

    /* wait for connection to complete */
    FD_ZERO (&rfds);
    i = 0;
    while (fds[i] > 0) {
        FD_SET (fds[i], &rfds);
        i++;
    }
    last = i - 1;

    tv->tv_sec = 10;
    tv->tv_usec = 0;

    if (select (fds[last] + 1, &rfds, NULL, NULL, tv) <= 0)
        return -1;

    i = 0;
    while (fds[i] > 0 && !FD_ISSET (fds[i], &rfds)) {
        i++;
    }

    fd = fds[i];
    if (!fd)
        return -1;

    ralen = sizeof ra;
    do {
        afd = accept (fd, (struct sockaddr *) & ra, &ralen);
    } while (afd < 1 && errno == EINTR);

    if (afd < 0)
        return (-1);

    getnameinfo ((struct sockaddr *) & ra, ralen, remote_ip_str,
                 NI_MAXHOST, NULL, NI_MAXSERV, NI_NUMERICHOST);
    syslog (LOG_INFO, "Accepted client from: %s.\n", remote_ip_str);

    return afd;
}

int direct_connect (struct gateway *gw, struct http_request *http, struct client_state *csp) {
    if (gw->forward_host)
        return (connect_to (gw->forward_host, gw->forward_port, csp));
    else
        return (connect_to (http->host, http->port, csp));
}

int connect_to (char *host, char *port, struct client_state * csp) {
    int fd = -1;
    int flags = -1;
    fd_set wfds;
    struct timeval tv[1];
    struct addrinfo hints, *res, *res0;
    int error;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    error = getaddrinfo (host, port, &hints, &res0);
    if (error) {
        syslog (LOG_NOTICE, "Name lookup failed: %s", gai_strerror(error));
        return (-1);
    }

    syslog (LOG_INFO, "Connecting to: %s at %s.\n", host, port);

    for (res = res0; res; res = res->ai_next) {
        fd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0)
            continue;

#ifdef TCP_NODELAY
        {                        /* turn off TCP coalescence */
            int mi = 1;
            setsockopt (fd, IPPROTO_TCP, TCP_NODELAY,
                        (char *) &mi, sizeof (int));
        }
#endif

        flags = fcntl (fd, F_GETFL, 0);
        if (flags != -1) {
            flags |= O_NDELAY;
            fcntl (fd, F_SETFL, flags);
        }

        error = connect (fd, (struct sockaddr *) res->ai_addr, res->ai_addrlen);
        if (error < 0) {
            if (errno != EINPROGRESS) {
                close (fd);
                fd = -1;
                continue;
            }
        }
        break;                        /* connected to a server */
    }

    if (res0)
        freeaddrinfo (res0);

    if (fd < 0)
        return -1;

    if (flags != -1) {
        flags &= ~O_NDELAY;
        fcntl (fd, F_SETFL, flags);
    }

    /* wait for connection to complete */
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);

    tv->tv_sec = 10;
    tv->tv_usec = 0;

    if (select (fd + 1, NULL, &wfds, NULL, tv) <= 0) {
        (void) close (fd);
        return (-1);
    }
    return (fd);
}

