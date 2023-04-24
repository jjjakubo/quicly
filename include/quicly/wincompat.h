//
// Created by ACER on 24/04/2023.
//

#ifndef QUICLY_WINCOMPAT_H
#define QUICLY_WINCOMPAT_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>

#include <inttypes.h>
#include <unistd.h>

typedef uint16_t in_port_t;

struct iovec
{
    void	*iov_base;  /* Base address of a memory region for input or output */
    size_t	 iov_len;   /* The size of the memory pointed to by iov_base */
};

#endif // QUICLY_WINCOMPAT_H
