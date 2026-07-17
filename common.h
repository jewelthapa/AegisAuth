#ifndef COMMON_H
#define COMMON_H

/* ==========================================================
   AegisAuth — Privilege-Separated Authentication Framework
   Shared Definitions
   ========================================================== */

#define SECRETS_PATH "./secrets.db"

/* Backend executable */

#define BACKEND_PATH "./Backend"

/* UNIX socket */

#define BACKEND_SOCK_FD 3
#define BACKEND_SOCK_ARG "3"

/* User limits */

#define USER_MAX 32
#define PASS_MAX 128

/* Maximum stored users */

#define MAX_USERS 64

/* Privilege drop */

#define UNPRIV_UID 65534
#define UNPRIV_GID 65534

/* Authentication request */

struct auth_request
{
    char user[USER_MAX];
    char pass[PASS_MAX];
};

/* Authentication reply */

enum auth_reply
{
    AUTH_DENIED = 0,
    AUTH_GRANTED = 1,
    AUTH_ERROR = 2
};

#endif
