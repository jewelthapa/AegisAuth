/* Backend.c - privileged validator of a privilege-separated auth service.
 *
 * Lifecycle:
 *   1. inherit the socket from the Frontend (fd 3)
 *   2. WHILE PRIVILEGED: read the root-only credential store into memory
 *   3. permanently drop privileges and verify the drop
 *   4. serve authentication requests from the in-memory hashes; never
 *      regain root, and never log or store a plaintext password
 * Also manages the credential store:  ./Backend adduser jewel password123
 *
 * The Frontend performs untrusted I/O; this process holds the secrets.
 * Neither component is ever simultaneously privileged AND exposed to raw
 * user input - that separation is the Principle of Least Privilege.
 *
 * Build:  gcc -Wall -Wextra -O2 -o Backend Backend.c -lcrypt
 * NOTE: Linux only (uses setresuid, /proc, and glibc SHA-512 crypt "$6$").
 *       Will not compile on macOS.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <crypt.h>
#include <fcntl.h>

/* ---- config + wire format : MUST stay identical to Frontend.c ---- */
#define SECRETS_PATH  "./secrets.db"
#define UNPRIV_UID    65534           /* "nobody" */
#define UNPRIV_GID    65534
#define USER_MAX      32
#define PASS_MAX      128
struct auth_request { char user[USER_MAX]; char pass[PASS_MAX]; };
enum  auth_reply    { AUTH_DENIED = 0, AUTH_GRANTED = 1, AUTH_ERROR = 2 };

struct cred { char user[USER_MAX]; char hash[128]; };
static struct cred creds[64];
static int ncreds = 0;

static const char alphabet[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* ======================= colour + logging ======================= */
static const char *C_RST="",*C_RED="",*C_GRN="",*C_YEL="",*C_CYN="",*C_DIM="";
static void init_colours(void) {
    if (isatty(STDERR_FILENO)) {
        C_RST="\033[0m"; C_RED="\033[31m"; C_GRN="\033[32m";
        C_YEL="\033[33m"; C_CYN="\033[36m"; C_DIM="\033[2m";
    }
}

static void logline(const char *colour, const char *level, const char *fmt, ...) {
    char ts[16]; time_t t = time(NULL); struct tm tm;
    localtime_r(&t, &tm); strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    fprintf(stderr, "%s[%s]%s %s[%s]%s [backend]  ",
            C_DIM, ts, C_RST, colour, level, C_RST);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
#define LINFO(...) logline(C_CYN, "INFO", __VA_ARGS__)
#define LOKAY(...) logline(C_GRN, "OK  ", __VA_ARGS__)
#define LWARN(...) logline(C_YEL, "WARN", __VA_ARGS__)
#define LFAIL(...) logline(C_RED, "FAIL", __VA_ARGS__)

/* ======================= privilege handling ======================= */
static void show_proc_status(const char *who) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4))
            fprintf(stderr, "           [%s] %s", who, line);
    fclose(f);
}

/*
 * Permanently relinquish elevated privilege and PROVE the drop succeeded.
 * See the matching comment in Frontend.c: setresuid() overwrites the saved
 * uid too, and the setuid(0) probe must fail for the drop to be trustworthy.
 */
static void drop_privileges(void) {
    if (geteuid() != 0) {
        LWARN("Not root: privilege drop skipped.");
        return;
    }
    if (setgroups(0, NULL) != 0)                            { perror("setgroups"); exit(1); }
    if (setresgid(UNPRIV_GID, UNPRIV_GID, UNPRIV_GID) != 0) { perror("setresgid"); exit(1); }
    if (setresuid(UNPRIV_UID, UNPRIV_UID, UNPRIV_UID) != 0) { perror("setresuid"); exit(1); }

    uid_t r, e, s;
    getresuid(&r, &e, &s);
    if (r != UNPRIV_UID || e != UNPRIV_UID || s != UNPRIV_UID) {
        LFAIL("uid drop incomplete."); exit(1);
    }
    if (setuid(0) == 0) { LFAIL("regained root after drop!"); exit(1); }
    LOKAY("Backend privileges dropped and verified (uid=%d).", UNPRIV_UID);
    show_proc_status("backend");
}

/* ======================= credential store ======================= */
/*
 * ./Backend adduser <user> <pass>  ->  append "user:sha512-hash" to the store.
 * A one-way SHA-512 hash is stored, never the plaintext password, so the
 * store cannot reveal the original passwords even if it is read.
 */
static int do_adduser(const char *user, const char *pass) {
    char setting[21] = "$6$";                    /* "$6$" selects SHA-512 crypt */
    srandom((unsigned)time(NULL) ^ (unsigned)getpid());
    for (int i = 3; i < 19; i++) setting[i] = alphabet[random() % 64];
    setting[19] = '$'; setting[20] = '\0';

    char *hash = crypt(pass, setting);
    if (!hash) { perror("crypt"); return 1; }

    int fd = open(SECRETS_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) { perror("open"); return 1; }
    dprintf(fd, "%s:%s\n", user, hash);
    close(fd);
    printf("Added '%s' to %s (mode 0600)\n", user, SECRETS_PATH);
    return 0;
}

/*
 * Load the credential store into memory. This MUST run while the process is
 * still privileged, because the store (like /etc/shadow) is deliberately
 * readable only by root. Acquiring the resource before dropping privilege is
 * the standard way to honour least privilege.
 */
static void load_secrets(void) {
    FILE *f = fopen(SECRETS_PATH, "r");
    if (!f) { perror("[backend] cannot open credential store"); exit(1); }
    char line[512];
    while (ncreds < 64 && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\n")] = '\0';
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        snprintf(creds[ncreds].user, sizeof creds[ncreds].user,
                 "%.*s", (int)(sizeof creds[ncreds].user - 1), line);
        snprintf(creds[ncreds].hash, sizeof creds[ncreds].hash,
                 "%.*s", (int)(sizeof creds[ncreds].hash - 1), colon + 1);
        ncreds++;
    }
    fclose(f);
    LINFO("Loaded %d credential(s) while privileged.", ncreds);
}

/* ======================= verification ======================= */
/* Constant-time comparison: does not leak how many bytes matched via timing. */
static int ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned char diff = (unsigned char)(la ^ lb);
    size_t n = la < lb ? la : lb;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static enum auth_reply verify(struct auth_request *req) {
    for (int i = 0; i < ncreds; i++) {
        if (strncmp(creds[i].user, req->user, USER_MAX) == 0) {
            char *got = crypt(req->pass, creds[i].hash);   /* re-hash with stored salt */
            return (got && ct_equal(got, creds[i].hash)) ? AUTH_GRANTED : AUTH_DENIED;
        }
    }
    (void)crypt(req->pass, "$6$saltsaltsaltsa$");  /* equalise timing for unknown users */
    return AUTH_DENIED;
}

/* ======================= main ======================= */
int main(int argc, char **argv) {
    init_colours();

    /* Administrative mode: add a user to the store, then exit. */
    if (argc >= 2 && strcmp(argv[1], "adduser") == 0) {
        if (argc != 4) { fprintf(stderr, "usage: %s adduser <user> <pass>\n", argv[0]); return 1; }
        return do_adduser(argv[2], argv[3]);
    }

    if (argc < 2) { LFAIL("Missing socket fd argument."); return 1; }
    int sock = atoi(argv[1]);

    LINFO("Backend started (pid %d).", (int)getpid());
    load_secrets();          /* needs privilege */
    drop_privileges();       /* never needs it again */
    LINFO("Waiting for authentication requests...");

    struct auth_request req;
    for (;;) {
        memset(&req, 0, sizeof req);
        ssize_t r = read(sock, &req, sizeof req);
        if (r == 0) break;                              /* frontend closed the socket */
        if (r != (ssize_t)sizeof req) { explicit_bzero(&req, sizeof req); break; }

        req.user[USER_MAX - 1] = '\0';                  /* trust nothing off the wire */
        req.pass[PASS_MAX - 1] = '\0';
        LINFO("Request received for user '%s'.", req.user);

        enum auth_reply reply = verify(&req);
        explicit_bzero(&req, sizeof req);               /* wipe password immediately */

        if (reply == AUTH_GRANTED) LOKAY("Authentication successful.");
        else                       LWARN("Authentication failed.");

        unsigned char byte = (unsigned char)reply;
        if (write(sock, &byte, 1) != 1) break;
    }

    explicit_bzero(creds, sizeof creds);                /* wipe hashes on exit */
    close(sock);
    LINFO("Backend shutting down.");
    return 0;
}
