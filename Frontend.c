/* Frontend.c - untrusted-input side of a privilege-separated auth service.
 *
 * Responsibilities (each handled by its own function below):
 *   - present a menu-driven user interface
 *   - launch the Backend as a completely separate executable (fork + execve)
 *   - drop its own privileges (it never needs any)
 *   - validate user input before it ever reaches the privileged process
 *   - relay authentication requests over a UNIX socket and report the result
 *   - wipe the password from memory the moment it is no longer needed
 *
 * The Frontend never opens the credential store. That lives only in the
 * Backend, so the process that touches untrusted input holds no secrets.
 *
 * Build:  gcc -Wall -Wextra -O2 -o Frontend Frontend.c
 * NOTE: Linux only (uses setresuid + /proc). Will not compile on macOS.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>

/* ---- config + wire format : MUST stay identical to Backend.c ---- */
#define BACKEND_PATH      "./Backend"
#define BACKEND_SOCK_FD   3
#define BACKEND_SOCK_ARG  "3"
#define UNPRIV_UID        65534        /* "nobody" */
#define UNPRIV_GID        65534
#define USER_MAX          32
#define PASS_MAX          128
struct auth_request { char user[USER_MAX]; char pass[PASS_MAX]; };
enum  auth_reply    { AUTH_DENIED = 0, AUTH_GRANTED = 1, AUTH_ERROR = 2 };

enum { APP_OK = 0, APP_EXIT = 1 };

extern char **environ;

/* ======================= colour + logging ======================= */
/* Colour is enabled only on a real terminal, so redirected logs and the
 * captured demo log stay free of escape codes. */
static const char *C_RST="",*C_RED="",*C_GRN="",*C_YEL="",*C_CYN="",*C_DIM="";
static void init_colours(void) {
    if (isatty(STDOUT_FILENO)) {
        C_RST="\033[0m"; C_RED="\033[31m"; C_GRN="\033[32m";
        C_YEL="\033[33m"; C_CYN="\033[36m"; C_DIM="\033[2m";
    }
}

/* Timestamped, level-tagged log line on stderr: "[14:32:11] [INFO] [frontend] ..." */
static void logline(const char *colour, const char *level, const char *fmt, ...) {
    char ts[16]; time_t t = time(NULL); struct tm tm;
    localtime_r(&t, &tm); strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    fprintf(stderr, "%s[%s]%s %s[%s]%s [frontend] ",
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
 *
 * setresuid() overwrites the real, effective AND saved uid, so the process
 * cannot later restore root. The subsequent setuid(0) is expected to FAIL;
 * if it were to succeed the drop would be reversible and therefore useless.
 */
static void drop_privileges(void) {
    if (geteuid() != 0) {
        LWARN("Not root: privilege drop skipped (run under sudo to demonstrate it).");
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
    LOKAY("Frontend privileges dropped and verified (uid=%d).", UNPRIV_UID);
    show_proc_status("frontend");
}

/* ======================= input handling ======================= */
/* Returns 1 on success, 0 on end-of-input (EOF) so callers can exit cleanly. */
static int read_line(const char *prompt, char *buf, size_t n) {
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }
    if (!fgets(buf, n, stdin)) { buf[0] = '\0'; return 0; }
    buf[strcspn(buf, "\n")] = '\0';
    return 1;
}

/*
 * Read a password without leaking it to the screen. On a real terminal the
 * characters are masked with '*' (with backspace support); when input is
 * piped (e.g. for automated tests) it falls back to a plain line read.
 */
static int read_secret(const char *prompt, char *buf, size_t n) {
    fputs(prompt, stdout); fflush(stdout);
    if (!isatty(STDIN_FILENO))
        return read_line(NULL, buf, n);

    struct termios old, raw;
    tcgetattr(STDIN_FILENO, &old);
    raw = old; raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    size_t i = 0; int c;
    while ((c = getchar()) != EOF && c != '\n' && c != '\r') {
        if (c == 127 || c == 8) {                 /* backspace */
            if (i > 0) { i--; fputs("\b \b", stdout); }
        } else if (i + 1 < n && c >= 32 && c < 127) {
            buf[i++] = (char)c; fputc('*', stdout);
        }
        fflush(stdout);
    }
    buf[i] = '\0';
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fputc('\n', stdout);
    return 1;
}

/* Reject bad input in the UNPRIVILEGED frontend, before it reaches the
 * privileged backend. Returns NULL if valid, else a human-readable reason. */
static const char *validate(const char *user, const char *pass) {
    if (user[0] == '\0')          return "username is empty";
    if (pass[0] == '\0')          return "password is empty";
    if (strlen(user) >= USER_MAX) return "username too long (max 31 characters)";
    if (strlen(pass) >= PASS_MAX) return "password too long (max 127 characters)";
    if (strchr(user, ' '))        return "username must not contain spaces";
    return NULL;
}

/* ======================= user interface ======================= */
static void display_banner(void) {
    printf("%s====================================================%s\n", C_CYN, C_RST);
    printf("        Secure Authentication Service\n");
    printf("        Programming and Learning Systems\n");
    printf("%s====================================================%s\n", C_CYN, C_RST);
}

static void display_menu(void) {
    printf("\n  1. Login\n  2. About\n  3. Exit\n\n");
}

static void display_about(void) {
    printf("\n%s----------------------------------------------------%s\n", C_CYN, C_RST);
    printf("  Task 1 - Privilege Separation Demo\n");
    printf("%s----------------------------------------------------%s\n", C_CYN, C_RST);
    printf("  Mechanisms demonstrated:\n");
    printf("    fork() / execve()   - process isolation\n");
    printf("    UNIX domain socket  - local inter-process communication\n");
    printf("    setresuid()         - permanent privilege dropping\n");
    printf("    explicit_bzero()    - secure memory handling\n");
}

/* ======================= backend launch + IPC ======================= */
static int launch_backend(pid_t *pid) {
    int sv[2];
    LINFO("Creating communication channel (UNIX domain socketpair)...");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(1); }

    LINFO("Launching backend process (fork + execve)...");
    *pid = fork();
    if (*pid < 0) { perror("fork"); exit(1); }

    if (*pid == 0) {
        /*
         * Child: replace this image with the Backend executable. execve()
         * gives the backend a fresh process image, strengthening isolation
         * between the two components.
         */
        close(sv[0]);
        if (dup2(sv[1], BACKEND_SOCK_FD) < 0) { perror("dup2"); _exit(1); }
        if (sv[1] != BACKEND_SOCK_FD) close(sv[1]);
        char *args[] = { (char *)BACKEND_PATH, (char *)BACKEND_SOCK_ARG, NULL };
        execve(BACKEND_PATH, args, environ);
        perror("execve"); _exit(127);
    }

    close(sv[1]);
    LOKAY("Backend launched successfully (pid %d).", (int)*pid);
    return sv[0];
}

/* Send one request, receive one verdict. Wipes the request buffer after use. */
static int send_request(int sock, const char *user, const char *pass, unsigned char *reply) {
    struct auth_request req;
    memset(&req, 0, sizeof req);
    snprintf(req.user, sizeof req.user, "%s", user);
    snprintf(req.pass, sizeof req.pass, "%s", pass);

    LINFO("Credentials sent to backend.");
    ssize_t w = write(sock, &req, sizeof req);
    explicit_bzero(&req, sizeof req);
    if (w != (ssize_t)sizeof req) { LFAIL("Short write to backend."); return -1; }

    LINFO("Waiting for authentication result...");
    return (read(sock, reply, 1) == 1) ? 0 : -1;
}

static int ask_retry(void) {
    char c[16];
    printf("\n  1) Try again\n  2) Back to menu\n");
    if (!read_line("  Choice: ", c, sizeof c)) return 0;
    return c[0] == '1';
}

/* One login interaction, with input validation and a retry loop. */
static int login(int sock) {
    for (;;) {
        char user[256], pass[256];
        printf("\n%s-------------------------%s\n Login\n%s-------------------------%s\n",
               C_CYN, C_RST, C_CYN, C_RST);
        LINFO("Login selected.");

        if (!read_line("\n Username : ", user, sizeof user)) return APP_EXIT;
        if (!read_secret(" Password : ", pass, sizeof pass)) {
            explicit_bzero(pass, sizeof pass); return APP_EXIT;
        }

        const char *err = validate(user, pass);
        if (err) {
            LWARN("Input rejected: %s.", err);
            printf("\n%s  [WARNING] %s.%s\n", C_YEL, err, C_RST);
            explicit_bzero(pass, sizeof pass);
            if (ask_retry()) continue; else return APP_OK;
        }

        printf("\n Connecting to authentication service...\n");
        unsigned char reply = AUTH_ERROR;
        int rc = send_request(sock, user, pass, &reply);
        explicit_bzero(pass, sizeof pass);           /* password no longer needed */

        if (rc != 0) {
            LFAIL("Communication with backend failed.");
            printf("%s  [ERROR] Authentication service unavailable.%s\n", C_RED, C_RST);
            return APP_EXIT;
        }

        if (reply == AUTH_GRANTED) {
            LOKAY("Authentication successful for '%s'.", user);
            printf("\n%s  [SUCCESS] Authentication successful.%s\n", C_GRN, C_RST);
            printf("  Welcome, %s.\n", user);
            return APP_OK;
        }

        LFAIL("Authentication failed for '%s'.", user);
        printf("\n%s  [FAILED] Authentication failed.%s\n", C_RED, C_RST);
        printf("  Invalid username or password.\n");
        if (ask_retry()) continue; else return APP_OK;
    }
}

/* ======================= main ======================= */
int main(void) {
    init_colours();
    display_banner();
    LINFO("Starting frontend...");

    pid_t pid;
    int sock = launch_backend(&pid);
    LINFO("Dropping frontend privileges...");
    drop_privileges();

    for (;;) {
        display_menu();
        char choice[16];
        if (!read_line("  Choice: ", choice, sizeof choice)) break;
        switch (choice[0]) {
            case '1': if (login(sock) == APP_EXIT) goto done; break;
            case '2': display_about(); break;
            case '3': goto done;
            default:  printf("%s  Invalid choice. Please select 1-3.%s\n", C_YEL, C_RST);
        }
    }
done:
    LINFO("Shutting down. Closing backend connection...");
    close(sock);                 /* backend sees EOF and exits */
    waitpid(pid, NULL, 0);
    printf("\nGoodbye.\n");
    return 0;
}
