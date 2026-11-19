/*
 * Shadetree iPhone Bridge: the stable launcher that macOS holds the iphone plugin's
 * Full Disk Access (FDA) grant against.
 *
 * Why it exists: macOS TCC checks FDA against the *responsible* process, not the
 * binary that calls open(). Claude Desktop starts MCP servers through
 * Claude.app/Contents/Helpers/disclaimer, which makes its first child (previously
 * `uv`, at a version-specific Homebrew path) the responsible process. FDA on
 * Claude.app is ignored, and FDA on uv breaks on every uv upgrade. This bridge
 * sits in that slot, so the one grant users make is to this bundle.
 *
 * Behavior:
 *   1. If this process is not its own responsible process (started from a
 *      terminal or IDE), re-spawn itself with responsibility disclaimed, so the
 *      grant is always checked against this bundle no matter what launched it.
 *   2. Spawn exactly `uv run --project <plugin root> --locked python -m
 *      shadetree_ai_plugins_iphone`, inheriting stdio, and stay alive as its
 *      parent. It must spawn and wait, not exec: after an exec, TCC would check
 *      uv instead of this bundle.
 *
 * Hardening: anything holding FDA that runs arbitrary input is an FDA bypass for
 * every other local program. So this bridge ignores all arguments, derives the
 * plugin root from its own location, and strips environment variables that
 * could redirect which interpreter or code runs (DYLD_*, PYTHON*, UV_*,
 * VIRTUAL_ENV, CONDA_*).
 *
 * Build: bridge/build.sh (universal arm64 + x86_64). The built bundle is
 * committed under bin/ because plugin installs copy files and never run a
 * build step.
 */

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/* Private but long-stable libsystem APIs; the same ones Claude's disclaimer,
 * iTerm2, and other launchers use. */
extern int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t *attrs, int disclaim);
extern pid_t responsibility_get_pid_responsible_for_pid(pid_t pid);

#define BRIDGE "shadetree-iphone-bridge"
#define SERVER_MODULE "shadetree_ai_plugins_iphone"

static volatile pid_t g_child = 0;

static void forward_signal(int sig) {
    if (g_child > 0) kill(g_child, sig);
}

static int wait_child(pid_t child) {
    g_child = child;
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror(BRIDGE ": waitpid");
            return 1;
        }
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

static int is_executable(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}

static int has_prefix(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int is_unsafe_env(const char *entry) {
    return has_prefix(entry, "DYLD_") || has_prefix(entry, "PYTHON") ||
           has_prefix(entry, "UV_") || has_prefix(entry, "VIRTUAL_ENV=") ||
           has_prefix(entry, "CONDA_");
}

static char **sanitized_env(void) {
    size_t n = 0;
    while (environ[n]) n++;
    char **env = calloc(n + 1, sizeof(char *));
    if (!env) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        if (!is_unsafe_env(environ[i])) env[j++] = environ[i];
    }
    env[j] = NULL;
    return env;
}

/* uv on PATH first, then the standard install locations. Claude Desktop may
 * start MCP servers with a minimal PATH, so the fallbacks matter. */
static int find_uv(char *out, size_t out_len) {
    const char *path = getenv("PATH");
    if (path && *path) {
        char *copy = strdup(path);
        if (copy) {
            char *save = NULL;
            for (char *dir = strtok_r(copy, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
                if (*dir != '/') continue; /* ignore relative PATH entries */
                snprintf(out, out_len, "%s/uv", dir);
                if (is_executable(out)) {
                    free(copy);
                    return 1;
                }
            }
            free(copy);
        }
    }
    const char *home = getenv("HOME");
    const char *home_rel[] = {".local/bin/uv", ".cargo/bin/uv"};
    for (size_t i = 0; home && i < sizeof(home_rel) / sizeof(*home_rel); i++) {
        snprintf(out, out_len, "%s/%s", home, home_rel[i]);
        if (is_executable(out)) return 1;
    }
    const char *abs[] = {"/opt/homebrew/bin/uv", "/usr/local/bin/uv"};
    for (size_t i = 0; i < sizeof(abs) / sizeof(*abs); i++) {
        snprintf(out, out_len, "%s", abs[i]);
        if (is_executable(out)) return 1;
    }
    return 0;
}

/* <root>/bin/<Bridge>.app/Contents/MacOS/<exe>: five dirname() steps up. */
static int plugin_root(const char *exe, char *out, size_t out_len) {
    char buf[PATH_MAX];
    snprintf(buf, sizeof buf, "%s", exe);
    for (int i = 0; i < 5; i++) {
        char *d = dirname(buf);
        if (!d) return 0;
        snprintf(buf, sizeof buf, "%s", d);
    }
    snprintf(out, out_len, "%s", buf);
    char marker[PATH_MAX];
    snprintf(marker, sizeof marker, "%s/src/" SERVER_MODULE "/__main__.py", out);
    return access(marker, R_OK) == 0;
}

int main(void) {
    char raw_exe[PATH_MAX];
    uint32_t raw_len = sizeof raw_exe;
    char exe[PATH_MAX];
    if (_NSGetExecutablePath(raw_exe, &raw_len) != 0 || !realpath(raw_exe, exe)) {
        fprintf(stderr, BRIDGE ": cannot resolve own executable path\n");
        return 1;
    }

    signal(SIGTERM, forward_signal);
    signal(SIGINT, forward_signal);
    signal(SIGHUP, forward_signal);

    char **env = sanitized_env();
    if (!env) {
        fprintf(stderr, BRIDGE ": out of memory\n");
        return 1;
    }

    if (responsibility_get_pid_responsible_for_pid(getpid()) != getpid()) {
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        responsibility_spawnattrs_setdisclaim(&attr, 1);
        char *child_argv[] = {exe, NULL};
        pid_t child;
        int rc = posix_spawn(&child, exe, NULL, &attr, child_argv, env);
        posix_spawnattr_destroy(&attr);
        if (rc != 0) {
            fprintf(stderr, BRIDGE ": re-spawn failed: %s\n", strerror(rc));
            return 1;
        }
        return wait_child(child);
    }

    char root[PATH_MAX];
    if (!plugin_root(exe, root, sizeof root)) {
        fprintf(stderr,
                BRIDGE ": %s is not inside the iphone plugin (expected <plugin>/bin/<app>)\n", exe);
        return 1;
    }

    char uv[PATH_MAX];
    if (!find_uv(uv, sizeof uv)) {
        fprintf(stderr, BRIDGE ": uv not found. Install it: "
                        "https://docs.astral.sh/uv/getting-started/installation/\n");
        return 127;
    }

    char *uv_argv[] = {uv,     "run",  "--project", root, "--locked",
                       "python", "-m", SERVER_MODULE, NULL};
    pid_t child;
    int rc = posix_spawn(&child, uv, NULL, NULL, uv_argv, env);
    if (rc != 0) {
        fprintf(stderr, BRIDGE ": failed to start %s: %s\n", uv, strerror(rc));
        return 1;
    }
    return wait_child(child);
}
