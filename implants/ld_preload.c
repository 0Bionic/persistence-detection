/* Harmless LD_PRELOAD payload for the persistence-detection project.
 *
 * Once listed in /etc/ld.so.preload, the dynamic linker loads this shared
 * object into *every* new ELF process on the system (that is the whole
 * point of the technique, and also why it is dangerous if done wrong — see
 * proposal section 9). Its constructor runs once per process, right before
 * main(), and appends one marker line via the same _marker.sh payload every
 * other implant uses.
 *
 * The marker file path and the implants/ directory are baked in at compile
 * time (ld_preload.sh passes them as -D flags), not read from the
 * environment: a real implant can't rely on every process on the system
 * happening to inherit its env vars, so neither does this one.
 *
 * Two safety measures, because this constructor itself runs inside new
 * processes that this constructor spawns:
 *   1. PD_LD_PRELOAD_GUARD breaks the recursion: the marker-writing child
 *      process we fork is launched with the guard set, so its own copy of
 *      this constructor (also preloaded into it, since the hook is global)
 *      returns immediately instead of forking again.
 *   2. A simple mtime-based rate limit keeps a busy system from turning
 *      into a fork storm of marker writers (every single process on the
 *      box would otherwise trigger one system() call each).
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifndef PD_MARKER_FILE_PATH
#define PD_MARKER_FILE_PATH "/tmp/pd-markers/markers.log"
#endif
#ifndef PD_IMPLANT_DIR_PATH
#define PD_IMPLANT_DIR_PATH "."
#endif

__attribute__((constructor))
static void pd_ld_preload_ctor(void) {
    if (getenv("PD_LD_PRELOAD_GUARD") != NULL) {
        return; /* this is our own marker-writer child; do nothing */
    }

    /* Rate limit: skip if the marker file was touched in the last second. */
    struct stat st;
    if (stat(PD_MARKER_FILE_PATH, &st) == 0) {
        time_t now = time(NULL);
        if (now - st.st_mtime < 1) {
            return;
        }
    }

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "/usr/bin/env PD_MARKER_FILE=%s "
             "bash %s/_marker.sh ld_preload >/dev/null 2>&1",
             PD_MARKER_FILE_PATH, PD_IMPLANT_DIR_PATH);

    /* system() forks /bin/sh -c cmd, which inherits our environment. Set the
     * guard there (not just in the command string) so that forked shell -
     * which is itself preloaded with this very library - sees the guard
     * before its own constructor runs, instead of recursing one more level
     * first. Unset it again after so the calling process's own environment
     * (e.g. a long-lived login shell) isn't permanently silenced. */
    setenv("PD_LD_PRELOAD_GUARD", "1", 1);
    if (system(cmd) == -1) {
        /* best-effort marker; nothing to do if the fork/exec itself failed */
    }
    unsetenv("PD_LD_PRELOAD_GUARD");
}
