/*
 * Process uLog simple log library
 * Author: TyK <tisyang@gmail.com>
 * License: MIT License
 * Date: 2026-02-06
 *
 *
 */

#ifndef ULOG_MACRO_LOG_H
#define ULOG_MACRO_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

enum uLogLevel {
    ULOG_LL_DEBUG   = 0,
    ULOG_LL_INFO    = 1,
    ULOG_LL_NOTICE  = 2,
    ULOG_LL_WARNING = 3,
    ULOG_LL_ERROR   = 4,
    ULOG_LL__COUNT
};

// short __FILE___ macro
# define ULOG_FILENAME  (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
# define ULOG_FILELINE  __LINE__
# define ULOG_FUNCNAME  __func__

// log output to new file (not affect stdou/stderr)
// return 0 OK, otherwise error
// filepath: NULL => close output to file
int  ulog_tofile(const char *newfile);
// get ulog current log file bytes
// return 0 OK, otherwise error
// *size storege filesize
int  ulog_size(long *size);
// flush file
void ulog_flush();
// core output function
void ulog_output(int level, const char *file, int line, const char *func, const char *msg);
// core printf function
void ulog_printf(int level, const char *file, int line, const char *func, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));


// set output level
// return 0 OK, otherwise error
int  ulog_set_level(int level);

#define ULOG_TIMEFMT_LONG   "YYYY-mm-dd HH:MM::SS.ssssss"
#define ULOG_TIMEFMT_SHORT  "mm/dd HH:MM:SS.ssssss"
#define ULOG_TIMEFMT_MONO   "mono.sssssss"
// set output time fmt
// return 0 OK, otherwise error
int  ulog_set_timefmt(const char *timefmt);

#define ULOG_SRCFMT_FULL    "file:line [tid]func"
#define ULOG_SRCFMT_LONG    "file:line func"
#define ULOG_SRCFMT_SHORT   "file:line"
#define ULOG_SRCFMT_NONE    ""
// set output src fmt, file line func
// return 0 OK, otherwise error
int  ulog_set_srcfmt(const char *srcfmt);

#define ULOG_LEVEL_(level, fmt, ...) \
        ulog_printf(level, ULOG_FILENAME, ULOG_FILELINE, ULOG_FUNCNAME, fmt, ##__VA_ARGS__)

// debug macro
#define ulog_debug(fmt, ...)   ULOG_LEVEL_(ULOG_LL_DEBUG,   fmt, ##__VA_ARGS__)
#define ulog_info(fmt, ...)    ULOG_LEVEL_(ULOG_LL_INFO,    fmt, ##__VA_ARGS__)
#define ulog_notice(fmt, ...)  ULOG_LEVEL_(ULOG_LL_NOTICE,  fmt, ##__VA_ARGS__)
#define ulog_warn(fmt, ...)    ULOG_LEVEL_(ULOG_LL_WARNING, fmt, ##__VA_ARGS__)
#define ulog_error(fmt, ...)   ULOG_LEVEL_(ULOG_LL_ERROR,   fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

# ifdef ULOG_IMPLEMENTATION
#  ifndef ULOG_LINEBUF_MAXSZ
#   define ULOG_LINEBUF_MAXSZ   4096
#  endif
#  include <stdio.h>
#  include <time.h>
#  include <stdarg.h>
#  include <stdatomic.h>
#  include <errno.h>
#  include <string.h>
#  include <unistd.h>
#  include <sys/syscall.h>

static pid_t ulog_get_tid(void) {
    static __thread pid_t cached_tid = 0;
    if (__builtin_expect(cached_tid == 0, 0)) {
        cached_tid = (pid_t)syscall(SYS_gettid);
    }
    return cached_tid;
}

static const char * const LEVEL_STR[ULOG_LL__COUNT] = {
    [ULOG_LL_DEBUG]     = "D ",
    [ULOG_LL_INFO]      = "I ",
    [ULOG_LL_NOTICE]    = "N ",
    [ULOG_LL_WARNING]   = "W ",
    [ULOG_LL_ERROR]     = "E ",
};

static const char* const LEVEL_TERM_COLOR[] = {
    [ULOG_LL_DEBUG]     = "\x1b[34m",
    [ULOG_LL_INFO]      = "\x1b[32m",
    [ULOG_LL_NOTICE]    = "\x1b[35m",
    [ULOG_LL_WARNING]   = "\x1b[33m",
    [ULOG_LL_ERROR]     = "\x1b[31m",
};
#define COLOR_SRC   "\x1b[90m"
#define COLOR_TIME  "\x1b[90m"
#define COLOR_RESET "\x1b[0m"


#define LEVEL_FROM_BITS(bits)   ((bits) & 0xF)
#define LEVEL_TO_BITS(lv)       ((lv) & 0xF)

enum uLogTimeFmt {
    TIMEFMT_MONO    = 0,
    TIMEFMT_LONG    = 1,
    TIMEFMT_SHORT   = 2,
    TIMEFMT__COUNT
};
#define TIMEFMT_FROM_BITS(bits) (((bits) >> 4) & 0xF)
#define TIMEFMT_TO_BITS(fmt)    (((fmt) & 0xF) << 4)

enum uLogSrcFmt {
    SRCFMT_NONE     = 0,
    SRCFMT_SHORT    = 1,
    SRCFMT_LONG     = 2,
    SRCFMT_FULL     = 3,
    SRCFMT__COUNT
};
#define SRCFMT_FROM_BITS(bits)  (((bits) >> 8) & 0xF)
#define SRCFMT_TO_BITS(fmt)     (((fmt) & 0xF) << 8)


struct ulog_ctx {
    int     tty_bits;       // tty check:
                            // bit 0: if checked
                            // bit 1: stdout tty
                            // bit 2: stderr tty
    FILE    *fp;            // current fp

    time_t  last_sec;           // last format sec
    char    last_time_str[32];  // last time str
    atomic_uint flags;      // atomic bitflags for internal log fmt use
                            // bit [0:3] => log level
                            // bit [4:8] => time format
                            // bit [8:11] => src format
    atomic_flag write_lock; // atomic lock for internal write
};

#define ULOG_DEFAULT_FLAGS \
    (LEVEL_TO_BITS(ULOG_LL_DEBUG) | TIMEFMT_TO_BITS(TIMEFMT_SHORT) | SRCFMT_TO_BITS(SRCFMT_SHORT))

static struct ulog_ctx g_ulog_ctx = {
    .tty_bits = 0,
    .fp = NULL,
    .flags = ULOG_DEFAULT_FLAGS,
    .write_lock = ATOMIC_FLAG_INIT,
    .last_sec = 0,
};

static inline void ulog_lock(struct ulog_ctx *ctx)
{
    while (atomic_flag_test_and_set_explicit(&ctx->write_lock, memory_order_acquire)) {
#if defined(__i386__) || defined(__x86_64__)
        __asm__ __volatile__("pause");
#elif defined(__arm__) || defined(__aarch64__)
        __asm__ __volatile__("yield");
#elif defined(__riscv__)
        __asm__ __volatile__ ("pause" ::: "memory");
#else
#endif
    }
}

static inline void ulog_unlock(struct ulog_ctx *ctx)
{
    atomic_flag_clear_explicit(&ctx->write_lock, memory_order_release);
}

int  ulog_set_level(int level)
{
    if (level >= ULOG_LL_DEBUG && level < ULOG_LL__COUNT) {
        unsigned expected = atomic_load(&g_ulog_ctx.flags);
        unsigned desired;
        unsigned mask = 0xF;
        do {
            desired = (expected & ~mask) | (level & mask);
        } while (!atomic_compare_exchange_weak(&g_ulog_ctx.flags, &expected, desired));
        return 0;
    } else {
        return EINVAL;
    }
}

int  ulog_set_timefmt(const char *timefmt)
{
    int fmt = -1;
    if (fmt) {
        if (strcmp(timefmt, ULOG_TIMEFMT_LONG) == 0) {
            fmt = TIMEFMT_LONG;
        } else if (strcmp(timefmt, ULOG_TIMEFMT_SHORT) == 0) {
            fmt = TIMEFMT_SHORT;
        } else if (strcmp(timefmt, ULOG_TIMEFMT_MONO) == 0) {
            fmt = TIMEFMT_MONO;
        }
    }
    if (fmt >= TIMEFMT_MONO && fmt < TIMEFMT__COUNT) {
        unsigned expected = atomic_load(&g_ulog_ctx.flags);
        unsigned desired;
        unsigned mask = 0xF0;
        do {
            desired = (expected & ~mask) | (TIMEFMT_TO_BITS(fmt) & mask);
        } while (!atomic_compare_exchange_weak(&g_ulog_ctx.flags, &expected, desired));
        return 0;
    } else {
        return EINVAL;
    }
}

int  ulog_set_srcfmt(const char *srcfmt)
{
    int fmt = -1;
    if (fmt) {
        if (strcmp(srcfmt, ULOG_SRCFMT_NONE) == 0) {
            fmt = SRCFMT_NONE;
        } else if (strcmp(srcfmt, ULOG_SRCFMT_LONG) == 0) {
            fmt = SRCFMT_LONG;
        } else if (strcmp(srcfmt, ULOG_SRCFMT_SHORT) == 0) {
            fmt = SRCFMT_SHORT;
        } else if (strcmp(srcfmt, ULOG_SRCFMT_FULL) == 0) {
            fmt = SRCFMT_FULL;
        }
    }
    if (fmt >= SRCFMT_NONE && fmt < SRCFMT__COUNT) {
        unsigned expected = atomic_load(&g_ulog_ctx.flags);
        unsigned desired;
        unsigned mask = 0xF00;
        do {
            desired = (expected & ~mask) | (SRCFMT_TO_BITS(fmt) & mask);
        } while (!atomic_compare_exchange_weak(&g_ulog_ctx.flags, &expected, desired));
        return 0;
    } else {
        return EINVAL;
    }
}

int ulog_size(long *size)
{
    long fsize = 0;
    int ret = 0;
    ulog_lock(&g_ulog_ctx);
    if (g_ulog_ctx.fp) {
        fsize = ftell(g_ulog_ctx.fp);
        if (fsize < 0) {
            ret = errno;
        }
    } else {
        ret = ENOENT;
    }
    ulog_unlock(&g_ulog_ctx);
    if (ret == 0 && size) *size = fsize;
    return ret;
}

int ulog_tofile(const char *newfile)
{
    int ret = 0;
    ulog_lock(&g_ulog_ctx);

    if (g_ulog_ctx.tty_bits == 0) {
        g_ulog_ctx.tty_bits = 1;
        g_ulog_ctx.tty_bits |= (!!isatty(fileno(stdout))) << 1;
        g_ulog_ctx.tty_bits |= (!!isatty(fileno(stderr))) << 2;
    }

    if (g_ulog_ctx.fp) {
        fflush(g_ulog_ctx.fp);
        fclose(g_ulog_ctx.fp);
        g_ulog_ctx.fp = NULL;
    }

    if (newfile) {
        g_ulog_ctx.fp = fopen(newfile, "ae");
        if (!g_ulog_ctx.fp) {
            ret = errno;
        }
    }

    ulog_unlock(&g_ulog_ctx);
    if (ret) {
        ulog_error("ulog_tofile newfile='%s' failed, %s", newfile, strerror(ret));
    }
    return ret;
}

void ulog_flush()
{
    ulog_lock(&g_ulog_ctx);
    if (g_ulog_ctx.fp) {
        fflush(g_ulog_ctx.fp);
        int fd = fileno(g_ulog_ctx.fp);
        if (fd >= 0 && !isatty(fd)) {
            fsync(fd);
        }
    }
    ulog_unlock(&g_ulog_ctx);
}

// core output function
void ulog_output(int level, const char *file, int line, const char *func, const char *msg)
{
    int msg_len = strlen(msg);

    unsigned flags = atomic_load_explicit(&g_ulog_ctx.flags, memory_order_relaxed);
    if (level < LEVEL_FROM_BITS(flags)) return;

    int timefmt = TIMEFMT_FROM_BITS(flags);
    struct timespec ts = {0};
    clock_gettime(timefmt == TIMEFMT_MONO ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts);

    int srcfmt = SRCFMT_FROM_BITS(flags);
    char srcbuf[256] = {0};
    file = file ?: "<\?\?\?>";
    func = func ?: "<\?\?\?>";
    char lbuf[16] = "?";
    if (line >= 0) {
        snprintf(lbuf, sizeof(lbuf), "%d", line);
    }
    switch (srcfmt) {
    case SRCFMT_FULL:
        snprintf(srcbuf, sizeof(srcbuf), "%s:%s [%d]%s", file, lbuf, ulog_get_tid(), func);
        break;
    case SRCFMT_LONG:
        snprintf(srcbuf, sizeof(srcbuf), "%s:%s %s", file, lbuf, func);
        break;
    case SRCFMT_SHORT:
        snprintf(srcbuf, sizeof(srcbuf), "%s:%s", file, lbuf);
        break;
    }

    ulog_lock(&g_ulog_ctx);
    if (g_ulog_ctx.tty_bits == 0) {
        g_ulog_ctx.tty_bits = 1;
        g_ulog_ctx.tty_bits |= (!!isatty(fileno(stdout))) << 1;
        g_ulog_ctx.tty_bits |= (!!isatty(fileno(stderr))) << 2;
    }

    if (__builtin_expect(ts.tv_sec != g_ulog_ctx.last_sec, 0)) {
        if (timefmt == TIMEFMT_MONO) {
            snprintf(g_ulog_ctx.last_time_str, sizeof(g_ulog_ctx.last_time_str), "%lld", (long long)ts.tv_sec);
        } else {
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            strftime(g_ulog_ctx.last_time_str, sizeof(g_ulog_ctx.last_time_str),
                timefmt == TIMEFMT_LONG ? "%Y-%m-%d %H:%M:%S" : "%m/%d %H:%M:%S",
                &tm_info);
        }
        g_ulog_ctx.last_sec = ts.tv_sec;
    }

    FILE *fcur = (level >= ULOG_LL_ERROR) ? stderr : stdout;
    int fd_idx = (level >= ULOG_LL_ERROR) ? 2 : 1;
    bool is_tty = (g_ulog_ctx.tty_bits >> fd_idx) & 1;
    if (is_tty) {
        fputs(COLOR_TIME, fcur);
        // only show time on screen
        fputs(g_ulog_ctx.last_time_str, fcur);
        fprintf(fcur, ".%06ld ", ts.tv_nsec / 1000);
        fputs(LEVEL_TERM_COLOR[level], fcur);
        fputs(LEVEL_STR[level], fcur);
        fputs(COLOR_SRC, fcur);
        fputs(srcbuf, fcur);
        fputs(COLOR_RESET, fcur);
        fputs(": ", fcur);
    } else {
        fputs(g_ulog_ctx.last_time_str, fcur);
        fprintf(fcur, ".%06ld ", ts.tv_nsec / 1000);
        fputs(LEVEL_STR[level], fcur);
        fputs(srcbuf, fcur);
        fputs(": ", fcur);
    }
    fwrite(msg, 1, (msg_len > ULOG_LINEBUF_MAXSZ ? ULOG_LINEBUF_MAXSZ : msg_len), fcur);
    fputc('\n', fcur);

    if (g_ulog_ctx.fp) {
        fcur = g_ulog_ctx.fp;
        fputs(g_ulog_ctx.last_time_str, fcur);
        fprintf(fcur, ".%06ld ", ts.tv_nsec / 1000);
        fputs(LEVEL_STR[level], fcur);
        fputs(srcbuf, fcur);
        fputs(": ", fcur);
        fwrite(msg, 1, (msg_len > ULOG_LINEBUF_MAXSZ ? ULOG_LINEBUF_MAXSZ : msg_len), fcur);
        fputc('\n', fcur);
    }

    ulog_unlock(&g_ulog_ctx);
}

// core printf function
void ulog_printf(int level, const char *file, int line, const char *func, const char *fmt, ...)
{
    unsigned flags = atomic_load_explicit(&g_ulog_ctx.flags, memory_order_relaxed);
    if (level < LEVEL_FROM_BITS(flags)) return;

    char buff[ULOG_LINEBUF_MAXSZ];
    va_list arglist;
    va_start(arglist, fmt);
    vsnprintf(buff, sizeof(buff), fmt, arglist);
    va_end(arglist);
    ulog_output(level, file, line, func, buff);
}

# endif // ULOG_IMPLEMENTATION

#endif // ULOG_MACRO_LOG_H
