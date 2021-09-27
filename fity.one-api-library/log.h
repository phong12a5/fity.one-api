#ifndef LOG_H
#define LOG_H

#include <errno.h>
#include <iostream>

#ifdef ANDROID
#include <android/log.h>

#ifdef DEBUG_MODE
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, __FUNCTION__, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG  , __FUNCTION__, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO   , __FUNCTION__, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN   , __FUNCTION__, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR  , __FUNCTION__, __VA_ARGS__)
#else
#define LOGV(...)
#define LOGD(...)
#define LOGI(...)
#define LOGW(...)
#define LOGE(...)
#endif

#else /* ANDROID */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <cstring>

#ifdef DEBUG_MODE
#define LOGV(...) D(__VA_ARGS__)
#define LOGD(...) D(__VA_ARGS__)
#define LOGI(...) D(__VA_ARGS__)
#define LOGW(...) D(__VA_ARGS__)
#define LOGE(...) E(__VA_ARGS__)

static void
D(const char *msg, ...)
{
    va_list ap;

    va_start (ap, msg);
    vfprintf(stdout, msg, ap);
    fprintf(stdout, "\n");
    va_end (ap);
    fflush(stdout);
}

static void
E(const char *msg, ...)
{
    va_list ap;

    va_start (ap, msg);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, ", %s", strerror(errno));
    fprintf(stderr, "\n");
    va_end (ap);
}
#else
#define LOGV(...)
#define LOGD(...)
#define LOGI(...)
#define LOGW(...)
#define LOGE(...)
#endif

#endif /* ANDROID */

#endif // LOG_H
