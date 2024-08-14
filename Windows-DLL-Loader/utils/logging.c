#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "logging.h"

LogLevel gLogLevel = Info;

void SetLogLevel(LogLevel lvl)
{
    gLogLevel = lvl;
}

void LogMessage(LogLevel level, bool bNewline, const char* fmt, ...)
{
    va_list va;
    const static char* prefixes[] = {
        " [+] ", // Debug
        " [+] ", // Info
        " [?] ", // Warning
        " [!] "  // Error
    };

    if (level < gLogLevel)
    {
        return;
    }

    // Calculate the length of the final format string
    size_t prefixedLen = strlen(prefixes[level]) + strlen(fmt) + (bNewline ? 1 : 0) + 1;
    char* prefixedFmt = (char*)malloc(prefixedLen);

    if (prefixedFmt == NULL) {
        // Handle memory allocation failure
        return;
    }

    // Create the final format string
    snprintf(prefixedFmt, prefixedLen, "%s%s%s", prefixes[level], fmt, bNewline ? "\n" : "");

    va_start(va, fmt);

    vprintf(prefixedFmt, va);

    va_end(va);

    // Free allocated memory
    free(prefixedFmt);
}
