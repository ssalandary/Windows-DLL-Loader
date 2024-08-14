#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>

#define Log(lvl, fmt, ...) LogMessage(lvl, true, fmt, ##__VA_ARGS__)
#define LogNoNewline(lvl, fmt, ...) LogMessage(lvl, false, fmt, ##__VA_ARGS__)

typedef enum
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
} LogLevel;

void LogMessage(LogLevel level, bool bNewline, const char* fmt, ...);

void SetLogLevel(LogLevel lvl);
