#pragma once

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <vector>
#include <string>
#include <fstream>
#include "pg_buffer.h"

#define Enum2String(var) #var

#define LOG_INFO(_module, _fmt, ...)     PG::log::Instance().Output(_module, __FILE__, __LINE__, Enum2String(PG::log::level::Info),    _fmt, ##__VA_ARGS__)
#define LOG_WARNING(_module, _fmt, ...)  PG::log::Instance().Output(_module, __FILE__, __LINE__, Enum2String(PG::log::level::Warning), _fmt, ##__VA_ARGS__)
#define LOG_ERROR(_module, _fmt, ...)    PG::log::Instance().Output(_module, __FILE__, __LINE__, Enum2String(PG::log::level::Error),   _fmt, ##__VA_ARGS__)

namespace PG {
    class log {
    public:
        enum class level {
            Info,
            Warning,
            Error,
        };

    public:
        static log& Instance();

        bool SetLogFile(const std::string& file_path);
        void Output    (const char *pModule, const char *file_path, int line, const char* levelInfo, const char *pFormat, ...);

    private:
        log();
        ~log();

    private:
        log(const log&) = delete;
        log& operator=(const log&) = delete;

    private:
        static void WriterThread(log *pInstance);


    private:
        static const int sMaxLineLength = 1024;
        static const int sMaxHeadLength = 128;
        static const int sCacheSize     = 256;
        static const int sTLSCacheSize  = 256;

        using TLSContainer = PG::CircularBuffer<char, sMaxHeadLength, sTLSCacheSize>;
        using LogContainer = std::vector<TLSContainer*>;

    private:
        LogContainer            m_Logs;
        std::mutex              m_LogMutex;
        std::condition_variable m_LogCond;
        std::thread             m_WriteThrd;
        std::fstream            m_FileStream;
        std::atomic_bool        m_bQuit;
    };
}