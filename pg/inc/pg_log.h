#pragma once

#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <string>
#include <fstream>

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
        static log& Instance() { static log sLog; return sLog; }
        bool Initlize(const std::string& file_path = "", int cache_size = sCacheSize);
        void Output  (const char *pModule, const char *file_path, int line, const char* levelInfo, const char *pFormat, ...);

    private:
        log();
        ~log();

    private:
        log(const log&) = delete;
        log& operator=(const log&) = delete;

        template<class _Rep,class _Period,class _Predicate>
        bool WaitForWriter(const std::chrono::duration<_Rep, _Period>& _Rel_time, _Predicate _Pred)
        {
            std::unique_lock<std::mutex> locker(m_writer_mutex);
            return m_writer_condition.wait_for(locker, _Rel_time, _Pred);
        }

        template<class _Predicate>
        void WaitWriter(_Predicate _Pred)
        {
            std::unique_lock<std::mutex> locker(m_writer_mutex);
            m_writer_condition.wait(locker, _Pred);
        }

    private:
        static void WriterThread(log *pInstance);
        static void TimerThread(log *pInstance);

    private:
        using LogContainer = std::vector<std::string>;

    private:
        bool                    m_quit;
        std::thread            *m_pThread;
        std::thread             m_timerThread;
        std::fstream            m_fileHandle;
        LogContainer            m_logs;
        std::condition_variable m_writer_condition;
        std::mutex              m_writer_mutex;

    private:
        static const int sMaxLineLength = 1024;
        static const int sMaxHeadLength = 128;
        static const int sCacheSize     = 256;
    };
}