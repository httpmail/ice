#include "pg_log.h"

#include <assert.h>
#include <stdarg.h>
#include <iostream>
#include <boost/filesystem.hpp>

namespace PG {
    log::log() :
        m_quit(false), m_bInited(false), m_writeThread(log::WriterThread, this)
    {
        m_logs.reserve(sCacheSize);
    }

    log::~log()
    {
        // check if all the log has been stored in file
        {
            std::unique_lock<std::mutex> lock(m_writer_mutex);
            m_writer_condition.wait(lock, [this] {
                return m_logs.empty();
            });
            m_quit = true;
        }

        // notify writerthread
        m_writer_condition.notify_one();

        if (m_writeThread.joinable())
            m_writeThread.join();
    }

    log & log::Instance()
    {
        static log sInstance;
        return sInstance;
    }

    bool log::Initlize(const std::string& file_path, int cache_size /* = sCacheSize */)
    {
        assert(cache_size);
        if (m_bInited)
            return true;

        m_bInited = true;

        std::lock_guard<std::mutex> locker(m_writer_mutex);

        m_logs.reserve(cache_size);
        m_fileHandle.open(file_path, std::ios::app);

        return m_fileHandle.is_open();
    }

    void log::Output(const char *pModule, const char *file_path, int line, const char* levelInfo, const char *pFormat, ...)
    {
        assert(file_path && pFormat && levelInfo);

        {
            std::lock_guard<std::mutex> lock(m_writer_mutex);
            assert(!m_quit);
        }

        char log[sMaxLineLength];

        namespace boost_fs = boost::filesystem;
        try
        {
            boost_fs::path full_path(file_path, boost_fs::native);
            assert(boost_fs::is_regular_file(full_path) && boost_fs::exists(full_path));

            auto head_len = sprintf_s(log, sMaxHeadLength, "%s-%s-%d",
                levelInfo, full_path.filename().string().c_str(), line);

            va_list argp;
            va_start(argp, pFormat);
            vsnprintf(&log[head_len], sMaxHeadLength - head_len, pFormat, argp);
            va_end(argp);

            std::lock_guard<std::mutex> lock(m_writer_mutex);
            m_logs.push_back(log);

            if (m_logs.size() == m_logs.capacity())
                m_writer_condition.notify_one();
        }
        catch (const boost_fs::filesystem_error& e)
        {
            (void)e;
        }
    }

    void log::WriterThread(log *pInstance)
    {
        assert(pInstance == &log::Instance());

        while (1)
        {
            std::unique_lock<std::mutex> lock(pInstance->m_writer_mutex);

            pInstance->m_writer_condition.wait_for(lock, std::chrono::seconds(10), [&pInstance] {
                return !pInstance->m_logs.empty() || pInstance->m_quit;
            });

            if (pInstance->m_logs.empty() && pInstance->m_quit)
                break;

            if (!pInstance->m_logs.empty())
            {
                LogContainer logs(pInstance->m_logs);
                pInstance->m_logs.clear();
                lock.unlock();

                // write log to file
                std::ostream& stream = pInstance->m_fileHandle.is_open() ? pInstance->m_fileHandle : std::cout;
                for (auto log : logs)
                    stream << log << std::endl;
                stream.flush();
            }
        }
    }
}