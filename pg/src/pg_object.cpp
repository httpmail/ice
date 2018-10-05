#include "pg_object.h"
#include "pg_log.h"

namespace PG {
    CObject::Objects CObject::sOjbects;

    CObject::CObject(const std::string& unique_name)
    {
        if (sOjbects.find(unique_name) != sOjbects.end())
        {
            LOG_ERROR(unique_name.c_str(), "object [%s] already existed", unique_name.c_str());
        }
        else
        {
            sOjbects.insert(unique_name);
        }
    }
}