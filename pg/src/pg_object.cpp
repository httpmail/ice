#include "pg_object.h"
#include "pg_log.h"

#include <assert.h>

namespace PG {
    CObject::Objects CObject::sOjbects;
    CObject::CObject(const std::string& unique_name) :
        m_unique_name(unique_name)
    {
        assert(sOjbects.find(m_unique_name) != sOjbects.end());
        sOjbects.insert(m_unique_name);
    }
}