#include "pg_object.h"
#include "pg_log.h"

#include <assert.h>

namespace PG {
    CObject::Objects CObject::sOjbects;
    CObject::CObject(const std::string& unique_name)
    {
        assert(sOjbects.find(unique_name) != sOjbects.end());
        sOjbects.insert(unique_name);
    }
}