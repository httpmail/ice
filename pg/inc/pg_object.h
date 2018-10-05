#pragma once

#include <string>
#include <set>

namespace PG {
    class CObject {
    public:
        CObject(const std::string& unique_name);
        virtual ~CObject() = 0 {}

    protected:
        virtual std::string UniqueStringName() const = 0;

    protected:
        using Objects = std::set<std::string>;

    protected:
        static Objects sOjbects;
    };
}