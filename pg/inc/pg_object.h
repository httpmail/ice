#pragma once

#include <string>
#include <set>

namespace PG {
    class CObject {
    public:
        CObject(const std::string& unique_name);
        virtual ~CObject() = 0 {}

    public:
        std::string UniqueStringName() const { return m_unique_name; }

    protected:
        using Objects = std::set<std::string>;

    protected:
        const std::string m_unique_name;

    protected:
        static Objects sOjbects;
    };
}