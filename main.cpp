
#include "pg_log.h"
#include "pg_buffer.h"

#include "channel.h"
#include "ping.h"
#include "stundef.h"
#include "stunmsg.h"
#include "stunprotocol.h"

#include <iostream>
#include "session.h"
#include "agent.h"

#include <chrono>

#include <map>
#include <set>
#include <unordered_set>


class root {
public:
    root()
    {
        std::cout << "call root" << std::endl;
        sObjects.insert(this);
    }

    root(const root&) = delete;
    virtual ~root() {}

public:
    static std::unordered_set<root*> sObjects;
};

std::unordered_set<root*> root::sObjects;

class child : public root{
public:
    child() {}
    virtual ~child() {}
};

class child0 : public child {
public:
    child0() {}
    ~child0() {}
    child0(const child0&)
    {
        std::cout << "call child0" << std::endl;
    }
};
int main(void)
{

    child0 _1;
    child0 _2(_1);
    child0 _3 = _2;
    return 0;
}
