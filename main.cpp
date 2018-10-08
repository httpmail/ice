
#include "pg_log.h"
#include "pg_buffer.h"

#include "channel.h"
#include <thread>
#include <iostream>

int main(void)
{

    char tmp[256];

    std::string read_info;
    const std::string write_info("0123456789");

    PG::circular_buffer buf(10);

    buf.write(write_info.data(), write_info.length());

    int read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    read_bytes = buf.read(tmp, 3);
    std::cout << std::string(tmp, read_bytes) << std::endl;

    buf.write(write_info.data(), write_info.length());
    read_bytes = buf.read(tmp, write_info.length());

    std::cout << std::string(tmp, read_bytes) << std::endl;


    return 0;
}