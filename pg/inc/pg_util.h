#pragma once

#include <stdint.h>
#include <ctime>
#include <boost/asio.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_real.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/random/mersenne_twister.hpp>


namespace {
    using generator_type = boost::mt19937;
    static generator_type sRandomGenerator(static_cast<uint32_t>(std::time(nullptr)));

#if !defined(BOOST_NO_INT64_T) && !defined(BOOST_NO_INTEGRAL_INT64_T)
    using  generator_type_64 = boost::mt19937_64;
    static generator_type_64 sRandomGenerator64(static_cast<uint32_t>(std::time(nullptr)));
#endif

    template<bool>
    class Generator {
    private:
        Generator() {};
        ~Generator() {};

    public:
        template<class T>
        static T Random(T min, T max)
        {
            static_assert(std::is_integral<T>::value || std::is_floating_point<T>::value, "Must Integer or Float");
            assert(min < max);
            boost::uniform_int<T> degen_dist(min, max);
            boost::variate_generator<generator_type&, boost::uniform_int<T> > deg(sRandomGenerator, degen_dist);
            return deg();
        }
    };

    template<>
    class Generator<false> {
    public:
        template<class T>
        static T Random(T min, T max)
        {
            static_assert(std::is_integral<T>::value || std::is_floating_point<T>::value, "Must Integer or Float");
            assert(min < max);
            boost::uniform_real<T> degen_dist(min, max);
            boost::variate_generator<generator_type&, boost::uniform_real<T> > deg(sRandomGenerator, degen_dist);
            return deg();
        }
    };

    enum class Bits {
        _16 = 0,
        _32,
        _64
    };

    template<Bits>
    class Endian {
    private:
        Endian() {}
        ~Endian(){}

    public:
        template<class T>
        static T host_2_network()
        {
            return boost::asio::detail::socket_ops::host_to_network_short(T);
        }

        template<class T>
        static T network_2_host()
        {
            return boost::asio::detail::socket_ops::network_to_host_short(T);
        }
    };

    template<>
    class Endian<Bits::_32> {
    public:
        template<class T>
        static T host_2_network()
        {
            return boost::asio::detail::socket_ops::host_to_network_long(T);
        }

        template<class T>
        static T network_2_host()
        {
            return boost::asio::detail::socket_ops::network_to_host_long(T);
        }
    };

    template<>
    class Endian<Bits::_64> {
    public:
        template<class T>
        static T host_2_network()
        {
            return boost::asio::detail::socket_ops::host_to_network_long(T);
        }

        template<class T>
        static T network_2_host()
        {
            return boost::asio::detail::socket_ops::network_to_host_long(T);
        }
    };
}

namespace PG {
    template<class T>
    T GenerateRandom(T min, T max)
    {
        static_assert(std::is_integral<T>::value || std::is_floating_point<T>::value, "Must Integer or Float");

        using is_integer = std::integral_constant<bool, std::is_integral<T>::value >;
        return Generator<is_integer::value>::Random(min, max);
    }

    static uint32_t GenerateRandom32()
    {
        return sRandomGenerator();
    }

    static uint64_t GenerateRandom64()
    {
        return GenerateRandom<uint64_t>(0, 0xFFFFFFFF);
    }

    template<class T>
    T host_to_network(T t)
    {
        static_assert(std::is_unsigned<t>::value && sizeof(T) > 1, "MUST be unsigned and sizeof(T) > 1");
    }

    template<class T>
    T network_to_host(T t)
    {
        static_assert(std::is_unsigned<t>::value && sizeof(T) > 1, "MUST be unsigned and sizeof(T) > 1");
    }
}