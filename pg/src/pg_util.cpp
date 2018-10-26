#pragma once

#include "pg_util.h"
#include <boost/random/linear_congruential.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_real.hpp>
#include <boost/random/uniform_01.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/generator_iterator.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <ctime>

namespace {
    using generator_type = boost::mt19937;
    static generator_type sRandomGenerator(static_cast<uint32_t>(std::time(nullptr)));
}

namespace PG {
    int16_t GenerateRandomNum(int16_t lower, int16_t upper)
    {
        assert(lower < upper);
        boost::uniform_int<> degen_dist(lower, upper);
        boost::variate_generator<generator_type&, boost::uniform_int<> > deg(sRandomGenerator, degen_dist);

        return deg();
    }
}