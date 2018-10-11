#pragma once

#include <string>
#include <map>
#include <set>

namespace ICE {
    class CSession;
    class CAgent{
    public:
        class CAgentConfig {
        public:
            CAgentConfig();
            virtual ~CAgentConfig();

        public:
            bool Initilize(const std::string& config_file);

        private:
            uint16_t m_RTO; /* initial value recommended 500ms - 3s */
            uint16_t m_Ta;  /* default value 50ms */
            uint16_t m_Rm;  /* default value 16   */
            uint16_t m_Ti;  /* default value 39500ms(39.5s) */
            uint16_t m_Rc;  /* default value 7 */
            uint16_t m_cand_pairs_limits; /* defualt value 100*/
            bool     m_ipv4_supported; 
        };
    };
}