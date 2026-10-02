#pragma once

#include "sniffcraft/enums.hpp"

#include "protocolCraft/enums.hpp"
#include "protocolCraft/Packet.hpp"

#include <chrono>
#include <memory>
#include <vector>

struct LogItem
{
    std::shared_ptr<ProtocolCraft::Packet> packet;
    std::chrono::time_point<std::chrono::system_clock> date;
    ProtocolCraft::ConnectionState connection_state;
    Endpoint origin;
    size_t bandwidth_bytes;
    /// @brief Bytes (packet id included) of a packet that couldn't be parsed, only set when packet is nullptr
    std::vector<unsigned char> raw_bytes;
};
