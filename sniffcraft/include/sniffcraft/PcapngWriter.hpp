#pragma once

#include <protocolCraft/Utilities/Json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// @brief One field of a parsed packet, flattened in depth-first order
struct PcapngField
{
    enum class Kind : uint8_t
    {
        Value = 0,
        Object = 1,
        Array = 2,
        Truncated = 3
    };

    Kind kind;
    uint16_t depth;
    std::string name;
    std::string value;
    /// @brief Byte range [start, end) of this field inside PcapngRecord::raw, UINT32_MAX if unknown
    uint32_t start;
    uint32_t end;
};

/// @brief Everything the sniffcraft Wireshark dissector needs to display one packet
struct PcapngRecord
{
    uint8_t origin = 0;
    /// @brief ProtocolCraft::ConnectionState, 0xFF for None
    uint8_t connection_state = 0xFF;
    bool parse_error = false;
    uint32_t protocol_version = 0;
    uint32_t connection_id = 0;
    uint32_t wire_size = 0;
    int32_t packet_id = -1;
    std::string name;
    /// @brief Uncompressed and decrypted packet bytes, packet id included
    std::vector<unsigned char> raw;
    std::vector<PcapngField> fields;
    std::string json;
};

/// @brief Minimal pcapng writer. Each packet is stored as LINKTYPE_WIRESHARK_UPPER_PDU
/// with the "sniffcraft" dissector name. See wireshark/sniffcraft.lua for the payload format.
class PcapngWriter
{
public:
    PcapngWriter();
    ~PcapngWriter();

    /// @brief Open a file (or a named pipe/fifo) and write the section and interface headers
    /// @param path Path of the file to (over)write
    /// @return True if the file was opened and the headers written
    bool Open(const std::string& path);
    bool IsOpen() const;
    /// @brief True if a write failed, for example because Wireshark closed the capture pipe
    bool HasFailed() const;
    void Close();

    void Write(const std::chrono::system_clock::time_point& date, const PcapngRecord& record);
    /// @brief Write an empty interface statistics block, used to detect a closed capture pipe
    void WriteHeartbeat();

    /// @brief Writer shared by all connections (used in extcap mode), nullptr if not set
    static std::shared_ptr<PcapngWriter> GetShared();
    static void SetShared(const std::shared_ptr<PcapngWriter>& writer);

private:
    void WriteBlock(const uint32_t type, const std::vector<unsigned char>& body);

private:
    mutable std::mutex mutex;
    std::FILE* file;
    std::atomic<bool> failed;

    static std::shared_ptr<PcapngWriter> shared_writer;
    static std::mutex shared_writer_mutex;
};

/// @brief Flatten a packet json (as returned by Packet::Serialize) into a list of fields
/// @param json Packet json, with or without parsing details
/// @param raw_size Size of the raw packet bytes the json was read from, packet id included
/// @return Flattened fields, ordered as they appear in the packet when offsets are known
std::vector<PcapngField> PcapngFieldsFromJson(const ProtocolCraft::Json::Value& json, const size_t raw_size);

/// @brief Remove the byte offsets from a json produced with PROTOCOLCRAFT_DETAILED_PARSING
ProtocolCraft::Json::Value PcapngStripOffsets(const ProtocolCraft::Json::Value& json);
