#include "sniffcraft/PcapngWriter.hpp"

#include <algorithm>
#include <limits>
#include <type_traits>
#include <utility>

using namespace ProtocolCraft;

namespace
{
    constexpr uint32_t block_type_shb = 0x0A0D0D0A;
    constexpr uint32_t block_type_idb = 0x00000001;
    constexpr uint32_t block_type_isb = 0x00000005;
    constexpr uint32_t block_type_epb = 0x00000006;
    constexpr uint32_t byte_order_magic = 0x1A2B3C4D;

    constexpr uint16_t option_end_of_opt = 0;
    constexpr uint16_t option_shb_userappl = 4;
    constexpr uint16_t option_if_name = 2;
    constexpr uint16_t option_if_description = 3;

    constexpr uint16_t linktype_wireshark_upper_pdu = 252;
    constexpr uint16_t exp_pdu_tag_end_of_opt = 0;
    constexpr uint16_t exp_pdu_tag_dissector_name = 12;
    constexpr std::string_view dissector_name = "sniffcraft";

    constexpr char record_magic[4] = { 'S', 'C', 'M', 'C' };
    constexpr uint8_t record_format_version = 1;
    constexpr uint8_t record_flag_parse_error = 1 << 0;
    constexpr uint8_t record_flag_has_offsets = 1 << 1;

    constexpr uint32_t unknown_offset = std::numeric_limits<uint32_t>::max();
    constexpr size_t max_fields = 4096;
    constexpr size_t max_array_elements = 256;
    constexpr size_t max_value_size = 4096;

    /// @brief pcapng blocks use the writer endianness, given by the section header byte order magic
    template <typename T>
    void AppendHost(std::vector<unsigned char>& out, const T value)
    {
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&value);
        out.insert(out.end(), bytes, bytes + sizeof(T));
    }

    /// @brief Exported PDU tags and sniffcraft records are big endian
    template <typename T>
    void AppendBigEndian(std::vector<unsigned char>& out, const T value)
    {
        const std::make_unsigned_t<T> unsigned_value = static_cast<std::make_unsigned_t<T>>(value);
        for (int i = sizeof(T) - 1; i >= 0; --i)
        {
            out.push_back(static_cast<unsigned char>((unsigned_value >> (8 * i)) & 0xFF));
        }
    }

    void PadTo4(std::vector<unsigned char>& out)
    {
        while (out.size() % 4 != 0)
        {
            out.push_back(0);
        }
    }

    void AppendOption(std::vector<unsigned char>& out, const uint16_t code, const std::string& value)
    {
        AppendHost<uint16_t>(out, code);
        AppendHost<uint16_t>(out, static_cast<uint16_t>(value.size()));
        out.insert(out.end(), value.begin(), value.end());
        PadTo4(out);
    }

    void AppendEndOfOptions(std::vector<unsigned char>& out)
    {
        AppendHost<uint16_t>(out, option_end_of_opt);
        AppendHost<uint16_t>(out, 0);
    }

    void AppendString16(std::vector<unsigned char>& out, const std::string& s)
    {
        const size_t size = std::min<size_t>(s.size(), std::numeric_limits<uint16_t>::max());
        AppendBigEndian<uint16_t>(out, static_cast<uint16_t>(size));
        out.insert(out.end(), s.begin(), s.begin() + size);
    }

    void AppendBytes32(std::vector<unsigned char>& out, const unsigned char* data, const size_t size)
    {
        AppendBigEndian<uint32_t>(out, static_cast<uint32_t>(size));
        out.insert(out.end(), data, data + size);
    }

    void AppendTimestamp(std::vector<unsigned char>& out, const std::chrono::system_clock::time_point& date)
    {
        // Default if_tsresol is microseconds
        const uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(date.time_since_epoch()).count());
        AppendHost<uint32_t>(out, static_cast<uint32_t>(timestamp >> 32));
        AppendHost<uint32_t>(out, static_cast<uint32_t>(timestamp & 0xFFFFFFFF));
    }

    bool IsOffsetWrapper(const Json::Value& value)
    {
        return value.is_object() &&
            value.size() == 3 &&
            value.contains("content") &&
            value.contains("start_offset") &&
            value.contains("end_offset");
    }

    /// @brief Convert detailed parsing offsets (bytes remaining until the end of the packet) to a byte range in the raw packet
    std::pair<uint32_t, uint32_t> GetRange(const Json::Value& value, const size_t raw_size)
    {
        if (!IsOffsetWrapper(value))
        {
            return { unknown_offset, unknown_offset };
        }
        const size_t start_remaining = value["start_offset"].get_number<size_t>();
        const size_t end_remaining = value["end_offset"].get_number<size_t>();
        if (start_remaining > raw_size || end_remaining > start_remaining)
        {
            return { unknown_offset, unknown_offset };
        }
        return { static_cast<uint32_t>(raw_size - start_remaining), static_cast<uint32_t>(raw_size - end_remaining) };
    }

    void Flatten(const Json::Value& value, const std::string& name, const uint16_t depth, const size_t raw_size, std::vector<PcapngField>& out);

    void FlattenObjectChildren(const Json::Object& object, const uint16_t depth, const size_t raw_size, std::vector<PcapngField>& out)
    {
        // Json objects are sorted by key, put them back in wire order when we know it
        std::vector<std::pair<const std::string*, const Json::Value*>> children;
        children.reserve(object.size());
        for (const auto& [k, v] : object)
        {
            children.push_back({ &k, &v });
        }
        std::stable_sort(children.begin(), children.end(), [raw_size](const auto& a, const auto& b) {
            return GetRange(*a.second, raw_size).first < GetRange(*b.second, raw_size).first;
        });
        for (const auto& [k, v] : children)
        {
            Flatten(*v, *k, depth, raw_size, out);
        }
    }

    void Flatten(const Json::Value& value, const std::string& name, const uint16_t depth, const size_t raw_size, std::vector<PcapngField>& out)
    {
        if (out.size() >= max_fields)
        {
            return;
        }

        const auto [start, end] = GetRange(value, raw_size);
        const Json::Value& content = IsOffsetWrapper(value) ? value["content"] : value;

        if (content.is_object())
        {
            out.push_back({ PcapngField::Kind::Object, depth, name, "", start, end });
            FlattenObjectChildren(content.get_object(), depth + 1, raw_size, out);
        }
        else if (content.is_array())
        {
            const Json::Array& array = content.get_array();
            out.push_back({ PcapngField::Kind::Array, depth, name, std::to_string(array.size()) + (array.size() == 1 ? " element" : " elements"), start, end });
            for (size_t i = 0; i < std::min(array.size(), max_array_elements); ++i)
            {
                Flatten(array[i], "[" + std::to_string(i) + "]", depth + 1, raw_size, out);
            }
            if (array.size() > max_array_elements && out.size() < max_fields)
            {
                out.push_back({ PcapngField::Kind::Truncated, static_cast<uint16_t>(depth + 1), "...", std::to_string(array.size() - max_array_elements) + " more", unknown_offset, unknown_offset });
            }
        }
        else
        {
            std::string str = content.is_string() ? content.get_string() : content.Dump();
            if (str.size() > max_value_size)
            {
                str = str.substr(0, max_value_size) + "...";
            }
            out.push_back({ PcapngField::Kind::Value, depth, name, std::move(str), start, end });
        }
    }
}

std::shared_ptr<PcapngWriter> PcapngWriter::shared_writer = nullptr;
std::mutex PcapngWriter::shared_writer_mutex;

PcapngWriter::PcapngWriter() : file(nullptr), failed(false)
{

}

PcapngWriter::~PcapngWriter()
{
    Close();
}

bool PcapngWriter::Open(const std::string& path)
{
    std::scoped_lock<std::mutex> lock(mutex);
    if (file != nullptr)
    {
        std::fclose(file);
    }
    failed = false;
    file = std::fopen(path.c_str(), "wb");
    if (file == nullptr)
    {
        failed = true;
        return false;
    }

    std::vector<unsigned char> shb;
    AppendHost<uint32_t>(shb, byte_order_magic);
    AppendHost<uint16_t>(shb, 1); // Major version
    AppendHost<uint16_t>(shb, 0); // Minor version
    AppendHost<int64_t>(shb, -1); // Unknown section length
    AppendOption(shb, option_shb_userappl, "SniffCraft");
    AppendEndOfOptions(shb);
    WriteBlock(block_type_shb, shb);

    std::vector<unsigned char> idb;
    AppendHost<uint16_t>(idb, linktype_wireshark_upper_pdu);
    AppendHost<uint16_t>(idb, 0); // Reserved
    AppendHost<uint32_t>(idb, 0); // No snap length
    AppendOption(idb, option_if_name, "sniffcraft");
    AppendOption(idb, option_if_description, "Minecraft protocol " + std::to_string(PROTOCOL_VERSION) + " (SniffCraft proxy)");
    AppendEndOfOptions(idb);
    WriteBlock(block_type_idb, idb);

    return !failed;
}

bool PcapngWriter::IsOpen() const
{
    std::scoped_lock<std::mutex> lock(mutex);
    return file != nullptr;
}

bool PcapngWriter::HasFailed() const
{
    return failed;
}

void PcapngWriter::Close()
{
    std::scoped_lock<std::mutex> lock(mutex);
    if (file != nullptr)
    {
        std::fclose(file);
        file = nullptr;
    }
}

void PcapngWriter::Write(const std::chrono::system_clock::time_point& date, const PcapngRecord& record)
{
    std::vector<unsigned char> data;

    // Exported PDU header, tells Wireshark which dissector to call
    AppendBigEndian<uint16_t>(data, exp_pdu_tag_dissector_name);
    const size_t padded_name_size = (dissector_name.size() + 1 + 3) & ~static_cast<size_t>(3);
    AppendBigEndian<uint16_t>(data, static_cast<uint16_t>(padded_name_size));
    data.insert(data.end(), dissector_name.begin(), dissector_name.end());
    data.resize(data.size() + padded_name_size - dissector_name.size(), 0);
    AppendBigEndian<uint16_t>(data, exp_pdu_tag_end_of_opt);
    AppendBigEndian<uint16_t>(data, 0);

    // SniffCraft record
    data.insert(data.end(), std::begin(record_magic), std::end(record_magic));
    data.push_back(record_format_version);
    data.push_back(record.origin);
    data.push_back(record.connection_state);
    const bool has_offsets = std::any_of(record.fields.begin(), record.fields.end(), [](const PcapngField& f) { return f.start != unknown_offset; });
    data.push_back((record.parse_error ? record_flag_parse_error : 0) | (has_offsets ? record_flag_has_offsets : 0));
    AppendBigEndian<uint32_t>(data, record.protocol_version);
    AppendBigEndian<uint32_t>(data, record.connection_id);
    AppendBigEndian<uint32_t>(data, record.wire_size);
    AppendBigEndian<int32_t>(data, record.packet_id);
    AppendString16(data, record.name);
    AppendBytes32(data, record.raw.data(), record.raw.size());
    AppendBigEndian<uint32_t>(data, static_cast<uint32_t>(record.fields.size()));
    for (const PcapngField& field : record.fields)
    {
        data.push_back(static_cast<uint8_t>(field.kind));
        AppendBigEndian<uint16_t>(data, field.depth);
        AppendString16(data, field.name);
        AppendBytes32(data, reinterpret_cast<const unsigned char*>(field.value.data()), field.value.size());
        AppendBigEndian<uint32_t>(data, field.start);
        AppendBigEndian<uint32_t>(data, field.end);
    }
    AppendBytes32(data, reinterpret_cast<const unsigned char*>(record.json.data()), record.json.size());

    std::vector<unsigned char> epb;
    epb.reserve(data.size() + 24);
    AppendHost<uint32_t>(epb, 0); // Interface id
    AppendTimestamp(epb, date);
    AppendHost<uint32_t>(epb, static_cast<uint32_t>(data.size())); // Captured length
    AppendHost<uint32_t>(epb, static_cast<uint32_t>(data.size())); // Original length
    epb.insert(epb.end(), data.begin(), data.end());
    PadTo4(epb);

    std::scoped_lock<std::mutex> lock(mutex);
    WriteBlock(block_type_epb, epb);
}

void PcapngWriter::WriteHeartbeat()
{
    std::vector<unsigned char> isb;
    AppendHost<uint32_t>(isb, 0); // Interface id
    AppendTimestamp(isb, std::chrono::system_clock::now());

    std::scoped_lock<std::mutex> lock(mutex);
    WriteBlock(block_type_isb, isb);
}

std::shared_ptr<PcapngWriter> PcapngWriter::GetShared()
{
    std::scoped_lock<std::mutex> lock(shared_writer_mutex);
    return shared_writer;
}

void PcapngWriter::SetShared(const std::shared_ptr<PcapngWriter>& writer)
{
    std::scoped_lock<std::mutex> lock(shared_writer_mutex);
    shared_writer = writer;
}

void PcapngWriter::WriteBlock(const uint32_t type, const std::vector<unsigned char>& body)
{
    if (file == nullptr || failed)
    {
        return;
    }

    const uint32_t total_length = static_cast<uint32_t>(body.size() + 12);
    std::vector<unsigned char> block;
    block.reserve(total_length);
    AppendHost<uint32_t>(block, type);
    AppendHost<uint32_t>(block, total_length);
    block.insert(block.end(), body.begin(), body.end());
    AppendHost<uint32_t>(block, total_length);

    if (std::fwrite(block.data(), 1, block.size(), file) != block.size() ||
        std::fflush(file) != 0)
    {
        failed = true;
    }
}

std::vector<PcapngField> PcapngFieldsFromJson(const Json::Value& json, const size_t raw_size)
{
    std::vector<PcapngField> output;
    const Json::Value& content = IsOffsetWrapper(json) ? json["content"] : json;
    if (content.is_object())
    {
        FlattenObjectChildren(content.get_object(), 0, raw_size, output);
    }
    else if (!content.is_null())
    {
        Flatten(json, "value", 0, raw_size, output);
    }
    return output;
}

Json::Value PcapngStripOffsets(const Json::Value& json)
{
    if (json.is_array())
    {
        Json::Array output;
        output.reserve(json.size());
        for (const auto& v : json.get_array())
        {
            output.push_back(PcapngStripOffsets(v));
        }
        return output;
    }
    if (json.is_object())
    {
        if (IsOffsetWrapper(json))
        {
            return PcapngStripOffsets(json["content"]);
        }
        Json::Object output;
        for (const auto& [k, v] : json.get_object())
        {
            output[k] = PcapngStripOffsets(v);
        }
        return output;
    }
    return json;
}
