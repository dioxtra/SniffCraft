#pragma once

/// @brief Wireshark extcap interface. When SniffCraft is placed in Wireshark extcap folder,
/// it shows up as a capture interface that runs the proxy and streams the packets to Wireshark.
/// See https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
namespace Extcap
{
    /// @brief Check if the program was called by Wireshark as an extcap
    bool IsExtcapCall(const int argc, char* argv[]);

    /// @brief Answer Wireshark extcap queries or run a capture
    /// @return Process exit code
    int Run(const int argc, char* argv[]);
}
