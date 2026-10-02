#include "sniffcraft/conf.hpp"
#include "sniffcraft/Extcap.hpp"
#include "sniffcraft/PcapngWriter.hpp"
#include "sniffcraft/server.hpp"

#ifdef USE_ENCRYPTION
#include <botcraft/Network/Authentifier.hpp>
#endif

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef SNIFFCRAFT_GAME_VERSION
#define SNIFFCRAFT_GAME_VERSION "unknown"
#endif

namespace Extcap
{
    namespace
    {
        constexpr std::string_view interface_value = "sniffcraft";
        constexpr std::string_view help_url = "https://github.com/dioxtra/SniffCraft";
        constexpr int dlt_wireshark_upper_pdu = 252;

        struct Options
        {
            bool list_interfaces = false;
            bool list_dlts = false;
            bool list_config = false;
            bool capture = false;
            bool login = false;
            std::string extcap_interface;
            std::string fifo;
            std::string server_address = "127.0.0.1:25565";
            int local_port = 25555;
            bool online = false;
            std::string account_cache_key;
            std::string conf_path;
            bool include_json = false;
            bool respect_filters = false;
            bool file_logs = false;
        };

        Options ParseArgs(const int argc, char* argv[])
        {
            Options options;
            for (int i = 1; i < argc; ++i)
            {
                std::string arg = argv[i];
                std::optional<std::string> inline_value;
                const size_t equal_pos = arg.find('=');
                if (arg.rfind("--", 0) == 0 && equal_pos != std::string::npos)
                {
                    inline_value = arg.substr(equal_pos + 1);
                    arg = arg.substr(0, equal_pos);
                }
                // Options can be given as --opt=value or --opt value
                const auto value = [&]() -> std::string {
                    if (inline_value.has_value())
                    {
                        return inline_value.value();
                    }
                    return i + 1 < argc ? argv[++i] : "";
                };

                if (arg == "--extcap-interfaces")
                {
                    options.list_interfaces = true;
                }
                else if (arg == "--extcap-dlts")
                {
                    options.list_dlts = true;
                }
                else if (arg == "--extcap-config")
                {
                    options.list_config = true;
                }
                else if (arg == "--capture")
                {
                    options.capture = true;
                }
                else if (arg == "--extcap-login")
                {
                    options.login = true;
                }
                else if (arg == "--extcap-interface")
                {
                    options.extcap_interface = value();
                }
                else if (arg == "--fifo")
                {
                    options.fifo = value();
                }
                else if (arg == "--server")
                {
                    options.server_address = value();
                }
                else if (arg == "--port")
                {
                    try
                    {
                        options.local_port = std::stoi(value());
                    }
                    catch (const std::exception&)
                    {
                        std::cerr << "Invalid --port value, using " << options.local_port << std::endl;
                    }
                }
                else if (arg == "--online")
                {
                    options.online = true;
                }
                else if (arg == "--account-cache-key")
                {
                    options.account_cache_key = value();
                }
                else if (arg == "--conf")
                {
                    options.conf_path = value();
                }
                else if (arg == "--json")
                {
                    options.include_json = true;
                }
                else if (arg == "--respect-filters")
                {
                    options.respect_filters = true;
                }
                else if (arg == "--file-logs")
                {
                    options.file_logs = true;
                }
                // Options we don't use but that come with a value
                else if (arg == "--extcap-capture-filter" ||
                    arg == "--extcap-control-in" ||
                    arg == "--extcap-control-out" ||
                    arg == "--extcap-version" ||
                    arg == "--extcap-reload-option")
                {
                    if (!inline_value.has_value() && arg != "--extcap-version")
                    {
                        value();
                    }
                }
            }
            return options;
        }

        std::filesystem::path GetExecutableDirectory(const char* argv0)
        {
#ifdef _WIN32
            wchar_t buffer[MAX_PATH];
            const DWORD size = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
            if (size > 0 && size < MAX_PATH)
            {
                return std::filesystem::path(std::wstring(buffer, size)).parent_path();
            }
#else
            std::error_code ec;
            const std::filesystem::path exe_path = std::filesystem::read_symlink("/proc/self/exe", ec);
            if (!ec)
            {
                return exe_path.parent_path();
            }
#endif
            return std::filesystem::absolute(argv0).parent_path();
        }

        void PrintInterfaces()
        {
            std::cout
                << "extcap {version=1.0}{help=" << help_url << "}\n"
                << "interface {value=" << interface_value << "}{display=SniffCraft Minecraft proxy (MC " << SNIFFCRAFT_GAME_VERSION << ")}\n";
        }

        void PrintDlts()
        {
            std::cout << "dlt {number=" << dlt_wireshark_upper_pdu << "}{name=WIRESHARK_UPPER_PDU}{display=Minecraft packets (SniffCraft)}\n";
        }

        void PrintConfig()
        {
            std::cout
                << "arg {number=0}{call=--server}{display=Minecraft server}{type=string}{default=127.0.0.1:25565}"
                    "{tooltip=Server SniffCraft connects to (address or address:port, SRV records are resolved)}{required=true}{group=Proxy}\n"
                << "arg {number=1}{call=--port}{display=Local proxy port}{type=unsigned}{default=25555}{range=1,65535}"
                    "{tooltip=Connect your Minecraft client to localhost on this port}{group=Proxy}\n"
                << "arg {number=2}{call=--online}{display=Online mode (Microsoft account)}{type=boolflag}{default=false}"
                    "{tooltip=Needed for online-mode servers. Log in once with: sniffcraft --extcap-login}{group=Proxy}\n"
                << "arg {number=3}{call=--account-cache-key}{display=Microsoft account cache key}{type=string}{default=}"
                    "{tooltip=Only needed if you logged in with several Microsoft accounts}{group=Proxy}\n"
                << "arg {number=4}{call=--json}{display=Include ProtocolCraft JSON}{type=boolflag}{default=false}"
                    "{tooltip=Also store the full json of each packet (bigger captures, enables json.* filters)}{group=Capture}\n"
                << "arg {number=5}{call=--respect-filters}{display=Apply conf ignore lists}{type=boolflag}{default=false}"
                    "{tooltip=Don't send packets ignored in the SniffCraft conf file}{group=Capture}\n"
                << "arg {number=6}{call=--conf}{display=SniffCraft conf file}{type=fileselect}{mustexist=true}"
                    "{tooltip=Optional, defaults to conf.json next to the extcap}{group=Capture}\n"
                << "arg {number=7}{call=--file-logs}{display=Also write SniffCraft log files}{type=boolflag}{default=false}"
                    "{tooltip=Keep the txt/bin/replay logs configured in the conf file}{group=Capture}\n";
        }

        int Login(const Options& options, const std::filesystem::path& working_dir)
        {
#ifdef USE_ENCRYPTION
            // The credentials cache is written in the working directory, where captures will look for it
            std::filesystem::current_path(working_dir);
            Botcraft::Authentifier authentifier;
            if (!authentifier.AuthMicrosoft(options.account_cache_key))
            {
                std::cerr << "Error trying to authenticate with Microsoft account" << std::endl;
                return 1;
            }
            std::cout << "Logged in, online mode captures can now be started from Wireshark" << std::endl;
            return 0;
#else
            std::cerr << "This version of SniffCraft was built without encryption support" << std::endl;
            return 1;
#endif
        }

        int Capture(const Options& options, const std::filesystem::path& working_dir)
        {
            if (options.fifo.empty())
            {
                std::cerr << "Missing --fifo argument" << std::endl;
                return 1;
            }

            // Conf, logs and cached credentials all live next to the extcap
            std::filesystem::current_path(working_dir);

            if (options.online && !std::filesystem::exists(working_dir / "botcraft_cached_credentials.json"))
            {
                std::cerr << "Online mode needs a Microsoft login, run this once in a terminal:\n\""
                    << (working_dir / "sniffcraft").string() << "\" --extcap-login" << std::endl;
                return 1;
            }

            // Nobody reads our stdout during a capture, keep SniffCraft output in a file
            std::ofstream output_log(working_dir / "sniffcraft_extcap.log", std::ios::out);
            std::cout.rdbuf(output_log.rdbuf());

            Conf::headless = true;
            Conf::conf_path = options.conf_path.empty() ? (working_dir / "conf.json").string() : options.conf_path;
            ProtocolCraft::Json::Value overrides = {
                { Conf::server_address_key, options.server_address },
                { Conf::local_port_key, options.local_port },
                { Conf::online_key, options.online },
                { Conf::console_log_key, false },
                { Conf::network_recap_to_console_key, false },
                { Conf::pcapng_log_key, true },
                { Conf::pcapng_json_key, options.include_json },
                { Conf::pcapng_respect_filters_key, options.respect_filters }
            };
            if (!options.file_logs)
            {
                overrides[Conf::text_file_log_key] = false;
                overrides[Conf::binary_file_log_key] = false;
                overrides[Conf::replay_log_key] = false;
            }
            if (!options.account_cache_key.empty())
            {
                overrides[Conf::account_cache_key_key] = options.account_cache_key;
            }
            Conf::overrides = overrides;

            std::shared_ptr<PcapngWriter> writer = std::make_shared<PcapngWriter>();
            if (!writer->Open(options.fifo))
            {
                std::cerr << "Error trying to open capture pipe " << options.fifo << std::endl;
                return 1;
            }
            PcapngWriter::SetShared(writer);

            std::atomic<bool> server_stopped = false;
            std::thread server_thread([&server_stopped]() {
                try
                {
                    Server server = Server();
                    server.run();
                }
                catch (const std::exception& e)
                {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
                server_stopped = true;
            });
            server_thread.detach();

            // Wireshark closes the pipe when the capture is stopped,
            // writing regularly is the only way to notice it when there is no traffic
            while (!server_stopped && !writer->HasFailed())
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                writer->WriteHeartbeat();
            }

            writer->Close();
            std::cout.flush();
            std::cerr.flush();
            output_log.flush();
            // Proxies are blocked in asio calls, there is no clean way to stop them from here
            std::_Exit(server_stopped ? 1 : 0);
        }
    }

    bool IsExtcapCall(const int argc, char* argv[])
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string_view arg = argv[i];
            if (arg.rfind("--extcap-", 0) == 0 || arg == "--capture")
            {
                return true;
            }
        }
        return false;
    }

    int Run(const int argc, char* argv[])
    {
        const Options options = ParseArgs(argc, argv);
        const std::filesystem::path working_dir = GetExecutableDirectory(argv[0]);

        if (options.login)
        {
            return Login(options, working_dir);
        }
        if (options.list_interfaces)
        {
            PrintInterfaces();
            return 0;
        }
        if (!options.extcap_interface.empty() && options.extcap_interface != interface_value)
        {
            std::cerr << "Unknown interface: " << options.extcap_interface << std::endl;
            return 1;
        }
        if (options.list_dlts)
        {
            PrintDlts();
            return 0;
        }
        if (options.list_config)
        {
            PrintConfig();
            return 0;
        }
        if (options.capture)
        {
            return Capture(options, working_dir);
        }

        std::cerr << "Unknown extcap call" << std::endl;
        return 1;
    }
}
