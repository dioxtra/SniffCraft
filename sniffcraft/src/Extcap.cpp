#include "sniffcraft/conf.hpp"
#include "sniffcraft/Extcap.hpp"
#include "sniffcraft/PcapngWriter.hpp"
#include "sniffcraft/server.hpp"

#ifdef USE_ENCRYPTION
#include <botcraft/Network/Authentifier.hpp>
#endif

#include <algorithm>
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
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifndef SNIFFCRAFT_GAME_VERSION
#define SNIFFCRAFT_GAME_VERSION "unknown"
#endif
#ifndef SNIFFCRAFT_VERSION_TABLE
#define SNIFFCRAFT_VERSION_TABLE ""
#endif

namespace Extcap
{
    namespace
    {
        constexpr std::string_view interface_value = "sniffcraft";
        constexpr std::string_view help_url = "https://github.com/dioxtra/SniffCraft-Wireshark";
        constexpr int dlt_wireshark_upper_pdu = 252;
        /// @brief Folder next to the extcap with SniffCraft builds for other game versions (sniffcraft-<version>[.exe])
        constexpr std::string_view versions_folder = "sniffcraft_versions";
        constexpr std::string_view versions_prefix = "sniffcraft-";

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
            bool allow_remote = false;
            std::string account_cache_key;
            std::string conf_path;
            bool include_json = false;
            bool respect_filters = false;
            bool file_logs = false;
            std::string mc_version;
            /// @brief Set when started by the SniffCraft build of another game version
            std::string workdir;
        };

        struct InstalledVersion
        {
            std::string game_version;
            int protocol_version;
            /// @brief Empty for the current executable
            std::filesystem::path executable;
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
                else if (arg == "--allow-remote")
                {
                    options.allow_remote = true;
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
                else if (arg == "--mc-version")
                {
                    options.mc_version = value();
                }
                else if (arg == "--extcap-workdir")
                {
                    options.workdir = value();
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

        /// @brief Game version -> protocol version for all the versions SniffCraft supports, oldest first
        std::vector<std::pair<std::string, int>> GetVersionTable()
        {
            std::vector<std::pair<std::string, int>> table;
            std::string_view remaining = SNIFFCRAFT_VERSION_TABLE;
            while (!remaining.empty())
            {
                const size_t comma = remaining.find(',');
                const std::string_view entry = remaining.substr(0, comma);
                const size_t equal = entry.find('=');
                if (equal != std::string_view::npos)
                {
                    table.push_back({ std::string(entry.substr(0, equal)), std::stoi(std::string(entry.substr(equal + 1))) });
                }
                if (comma == std::string_view::npos)
                {
                    break;
                }
                remaining.remove_prefix(comma + 1);
            }
            return table;
        }

        /// @brief Game versions this executable and the ones in versions_folder can capture, newest first
        std::vector<InstalledVersion> GetInstalledVersions(const std::filesystem::path& extcap_dir)
        {
            const std::vector<std::pair<std::string, int>> table = GetVersionTable();
            std::vector<InstalledVersion> versions = { { SNIFFCRAFT_GAME_VERSION, PROTOCOL_VERSION, {} } };

            std::error_code ec;
            for (const auto& entry : std::filesystem::directory_iterator(extcap_dir / versions_folder, ec))
            {
                // Not path::stem(), sniffcraft-1.21.10 has no extension outside of Windows
                std::string name = entry.path().filename().string();
                if (name.size() > 4 && name.compare(name.size() - 4, 4, ".exe") == 0)
                {
                    name.resize(name.size() - 4);
                }
                if (!entry.is_regular_file() || name.rfind(versions_prefix, 0) != 0)
                {
                    continue;
                }
                const std::string game_version = name.substr(versions_prefix.size());
                const auto it = std::find_if(table.begin(), table.end(), [&](const auto& p) { return p.first == game_version; });
                // A single build is enough for all the game versions sharing a protocol version
                if (it != table.end() &&
                    std::none_of(versions.begin(), versions.end(), [&](const InstalledVersion& v) { return v.protocol_version == it->second; }))
                {
                    versions.push_back({ game_version, it->second, entry.path() });
                }
            }

            std::sort(versions.begin(), versions.end(), [](const InstalledVersion& a, const InstalledVersion& b) {
                return a.protocol_version > b.protocol_version;
            });
            return versions;
        }

        /// @brief "1.21.9 - 1.21.10" for all the game versions using this protocol version
        std::string GetGameVersionRange(const int protocol_version)
        {
            std::vector<std::string> game_versions;
            for (const auto& [game_version, protocol] : GetVersionTable())
            {
                if (protocol == protocol_version)
                {
                    game_versions.push_back(game_version);
                }
            }
            if (game_versions.empty())
            {
                return "?";
            }
            return game_versions.size() == 1 ? game_versions.front() : game_versions.front() + " - " + game_versions.back();
        }

#ifdef _WIN32
        /// @brief Quote an argument following CommandLineToArgvW rules
        std::wstring QuoteArgument(const std::wstring& arg)
        {
            if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos)
            {
                return arg;
            }
            std::wstring quoted = L"\"";
            size_t backslashes = 0;
            for (const wchar_t c : arg)
            {
                if (c == L'\\')
                {
                    backslashes += 1;
                    continue;
                }
                quoted.append(c == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
                backslashes = 0;
                quoted.push_back(c);
            }
            quoted.append(backslashes * 2, L'\\');
            quoted.push_back(L'"');
            return quoted;
        }

        std::wstring ToWide(const std::string& s)
        {
            const int size = MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
            std::wstring output(size, L'\0');
            MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), output.data(), size);
            return output;
        }
#endif

        /// @brief Run the capture with the SniffCraft build of another game version
        /// @return Exit code of the other build
        int RunOtherVersion(const std::filesystem::path& executable, const int argc, char* argv[], const std::filesystem::path& working_dir)
        {
            // Same arguments, the other build shares our conf, logs and credentials folder
            std::vector<std::string> args;
            for (int i = 1; i < argc; ++i)
            {
                const std::string_view arg = argv[i];
                if (arg == "--mc-version")
                {
                    i += 1;
                    continue;
                }
                if (arg.rfind("--mc-version=", 0) == 0)
                {
                    continue;
                }
                args.push_back(argv[i]);
            }
            args.push_back("--extcap-workdir=" + working_dir.string());

#ifdef _WIN32
            std::wstring command_line = QuoteArgument(executable.wstring());
            for (const std::string& arg : args)
            {
                command_line += L" " + QuoteArgument(ToWide(arg));
            }

            STARTUPINFOW startup_info{};
            startup_info.cb = sizeof(startup_info);
            startup_info.dwFlags = STARTF_USESTDHANDLES;
            startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
            for (const HANDLE handle : { startup_info.hStdInput, startup_info.hStdOutput, startup_info.hStdError })
            {
                if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
                {
                    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
                }
            }

            // Wireshark kills this process when the capture stops, the job makes sure the other build goes with it
            const HANDLE job = CreateJobObjectW(nullptr, nullptr);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));

            PROCESS_INFORMATION process_info{};
            if (!CreateProcessW(executable.wstring().c_str(), command_line.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &startup_info, &process_info))
            {
                std::cerr << "Error trying to start " << executable.string() << " (error " << GetLastError() << ")" << std::endl;
                CloseHandle(job);
                return 1;
            }
            AssignProcessToJobObject(job, process_info.hProcess);
            ResumeThread(process_info.hThread);
            WaitForSingleObject(process_info.hProcess, INFINITE);

            DWORD exit_code = 1;
            GetExitCodeProcess(process_info.hProcess, &exit_code);
            CloseHandle(process_info.hThread);
            CloseHandle(process_info.hProcess);
            CloseHandle(job);
            return static_cast<int>(exit_code);
#else
            const std::string executable_str = executable.string();
            std::vector<char*> exec_args = { const_cast<char*>(executable_str.c_str()) };
            for (std::string& arg : args)
            {
                exec_args.push_back(arg.data());
            }
            exec_args.push_back(nullptr);
            execv(executable_str.c_str(), exec_args.data());
            std::cerr << "Error trying to start " << executable_str << std::endl;
            return 1;
#endif
        }

        void PrintInterfaces()
        {
            std::cout
                << "extcap {version=1.0}{help=" << help_url << "}\n"
                << "interface {value=" << interface_value << "}{display=SniffCraft Minecraft proxy}\n";
        }

        void PrintDlts()
        {
            std::cout << "dlt {number=" << dlt_wireshark_upper_pdu << "}{name=WIRESHARK_UPPER_PDU}{display=Minecraft packets (SniffCraft)}\n";
        }

        void PrintConfig(const std::filesystem::path& extcap_dir)
        {
            std::cout
                << "arg {number=0}{call=--mc-version}{display=Minecraft version}{type=selector}"
                    "{tooltip=Version of your Minecraft client}{group=Proxy}\n";
            for (const InstalledVersion& version : GetInstalledVersions(extcap_dir))
            {
                // This executable version is the default, it doesn't need to start another one
                std::cout << "value {arg=0}{value=" << version.game_version << "}{display=" << GetGameVersionRange(version.protocol_version)
                    << " (protocol " << version.protocol_version << ")}{default=" << (version.executable.empty() ? "true" : "false") << "}\n";
            }
            std::cout
                << "arg {number=1}{call=--server}{display=Minecraft server}{type=string}{default=127.0.0.1:25565}"
                    "{tooltip=Server SniffCraft connects to (address or address:port, SRV records are resolved)}{required=true}{group=Proxy}\n"
                << "arg {number=2}{call=--port}{display=Local proxy port}{type=unsigned}{default=25555}{range=1,65535}"
                    "{tooltip=Connect your Minecraft client to localhost on this port}{group=Proxy}\n"
                << "arg {number=3}{call=--online}{display=Online mode (Microsoft account)}{type=boolflag}{default=false}"
                    "{tooltip=Needed for online-mode servers. Log in once with: sniffcraft --extcap-login}{group=Proxy}\n"
                << "arg {number=4}{call=--account-cache-key}{display=Microsoft account cache key}{type=string}{default=}"
                    "{tooltip=Only needed if you logged in with several Microsoft accounts}{group=Proxy}\n"
                << "arg {number=5}{call=--json}{display=Include ProtocolCraft JSON}{type=boolflag}{default=false}"
                    "{tooltip=Also store the full json of each packet (bigger captures, enables json.* filters)}{group=Capture}\n"
                << "arg {number=6}{call=--respect-filters}{display=Apply conf ignore lists}{type=boolflag}{default=false}"
                    "{tooltip=Don't send packets ignored in the SniffCraft conf file}{group=Capture}\n"
                << "arg {number=7}{call=--conf}{display=SniffCraft conf file}{type=fileselect}{mustexist=true}"
                    "{tooltip=Optional, defaults to conf.json next to the extcap}{group=Capture}\n"
                << "arg {number=8}{call=--file-logs}{display=Also write SniffCraft log files}{type=boolflag}{default=false}"
                    "{tooltip=Keep the txt/bin/replay logs configured in the conf file}{group=Capture}\n"
                << "arg {number=9}{call=--allow-remote}{display=Allow connections from other devices}{type=boolflag}{default=false}"
                    "{tooltip=Listen on all network interfaces instead of localhost only. In online mode, anyone who can reach this port "
                    "joins the server with your Microsoft account}{group=Proxy}\n";
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
                { Conf::local_address_key, options.allow_remote ? "0.0.0.0" : "127.0.0.1" },
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
        const std::filesystem::path extcap_dir = GetExecutableDirectory(argv[0]);
        const std::filesystem::path working_dir = options.workdir.empty() ? extcap_dir : std::filesystem::path(options.workdir);

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
            PrintConfig(extcap_dir);
            return 0;
        }
        if (options.capture)
        {
            if (!options.mc_version.empty() && options.mc_version != SNIFFCRAFT_GAME_VERSION)
            {
                for (const InstalledVersion& version : GetInstalledVersions(extcap_dir))
                {
                    if (version.game_version == options.mc_version)
                    {
                        return version.executable.empty() ? Capture(options, working_dir) : RunOtherVersion(version.executable, argc, argv, working_dir);
                    }
                }
                std::cerr << "SniffCraft for Minecraft " << options.mc_version << " is not installed in " << (extcap_dir / versions_folder).string() << std::endl;
                return 1;
            }
            return Capture(options, working_dir);
        }

        std::cerr << "Unknown extcap call" << std::endl;
        return 1;
    }
}
