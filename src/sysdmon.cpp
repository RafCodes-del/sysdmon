#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <cctype>
#include <unistd.h>

#include <libnotify/notify.h>

#ifdef HAS_SYSTEMD
#include <systemd/sd-journal.h>
#endif

bool use_notify = true;
int max_output_lines = -1;

void send_alert(const std::string& title, const std::string& message) {
    if (use_notify) {
        if (!notify_is_initted()) {
            notify_init("sysdmon");
        }
        NotifyNotification* n = notify_notification_new(title.c_str(), message.c_str(), nullptr);
        notify_notification_set_urgency(n, NOTIFY_URGENCY_CRITICAL);
        notify_notification_set_timeout(n, 5000);
        notify_notification_show(n, nullptr);
        g_object_unref(G_OBJECT(n));
    } else {
        std::cout << "[" << title << "] " << message << std::endl;
    }
}

bool file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

std::string to_lower(const std::string& input) {
    std::string output = input;
    for (auto& c : output) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return output;
}

bool should_output_line(int& count) {
    if (max_output_lines < 0) return true;
    if (count >= max_output_lines) return false;
    ++count;
    return true;
}

void analyze_syslog(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Failed to open syslog file: " << path << std::endl;
        return;
    }

    std::string line;
    int printed_lines = 0;
    while (std::getline(file, line)) {
        std::string lower_line = to_lower(line);
        if (lower_line.find("error") != std::string::npos ||
            lower_line.find("fail") != std::string::npos ||
            lower_line.find("critical") != std::string::npos) {
            if (should_output_line(printed_lines))
                send_alert("Syslog Analyze", line);
            else break;
        }
    }

    std::cout << "Syslog analysis complete.\n";
}

#ifdef HAS_SYSTEMD
void analyze_journal() {
    sd_journal* journal = nullptr;
    int r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        std::cerr << "Failed to open journal: " << strerror(-r) << std::endl;
        return;
    }

    sd_journal_seek_head(journal);
    std::cout << "Analyzing systemd journal...\n";

    int printed_lines = 0;
    while (sd_journal_next(journal) > 0) {
        const void* data;
        size_t length;

        r = sd_journal_get_data(journal, "PRIORITY", &data, &length);
        if (r < 0) continue;

        std::string priority_str(static_cast<const char*>(data), length);
        if (priority_str.empty()) continue;

        int priority = priority_str.back() - '0';
        if (priority > 3) continue;

        r = sd_journal_get_data(journal, "MESSAGE", &data, &length);
        if (r < 0) continue;

        std::string message(static_cast<const char*>(data) + 8, length - 8);

        std::string unit = "";
        if (sd_journal_get_data(journal, "_SYSTEMD_UNIT", &data, &length) >= 0) {
            unit = std::string(static_cast<const char*>(data) + 13, length - 13);
        }

        std::string alert_title = "Journal Analyze";
        if (!unit.empty()) alert_title += " - " + unit;

        if (!should_output_line(printed_lines)) break;

        send_alert(alert_title, message);
    }

    sd_journal_close(journal);
    std::cout << "Journal analysis complete.\n";
}
#endif

void monitor_syslog(const std::string& path) {
    std::ifstream file(path, std::ios::in);
    if (!file.is_open()) {
        std::cerr << "Failed to open syslog file: " << path << std::endl;
        return;
    }

    file.seekg(0, std::ios::end);

    std::string line;
    std::cout << "Monitoring syslog at " << path << " for errors...\n";

    while (true) {
        while (std::getline(file, line)) {
            std::string lower_line = to_lower(line);
            if (lower_line.find("error") != std::string::npos ||
                lower_line.find("fail") != std::string::npos ||
                lower_line.find("critical") != std::string::npos) {
                send_alert("Syslog Alert", line);
            }
        }
        if (file.eof()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            file.clear();
        } else {
            std::cerr << "Error reading syslog file\n";
            break;
        }
    }
}

#ifdef HAS_SYSTEMD
void monitor_journal() {
    sd_journal* journal = nullptr;
    int r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        std::cerr << "Failed to open journal: " << strerror(-r) << std::endl;
        return;
    }

    sd_journal_seek_tail(journal);
    std::cout << "Monitoring systemd journal for errors...\n";

    while (true) {
        r = sd_journal_wait(journal, 5000000);
        if (r < 0) {
            std::cerr << "sd_journal_wait error: " << strerror(-r) << std::endl;
            break;
        }
        if (r == 0) continue;

        while (sd_journal_next(journal) > 0) {
            const void* data;
            size_t length;

            r = sd_journal_get_data(journal, "PRIORITY", &data, &length);
            if (r < 0) continue;

            std::string priority_str(static_cast<const char*>(data), length);
            if (priority_str.empty()) continue;

            int priority = priority_str.back() - '0';
            if (priority > 3) continue;

            r = sd_journal_get_data(journal, "MESSAGE", &data, &length);
            if (r < 0) continue;

            std::string message(static_cast<const char*>(data) + 8, length - 8);

            std::string unit = "";
            if (sd_journal_get_data(journal, "_SYSTEMD_UNIT", &data, &length) >= 0) {
                unit = std::string(static_cast<const char*>(data) + 13, length - 13);
            }

            std::string alert_title = "Journal Alert";
            if (!unit.empty()) alert_title += " - " + unit;

            send_alert(alert_title, message);
        }
    }

    sd_journal_close(journal);
}

bool check_systemd_available() {
    sd_journal* journal = nullptr;
    int r = sd_journal_open(&journal, SD_JOURNAL_LOCAL_ONLY);
    if (r >= 0) {
        sd_journal_close(journal);
        return true;
    }
    return false;
}
#else
bool check_systemd_available() {
    return (system("command -v journalctl > /dev/null 2>&1") == 0);
}
#endif

enum class LogSource {
    SYSTEMD_JOURNAL,
    SYSLOG_FILE,
    JOURNALCTL_CMD,
    NONE
};

struct LogTarget {
    LogSource source;
    std::string path_or_cmd;
};

LogTarget detect_log_source() {
    if (check_systemd_available()) {
#ifdef HAS_SYSTEMD
        return {LogSource::SYSTEMD_JOURNAL, ""};
#else
        return {LogSource::JOURNALCTL_CMD, "journalctl -f -o short-monotonic"};
#endif
    }

    std::vector<std::string> candidates = {
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/user.log"
    };

    for (const auto& path : candidates) {
        if (file_exists(path)) {
            return {LogSource::SYSLOG_FILE, path};
        }
    }

    return {LogSource::NONE, ""};
}

void print_help() {
    std::cout <<
        "sysdmon usage:\n"
        "  -A, --analyze            Analyze log file once and exit\n"
        "  -M, --monitor            Monitor logs live (default)\n"
        "  -Km, --kill-all-monitors Kill all running sysdmon processes\n"
        "  --start-cmd              Output alerts to console instead of notifications\n"
        "  -T, --top                Limit output to first 10 alerts in analyze mode\n"
        "  -h, --help               Show this help message\n";
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }
    }

    const char* user_env = getenv("USER");
    std::string username = user_env ? user_env : "User";
    std::cout << "Good day, " << username << "." << std::endl;
    std::cout << "sysdmon v1.0 - SystemD Journal and Syslog Monitor & Analyzer" << std::endl;
    std::cout << "Monitoring your system logs for critical issues and alerting you promptly." << std::endl << std::endl;

    bool analyze_mode = false;
    bool monitor_mode = true;
    bool kill_monitors = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-A" || arg == "--analyze") {
            analyze_mode = true;
            monitor_mode = false;
        } else if (arg == "-M" || arg == "--monitor") {
            analyze_mode = false;
            monitor_mode = true;
        } else if (arg == "-Km" || arg == "--kill-all-monitors") {
            kill_monitors = true;
        } else if (arg == "--start-cmd") {
            use_notify = false;
        } else if (arg == "-T" || arg == "--top") {
            max_output_lines = 10;
        } else if (arg != "-h" && arg != "--help") {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_help();
            return 1;
        }
    }

    if (kill_monitors) {
        std::cout << "Killing all running sysdmon processes...\n";
        int ret = system("pkill -f sysdmon");
        if (ret != 0) {
            std::cerr << "No running sysdmon processes found or failed to kill.\n";
        }
        return 0;
    }

    LogTarget target = detect_log_source();

    if (target.source == LogSource::NONE) {
        std::cerr << "No supported log sources found for monitoring or analysis.\n";
        return 1;
    }

    if (analyze_mode) {
        switch (target.source) {
            case LogSource::SYSTEMD_JOURNAL:
#ifdef HAS_SYSTEMD
                analyze_journal();
#else
                std::cout << "Analyzing logs via journalctl command...\n";
                system("journalctl -n 100 --no-pager");
#endif
                break;
            case LogSource::SYSLOG_FILE:
                analyze_syslog(target.path_or_cmd);
                break;
            case LogSource::JOURNALCTL_CMD:
                std::cout << "Analyzing logs via journalctl command...\n";
                system("journalctl -n 100 --no-pager");
                break;
            default:
                std::cerr << "No supported log sources found for analysis.\n";
                return 1;
        }
        return 0;
    }

    if (monitor_mode) {
        switch (target.source) {
            case LogSource::SYSTEMD_JOURNAL:
#ifdef HAS_SYSTEMD
                monitor_journal();
#else
                std::cout << "Monitoring logs via journalctl command...\n";
                system("journalctl -f");
#endif
                break;
            case LogSource::SYSLOG_FILE:
                monitor_syslog(target.path_or_cmd);
                break;
            case LogSource::JOURNALCTL_CMD:
                std::cout << "Monitoring logs via journalctl command...\n";
                system("journalctl -f");
                break;
            default:
                std::cerr << "No supported log sources found for monitoring.\n";
                return 1;
        }
        return 0;
    }

    print_help();
    return 0;
}
