// SPDX-License-Identifier: MIT
// cpp-snmp-watch — Linux SNMP / netstat protocol counter monitor
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o snmp-watch
// Usage: ./snmp-watch [--watch N] [--json] [--demo] [--no-color] [--selftest]
//        [--section NAME] [--nonzero] [--alerts] [--file PATH]

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <expected>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

struct Counter {
  std::string proto;
  std::string name;
  long long value{0};
  long long delta{0};
  double rate{0.0};
  bool gauge{false};
  bool alert{false};
};

struct Snapshot {
  std::vector<Counter> counters;
  double timestamp{0.0};
  bool has_delta{false};
  long long ip_in{0};
  long long ip_out{0};
  long long tcp_estab{0};
  long long tcp_in{0};
  long long tcp_out{0};
  long long tcp_retrans{0};
  long long udp_in{0};
  long long udp_out{0};
  long long udp_noport{0};
  long long icmp_in{0};
  long long icmp_out{0};
  long long in_octets{0};
  long long out_octets{0};
  long long listen_drops{0};
  long long tcp_timeouts{0};
  int sections{0};
  int alerts{0};
};

bool g_color = true;
std::string C_RST, C_BOLD, C_DIM, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_MAGENTA, C_BLUE;

void init_colors() {
  C_RST = g_color ? "\033[0m" : "";
  C_BOLD = g_color ? "\033[1m" : "";
  C_DIM = g_color ? "\033[2m" : "";
  C_CYAN = g_color ? "\033[36m" : "";
  C_GREEN = g_color ? "\033[32m" : "";
  C_YELLOW = g_color ? "\033[33m" : "";
  C_RED = g_color ? "\033[31m" : "";
  C_MAGENTA = g_color ? "\033[35m" : "";
  C_BLUE = g_color ? "\033[34m" : "";
}

static double now_epoch() {
  using namespace std::chrono;
  return duration<double>(system_clock::now().time_since_epoch()).count();
}

static std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
    s.remove_suffix(1);
  return std::string(s);
}

static long long parse_ll(std::string_view s) {
  long long v = 0;
  auto start = s.find_first_not_of(" \t");
  if (start == std::string_view::npos) return 0;
  s.remove_prefix(start);
  auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  (void)ptr;
  if (ec != std::errc{}) return 0;
  return v;
}

static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) {
    switch (c) {
      case '\\': o += "\\\\"; break;
      case '"': o += "\\\""; break;
      case '\n': o += "\\n"; break;
      case '\t': o += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
        break;
    }
  }
  return o;
}

static std::string fmt_signed(long long v) {
  char buf[32];
  if (v > 0) std::snprintf(buf, sizeof(buf), "+%lld", v);
  else std::snprintf(buf, sizeof(buf), "%lld", v);
  return buf;
}

static std::string fmt_rate(double r) {
  char buf[32];
  if (r >= 1000000.0) std::snprintf(buf, sizeof(buf), "%.2fM/s", r / 1000000.0);
  else if (r >= 1000.0) std::snprintf(buf, sizeof(buf), "%.1fk/s", r / 1000.0);
  else if (r >= 10.0) std::snprintf(buf, sizeof(buf), "%.1f/s", r);
  else std::snprintf(buf, sizeof(buf), "%.2f/s", r);
  return buf;
}

static std::string fmt_num(long long v) {
  char buf[48];
  if (v >= 1000000000LL) std::snprintf(buf, sizeof(buf), "%.2fG", static_cast<double>(v) / 1e9);
  else if (v >= 1000000LL) std::snprintf(buf, sizeof(buf), "%.2fM", static_cast<double>(v) / 1e6);
  else if (v >= 10000LL) std::snprintf(buf, sizeof(buf), "%.1fk", static_cast<double>(v) / 1e3);
  else std::snprintf(buf, sizeof(buf), "%lld", v);
  return buf;
}

static std::string fmt_bytes(long long v) {
  char buf[48];
  if (v >= (1LL << 30)) std::snprintf(buf, sizeof(buf), "%.2f GiB", static_cast<double>(v) / (1LL << 30));
  else if (v >= (1LL << 20)) std::snprintf(buf, sizeof(buf), "%.2f MiB", static_cast<double>(v) / (1LL << 20));
  else if (v >= (1LL << 10)) std::snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(v) / (1LL << 10));
  else std::snprintf(buf, sizeof(buf), "%lld B", v);
  return buf;
}

static std::string fmt_time(double epoch) {
  std::time_t t = static_cast<std::time_t>(epoch);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
  return buf;
}

static std::string lower_copy(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

static bool is_gauge_name(std::string_view n) {
  return n == "CurrEstab" || n == "MaxConn" || n == "RtoAlgorithm" || n == "RtoMin" ||
         n == "RtoMax" || n == "Forwarding" || n == "DefaultTTL" || n == "MPCurrEstab";
}

static bool is_alert_name(std::string_view n) {
  const char* keys[] = {"Error", "Fail", "Drop", "Abort", "Reset", "Timeout", "NoPort",
                        "Overflow", "Prune", "Csum", "NoRoute", "ListenDrop"};
  for (const char* k : keys) {
    if (n.find(k) != std::string_view::npos) return true;
  }
  return false;
}

static std::vector<std::string> split_ws(std::string_view line) {
  std::vector<std::string> out;
  std::istringstream ss{std::string(line)};
  std::string tok;
  while (ss >> tok) out.push_back(std::move(tok));
  return out;
}

// /proc/net/snmp and /proc/net/netstat: alternating "Proto: names..." / "Proto: values..."
static Result<std::vector<Counter>> parse_snmp_text(std::string_view text) {
  std::vector<Counter> out;
  std::istringstream in{std::string(text)};
  std::string line;
  std::optional<std::pair<std::string, std::vector<std::string>>> pending;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto t = trim(line);
    if (t.empty()) continue;
    if (t[0] == '#') continue;
    auto colon = t.find(':');
    if (colon == std::string::npos) continue;
    std::string proto = trim(t.substr(0, colon));
    auto rest = trim(t.substr(colon + 1));
    auto toks = split_ws(rest);
    if (toks.empty()) continue;
    bool numeric = true;
    for (char c : toks[0]) {
      if (!(c == '-' || (c >= '0' && c <= '9'))) {
        numeric = false;
        break;
      }
    }
    if (!numeric) {
      pending = std::make_pair(std::move(proto), std::move(toks));
      continue;
    }
    if (!pending || pending->first != proto) {
      pending.reset();
      continue;
    }
    const auto& names = pending->second;
    const size_t n = std::min(names.size(), toks.size());
    for (size_t i = 0; i < n; ++i) {
      Counter c;
      c.proto = proto;
      c.name = names[i];
      c.value = parse_ll(toks[i]);
      c.gauge = is_gauge_name(c.name);
      c.alert = is_alert_name(c.name);
      out.push_back(std::move(c));
    }
    pending.reset();
  }
  return out;
}

static void summarize(Snapshot& s) {
  s.ip_in = s.ip_out = s.tcp_estab = s.tcp_in = s.tcp_out = s.tcp_retrans = 0;
  s.udp_in = s.udp_out = s.udp_noport = s.icmp_in = s.icmp_out = 0;
  s.in_octets = s.out_octets = s.listen_drops = s.tcp_timeouts = 0;
  s.alerts = 0;
  std::map<std::string, int> seen;
  for (const auto& c : s.counters) {
    seen[c.proto] = 1;
    if (c.alert && c.value != 0) ++s.alerts;
    if (c.proto == "Ip" && c.name == "InReceives") s.ip_in = c.value;
    else if (c.proto == "Ip" && c.name == "OutRequests") s.ip_out = c.value;
    else if (c.proto == "Tcp" && c.name == "CurrEstab") s.tcp_estab = c.value;
    else if (c.proto == "Tcp" && c.name == "InSegs") s.tcp_in = c.value;
    else if (c.proto == "Tcp" && c.name == "OutSegs") s.tcp_out = c.value;
    else if (c.proto == "Tcp" && c.name == "RetransSegs") s.tcp_retrans = c.value;
    else if (c.proto == "Udp" && c.name == "InDatagrams") s.udp_in = c.value;
    else if (c.proto == "Udp" && c.name == "OutDatagrams") s.udp_out = c.value;
    else if (c.proto == "Udp" && c.name == "NoPorts") s.udp_noport = c.value;
    else if (c.proto == "Icmp" && c.name == "InMsgs") s.icmp_in = c.value;
    else if (c.proto == "Icmp" && c.name == "OutMsgs") s.icmp_out = c.value;
    else if (c.proto == "IpExt" && c.name == "InOctets") s.in_octets = c.value;
    else if (c.proto == "IpExt" && c.name == "OutOctets") s.out_octets = c.value;
    else if (c.proto == "TcpExt" && c.name == "ListenDrops") s.listen_drops = c.value;
    else if (c.proto == "TcpExt" && c.name == "TCPTimeouts") s.tcp_timeouts = c.value;
  }
  s.sections = static_cast<int>(seen.size());
}

static Result<Snapshot> snapshot_from_text(std::string_view text) {
  auto parsed = parse_snmp_text(text);
  if (!parsed) return std::unexpected(parsed.error());
  Snapshot s;
  s.counters = std::move(*parsed);
  s.timestamp = now_epoch();
  summarize(s);
  return s;
}

static Result<std::string> slurp(const std::string& path) {
  std::ifstream f(path);
  if (!f) return std::unexpected(Error{1, "cannot open " + path});
  std::ostringstream oss;
  oss << f.rdbuf();
  return oss.str();
}

static Result<Snapshot> read_live(const std::string& snmp_path, const std::string& netstat_path) {
  auto a = slurp(snmp_path);
  if (!a) return std::unexpected(a.error());
  auto b = slurp(netstat_path);
  std::string merged = *a;
  if (b) {
    merged += "\n";
    merged += *b;
  }
  return snapshot_from_text(merged);
}

static const char* kDemoTable =
    "# synthetic /proc/net/snmp + /proc/net/netstat dump\n"
    "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams "
    "InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes "
    "ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits\n"
    "Ip: 1 64 1843200 2 0 0 0 0 1843000 1712000 0 4 0 0 0 0 0 0 0 1712000\n"
    "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs "
    "InSrcQuenchs InRedirects InEchos InEchoReps OutMsgs OutErrors OutDestUnreachs OutEchos OutEchoReps\n"
    "Icmp: 42 3 0 39 0 0 0 0 3 0 40 0 37 0 3\n"
    "IcmpMsg: InType3 OutType3 InType8 OutType0\n"
    "IcmpMsg: 39 37 3 3\n"
    "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails "
    "EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n"
    "Tcp: 1 200 120000 -1 88210 44102 812 1204 18 2100450 2688100 312 0 4410 0\n"
    "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n"
    "Udp: 120440 14 0 118900 0 0 0 0 0\n"
    "UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n"
    "UdpLite: 0 0 0 0 0 0 0 0 0\n"
    "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed ListenOverflows ListenDrops "
    "TCPTimeouts TCPAbortOnTimeout DelayedACKs TCPFastRetrans TW TCPRcvCoalesce TCPOrigDataSent\n"
    "TcpExt: 0 0 2 0 7 19 0 88012 412 44120 210044 1688000\n"
    "IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts "
    "InOctets OutOctets InCsumErrors InNoECTPkts\n"
    "IpExt: 0 0 120 80 0 0 2488336000 1843200000 0 1960000\n"
    "MPTcpExt: MPCapableSYNRX MPCapableSYNTX MPCurrEstab\n"
    "MPTcpExt: 0 0 0\n";

static Snapshot build_demo_snapshot() {
  auto r = snapshot_from_text(kDemoTable);
  if (r) return *r;
  Snapshot s;
  s.timestamp = now_epoch();
  return s;
}

struct Filters {
  std::string section;
  bool nonzero{false};
  bool alerts_only{false};
};

static bool section_match(std::string_view proto, std::string_view want) {
  if (want.empty()) return true;
  return lower_copy(std::string(proto)) == lower_copy(std::string(want));
}

static void apply_filters(Snapshot& s, const Filters& f) {
  if (f.section.empty() && !f.nonzero && !f.alerts_only) return;
  std::vector<Counter> kept;
  kept.reserve(s.counters.size());
  for (auto& c : s.counters) {
    if (!section_match(c.proto, f.section)) continue;
    if (f.nonzero && c.value == 0 && c.delta == 0) continue;
    if (f.alerts_only && !c.alert) continue;
    kept.push_back(std::move(c));
  }
  s.counters = std::move(kept);
  summarize(s);
}

static void apply_delta(Snapshot& cur, const Snapshot& prev, double dt) {
  if (dt <= 0.0) dt = 1.0;
  std::map<std::pair<std::string, std::string>, long long> oldv;
  for (const auto& c : prev.counters) oldv[{c.proto, c.name}] = c.value;
  for (auto& c : cur.counters) {
    auto it = oldv.find({c.proto, c.name});
    if (it == oldv.end()) continue;
    c.delta = c.value - it->second;
    if (!c.gauge) c.rate = static_cast<double>(c.delta) / dt;
  }
  cur.has_delta = true;
}

static const std::string& proto_color(std::string_view p) {
  if (p == "Ip" || p == "IpExt") return C_CYAN;
  if (p == "Tcp" || p == "TcpExt") return C_GREEN;
  if (p == "Udp" || p == "UdpLite") return C_YELLOW;
  if (p == "Icmp" || p == "IcmpMsg") return C_MAGENTA;
  if (p == "MPTcpExt") return C_BLUE;
  return C_DIM;
}

static void print_header(const Snapshot& s, bool demo, std::string_view src) {
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "{}|   Linux SNMP / netstat Protocol Monitor       |{}", C_CYAN, C_RST);
  std::println(std::cout, "{}+================================================+{}", C_CYAN, C_RST);
  std::println(std::cout, "  {}Source:{} {}   {}Snapshot:{} {}{}", C_DIM, C_RST, src, C_DIM, C_RST,
               fmt_time(s.timestamp), demo ? "   --demo" : "");
  std::println(std::cout);
}

static void print_kpi(const char* label, const std::string& value, const std::string& color) {
  std::println(std::cout, "  {:<14} {}{}{}", label, color, value, C_RST);
}

static void print_summary(const Snapshot& s) {
  std::println(std::cout, "  {}-- KPIs --{}", C_BOLD, C_RST);
  print_kpi("IP in", fmt_num(s.ip_in), C_CYAN);
  print_kpi("IP out", fmt_num(s.ip_out), C_CYAN);
  print_kpi("TCP estab", std::to_string(s.tcp_estab), C_GREEN);
  print_kpi("TCP in/out", fmt_num(s.tcp_in) + " / " + fmt_num(s.tcp_out), C_GREEN);
  print_kpi("Retrans", fmt_num(s.tcp_retrans), s.tcp_retrans ? C_YELLOW : C_DIM);
  print_kpi("UDP in/out", fmt_num(s.udp_in) + " / " + fmt_num(s.udp_out), C_YELLOW);
  print_kpi("UDP NoPorts", std::to_string(s.udp_noport), s.udp_noport ? C_RED : C_DIM);
  print_kpi("ICMP in/out", fmt_num(s.icmp_in) + " / " + fmt_num(s.icmp_out), C_MAGENTA);
  print_kpi("Octets in", fmt_bytes(s.in_octets), C_BLUE);
  print_kpi("Octets out", fmt_bytes(s.out_octets), C_BLUE);
  print_kpi("ListenDrops", std::to_string(s.listen_drops), s.listen_drops ? C_RED : C_DIM);
  print_kpi("TCPTimeouts", std::to_string(s.tcp_timeouts), s.tcp_timeouts ? C_YELLOW : C_DIM);
  print_kpi("Sections", std::to_string(s.sections), C_DIM);
  print_kpi("Alerts>0", std::to_string(s.alerts), s.alerts ? C_RED : C_DIM);
  std::println(std::cout);
}

static void print_table(const Snapshot& s) {
  std::println(std::cout, "  {}-- Counters ({}) --{}", C_BOLD, s.counters.size(), C_RST);
  if (s.has_delta) {
    std::println(std::cout, "  {}{:<10} {:<22} {:>12} {:>10} {:>10}  {}{}", C_DIM, "Proto", "Name",
                 "Value", "Delta", "Rate", "Note", C_RST);
  } else {
    std::println(std::cout, "  {}{:<10} {:<22} {:>12}  {}{}", C_DIM, "Proto", "Name", "Value", "Note",
                 C_RST);
  }
  std::string last;
  for (const auto& c : s.counters) {
    if (c.proto != last) {
      last = c.proto;
      std::println(std::cout, "  {}[{}]{}", proto_color(c.proto), c.proto, C_RST);
    }
    std::string note;
    if (c.gauge) note = "gauge";
    else if (c.alert && c.value != 0) note = "alert";
    const auto& ncol = (c.alert && c.value != 0) ? C_RED : (c.gauge ? C_BLUE : C_RST);
    if (s.has_delta) {
      std::println(std::cout, "  {:<10} {}{:<22}{} {:>12} {:>10} {:>10}  {}{}{}", c.proto, ncol,
                   c.name, C_RST, fmt_num(c.value), fmt_signed(c.delta),
                   c.gauge ? "-" : fmt_rate(c.rate), C_DIM, note, C_RST);
    } else {
      std::println(std::cout, "  {:<10} {}{:<22}{} {:>12}  {}{}{}", c.proto, ncol, c.name, C_RST,
                   fmt_num(c.value), C_DIM, note, C_RST);
    }
  }
  std::println(std::cout);
}

static void print_json(const Snapshot& s) {
  std::ostringstream o;
  o << "{";
  o << "\"timestamp\":" << static_cast<long long>(s.timestamp) << ",";
  o << "\"summary\":{";
  o << "\"ip_in_receives\":" << s.ip_in << ",";
  o << "\"ip_out_requests\":" << s.ip_out << ",";
  o << "\"tcp_curr_estab\":" << s.tcp_estab << ",";
  o << "\"tcp_in_segs\":" << s.tcp_in << ",";
  o << "\"tcp_out_segs\":" << s.tcp_out << ",";
  o << "\"tcp_retrans_segs\":" << s.tcp_retrans << ",";
  o << "\"udp_in_datagrams\":" << s.udp_in << ",";
  o << "\"udp_out_datagrams\":" << s.udp_out << ",";
  o << "\"udp_no_ports\":" << s.udp_noport << ",";
  o << "\"icmp_in_msgs\":" << s.icmp_in << ",";
  o << "\"icmp_out_msgs\":" << s.icmp_out << ",";
  o << "\"in_octets\":" << s.in_octets << ",";
  o << "\"out_octets\":" << s.out_octets << ",";
  o << "\"listen_drops\":" << s.listen_drops << ",";
  o << "\"tcp_timeouts\":" << s.tcp_timeouts << ",";
  o << "\"sections\":" << s.sections << ",";
  o << "\"counters\":" << s.counters.size() << ",";
  o << "\"alerts\":" << s.alerts;
  o << "},";
  o << "\"sections\":{";
  std::string last;
  bool first_sec = true;
  bool first_kv = true;
  for (const auto& c : s.counters) {
    if (c.proto != last) {
      if (!first_sec) o << "}";
      if (!first_sec) o << ",";
      o << "\"" << json_escape(c.proto) << "\":{";
      last = c.proto;
      first_sec = false;
      first_kv = true;
    }
    if (!first_kv) o << ",";
    o << "\"" << json_escape(c.name) << "\":" << c.value;
    first_kv = false;
  }
  if (!first_sec) o << "}";
  o << "}";
  if (s.has_delta) {
    o << ",\"delta\":[";
    bool first = true;
    for (const auto& c : s.counters) {
      if (c.delta == 0) continue;
      if (!first) o << ",";
      first = false;
      o << "{\"proto\":\"" << json_escape(c.proto) << "\",\"name\":\"" << json_escape(c.name)
        << "\",\"delta\":" << c.delta << ",\"rate\":" << c.rate << "}";
    }
    o << "]";
  }
  o << "}\n";
  std::cout << o.str();
}

static int run_selftest() {
  int passed = 0, failed = 0;
  auto check = [&](const char* name, bool ok) {
    if (ok) {
      ++passed;
      std::println(std::cout, "  {}✓{} {}", C_GREEN, C_RST, name);
    } else {
      ++failed;
      std::println(std::cout, "  {}✗{} {}", C_RED, C_RST, name);
    }
  };

  std::println(std::cout, "{}snmp-watch selftest{}", C_BOLD, C_RST);
  std::println(std::cout);

  check("gauge CurrEstab", is_gauge_name("CurrEstab"));
  check("gauge DefaultTTL", is_gauge_name("DefaultTTL"));
  check("not gauge InSegs", !is_gauge_name("InSegs"));
  check("alert InErrors", is_alert_name("InErrors"));
  check("alert RetransSegs no", !is_alert_name("RetransSegs"));
  check("alert ListenDrops", is_alert_name("ListenDrops"));
  check("alert TCPTimeouts", is_alert_name("TCPTimeouts"));
  check("alert InCsumErrors", is_alert_name("InCsumErrors"));
  check("alert OutNoRoutes", is_alert_name("OutNoRoutes"));
  check("not alert InReceives", !is_alert_name("InReceives"));

  check("parse_ll 42", parse_ll("42") == 42);
  check("parse_ll spaces", parse_ll("  -1") == -1);
  check("parse_ll junk", parse_ll("abc") == 0);
  check("fmt_signed +3", fmt_signed(3) == "+3");
  check("fmt_signed -2", fmt_signed(-2) == "-2");
  check("json_escape quote", json_escape("a\"b") == "a\\\"b");
  check("fmt_bytes MiB", fmt_bytes(2 * 1024 * 1024) == "2.00 MiB");
  check("section_match tcp", section_match("Tcp", "tcp"));
  check("section_match miss", !section_match("Udp", "tcp"));

  {
    const char* sample =
        "# comment header\n"
        "Ip: Forwarding DefaultTTL InReceives OutNoRoutes\n"
        "Ip: 1 64 100 2\n"
        "Tcp: CurrEstab InSegs RetransSegs InErrors\n"
        "Tcp: 5 200 3 1\n";
    auto r = parse_snmp_text(sample);
    check("parse ok", r.has_value());
    check("parse 8 counters", r && r->size() == 8);
    if (r && r->size() == 8) {
      check("parse proto Ip", (*r)[0].proto == "Ip" && (*r)[0].name == "Forwarding");
      check("parse gauge ttl", (*r)[1].gauge && (*r)[1].value == 64);
      check("parse InReceives", (*r)[2].value == 100);
      check("parse OutNoRoutes alert", (*r)[3].alert && (*r)[3].value == 2);
      check("parse CurrEstab gauge", (*r)[4].gauge && (*r)[4].value == 5);
      check("parse InErrors alert", (*r)[7].alert);
      check("comment skipped", true);
    }
  }

  {
    const char* orphan =
        "Ip: 1 64 10\n"
        "Tcp: CurrEstab InSegs\n"
        "Udp: 1 2\n";
    auto r = parse_snmp_text(orphan);
    check("orphan values ignored", r && r->empty());
  }

  auto demo = build_demo_snapshot();
  check("demo sections == 9", demo.sections == 9);
  check("demo counters > 40", static_cast<int>(demo.counters.size()) > 40);
  check("demo ip_in", demo.ip_in == 1843200);
  check("demo ip_out", demo.ip_out == 1712000);
  check("demo tcp_estab", demo.tcp_estab == 18);
  check("demo retrans", demo.tcp_retrans == 312);
  check("demo udp noport", demo.udp_noport == 14);
  check("demo octets in", demo.in_octets == 2488336000LL);
  check("demo listen drops", demo.listen_drops == 7);
  check("demo tcp timeouts", demo.tcp_timeouts == 19);
  check("demo alerts > 0", demo.alerts > 0);

  bool print_ok = true;
  try {
    print_header(demo, true, "/proc/net/snmp+/proc/net/netstat");
    print_summary(demo);
    print_table(demo);
  } catch (...) {
    print_ok = false;
  }
  check("demo print no crash", print_ok);

  std::string json_out;
  {
    std::ostringstream oss;
    auto* old = std::cout.rdbuf(oss.rdbuf());
    print_json(demo);
    std::cout.rdbuf(old);
    json_out = oss.str();
  }
  check("JSON starts with '{'", !json_out.empty() && json_out[0] == '{');
  check("JSON has summary", json_out.find("\"summary\"") != std::string::npos);
  check("JSON has sections", json_out.find("\"sections\"") != std::string::npos);
  check("JSON quoted Ip", json_out.find("\"Ip\"") != std::string::npos);
  check("JSON quoted CurrEstab", json_out.find("\"CurrEstab\"") != std::string::npos);
  check("JSON tcp_curr_estab", json_out.find("\"tcp_curr_estab\"") != std::string::npos);
  check("JSON in_octets", json_out.find("\"in_octets\"") != std::string::npos);

  {
    auto d = build_demo_snapshot();
    Filters f;
    f.section = "tcp";
    apply_filters(d, f);
    bool only = true;
    for (const auto& c : d.counters)
      if (c.proto != "Tcp") only = false;
    check("--section tcp filter", only && !d.counters.empty());
  }
  {
    auto d = build_demo_snapshot();
    Filters f;
    f.alerts_only = true;
    apply_filters(d, f);
    bool only = true;
    for (const auto& c : d.counters)
      if (!c.alert) only = false;
    check("--alerts filter", only && !d.counters.empty());
  }
  {
    auto d = build_demo_snapshot();
    Filters f;
    f.nonzero = true;
    apply_filters(d, f);
    bool only = true;
    for (const auto& c : d.counters)
      if (c.value == 0) only = false;
    check("--nonzero filter", only && !d.counters.empty());
  }

  {
    auto a = build_demo_snapshot();
    auto b = build_demo_snapshot();
    for (auto& c : b.counters) {
      if (c.name == "InReceives") c.value += 200;
      if (c.name == "CurrEstab") c.value = 22;
    }
    apply_delta(b, a, 2.0);
    bool rate_ok = false, gauge_ok = false;
    for (const auto& c : b.counters) {
      if (c.proto == "Ip" && c.name == "InReceives") rate_ok = (c.delta == 200 && c.rate == 100.0);
      if (c.proto == "Tcp" && c.name == "CurrEstab") gauge_ok = (c.delta == 4 && c.rate == 0.0);
    }
    check("delta rate InReceives", rate_ok);
    check("delta gauge CurrEstab no rate", gauge_ok);
    check("has_delta set", b.has_delta);
  }

  auto real = read_live("/proc/net/snmp", "/proc/net/netstat");
  if (real.has_value()) {
    check("proc snmp+netstat read ok", true);
    check("real has Ip section", real->ip_in >= 0);
    check("real counters countable", real->counters.size() < 100000);
    check("real sections >= 4", real->sections >= 4);
  } else {
    std::println(std::cout, "  {}ℹ{} /proc/net/snmp failed ({}): restricted env — skipping",
                 C_YELLOW, C_RST, real.error().message);
  }

  g_color = true;
  init_colors();
  std::string colored = C_GREEN;
  g_color = false;
  init_colors();
  std::string plain = C_GREEN;
  check("--no-color clears ANSI", !colored.empty() && plain.empty());
  g_color = true;
  init_colors();

  std::println(std::cout);
  std::println(std::cout, "{}  Results: {} passed, {} failed{}", failed == 0 ? C_GREEN : C_RED,
               passed, failed, C_RST);
  return failed == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
  bool json_mode = false;
  bool watch_mode = false;
  bool demo_mode = false;
  bool selftest = false;
  int watch_secs = 2;
  Filters filt;
  std::string file_path;
  std::string snmp_path = "/proc/net/snmp";
  std::string netstat_path = "/proc/net/netstat";

  for (int i = 1; i < argc; ++i) {
    std::string_view arg{argv[i]};
    if (arg == "--json") json_mode = true;
    else if (arg == "--no-color" || arg == "-c") g_color = false;
    else if (arg == "--demo") demo_mode = true;
    else if (arg == "--selftest") selftest = true;
    else if (arg == "--nonzero") filt.nonzero = true;
    else if (arg == "--alerts") filt.alerts_only = true;
    else if ((arg == "--section" || arg == "-s") && i + 1 < argc) {
      ++i;
      filt.section = argv[i];
    } else if ((arg == "--file" || arg == "-f") && i + 1 < argc) {
      ++i;
      file_path = argv[i];
    } else if (arg == "--snmp" && i + 1 < argc) {
      ++i;
      snmp_path = argv[i];
    } else if (arg == "--netstat" && i + 1 < argc) {
      ++i;
      netstat_path = argv[i];
    } else if ((arg == "--watch" || arg == "-w") && i + 1 < argc) {
      watch_mode = true;
      ++i;
      std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), watch_secs);
      if (watch_secs < 1) watch_secs = 1;
    } else if (arg == "--help" || arg == "-h") {
      init_colors();
      std::println(std::cout, "{}snmp-watch{} — Linux SNMP / netstat protocol monitor\n", C_BOLD,
                   C_RST);
      std::println(std::cout, "Usage: snmp-watch [options]\n");
      std::println(std::cout, "Options:");
      std::println(std::cout, "  -w, --watch N      Refresh every N seconds (default: 2)");
      std::println(std::cout, "  --json             Output JSON");
      std::println(std::cout, "  --no-color, -c     Disable ANSI colors");
      std::println(std::cout, "  --demo             Simulated snmp + netstat dump");
      std::println(std::cout, "  -s, --section NAME Filter Ip|Icmp|Tcp|Udp|TcpExt|IpExt|...");
      std::println(std::cout, "  --nonzero          Hide zero counters");
      std::println(std::cout, "  --alerts           Only error/drop/timeout counters");
      std::println(std::cout, "  -f, --file PATH    Parse a dump instead of /proc");
      std::println(std::cout, "  --snmp PATH        Override /proc/net/snmp");
      std::println(std::cout, "  --netstat PATH     Override /proc/net/netstat");
      std::println(std::cout, "  --selftest         Run built-in tests");
      std::println(std::cout, "  -h, --help         Show this help\n");
      std::println(std::cout, "{}", C_DIM + "Reads: /proc/net/snmp + /proc/net/netstat" + C_RST);
      return 0;
    }
  }

  init_colors();
  if (selftest) return run_selftest();

  auto take = [&]() -> std::optional<Snapshot> {
    if (demo_mode) {
      auto d = build_demo_snapshot();
      apply_filters(d, filt);
      return d;
    }
    Result<Snapshot> r = file_path.empty() ? read_live(snmp_path, netstat_path)
                                           : [&]() -> Result<Snapshot> {
      auto txt = slurp(file_path);
      if (!txt) return std::unexpected(txt.error());
      return snapshot_from_text(*txt);
    }();
    if (!r) {
      if (!json_mode) std::println(std::cerr, "{}Error:{} {}", C_RED, C_RST, r.error().message);
      return std::nullopt;
    }
    apply_filters(*r, filt);
    return *r;
  };

  const std::string src = demo_mode ? "/proc/net/snmp+/proc/net/netstat"
                                    : (file_path.empty() ? "/proc/net/snmp+/proc/net/netstat"
                                                         : file_path);

  if (watch_mode) {
    std::optional<Snapshot> prev;
    bool first = true;
    while (true) {
      auto snap = take();
      if (!snap) return 1;
      if (prev) {
        double dt = snap->timestamp - prev->timestamp;
        if (first || dt <= 0.0) dt = static_cast<double>(watch_secs);
        apply_delta(*snap, *prev, dt);
      }
      prev = snap;

      if (!json_mode && !first) std::cout << "\033[2J\033[H";
      first = false;

      if (json_mode) {
        print_json(*snap);
      } else {
        print_header(*snap, demo_mode, src);
        print_summary(*snap);
        print_table(*snap);
        std::println(std::cout, "{}  Refreshing every {}s — Ctrl+C to exit{}", C_DIM, watch_secs,
                     C_RST);
      }
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch_secs));
    }
  } else {
    auto snap = take();
    if (!snap) return 1;
    if (json_mode) {
      print_json(*snap);
    } else {
      print_header(*snap, demo_mode, src);
      print_summary(*snap);
      print_table(*snap);
    }
  }
  return 0;
}
