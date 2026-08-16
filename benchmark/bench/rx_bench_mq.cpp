// Multi-queue throughput benchmark with CPU and latency metrics.
// Each queue runs in its own process, pinned to a dedicated CPU core.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "falcon/backend/af_packet.hpp"
#include "falcon/backend/af_xdp.hpp"
#include "falcon/backend/socket.hpp"

namespace {

using Clock = std::chrono::steady_clock;
constexpr size_t kBatchSize = 2048;

struct CpuTimes {
    uint64_t user = 0;
    uint64_t nice = 0;
    uint64_t system = 0;
    uint64_t idle = 0;
    uint64_t iowait = 0;
    uint64_t irq = 0;
    uint64_t softirq = 0;
    uint64_t steal = 0;
};

CpuTimes read_cpu_times(int cpu) {
    std::ifstream stat("/proc/stat");
    std::string line;
    while (std::getline(stat, line)) {
        if (line.rfind("cpu" + std::to_string(cpu) + " ", 0) == 0) {
            CpuTimes t;
            std::sscanf(line.c_str(), "cpu%*d %llu %llu %llu %llu %llu %llu %llu %llu",
                        &t.user, &t.nice, &t.system, &t.idle, &t.iowait, &t.irq, &t.softirq, &t.steal);
            return t;
        }
    }
    return {};
}

double cpu_usage_percent(const CpuTimes& before, const CpuTimes& after) {
    const uint64_t total_before = before.user + before.nice + before.system + before.idle +
                                  before.iowait + before.irq + before.softirq + before.steal;
    const uint64_t total_after = after.user + after.nice + after.system + after.idle +
                                 after.iowait + after.irq + after.softirq + after.steal;
    const uint64_t idle_before = before.idle + before.iowait;
    const uint64_t idle_after = after.idle + after.iowait;

    const uint64_t total_delta = total_after - total_before;
    const uint64_t idle_delta = idle_after - idle_before;

    if (total_delta == 0) return 0.0;
    return 100.0 * (total_delta - idle_delta) / total_delta;
}

struct QueueResult {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t kernel_drops = 0;
    double elapsed_s = 0.0;
    double cpu_percent = 0.0;
    double pps = 0.0;
    double gbps = 0.0;
};

template <typename Backend>
QueueResult run_queue(const std::string& target, double seconds, uint64_t expected_packets,
                      int cpu_id, uint32_t queue_id, falcon::AfXdpMode xdp_mode) {
    // Pin to CPU
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        std::fprintf(stderr, "warning: failed to pin to CPU %d\n", cpu_id);
    }

    Backend backend = [&] {
        if constexpr (std::is_same_v<Backend, falcon::SocketBackend>) {
            return Backend(static_cast<uint16_t>(std::strtoul(target.c_str(), nullptr, 10)));
        } else if constexpr (std::is_same_v<Backend, falcon::AfXdpBackend>) {
            return Backend(target, xdp_mode, false, queue_id);
        } else {
            return Backend(target);
        }
    }();

    std::array<falcon::Frame, kBatchSize> frames;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool started = false;
    Clock::time_point start;
    CpuTimes cpu_start;

    while (true) {
        const size_t received = backend.recv(frames.data(), frames.size());
        if (received != 0 && !started) {
            started = true;
            start = Clock::now();
            cpu_start = read_cpu_times(cpu_id);
        }
        if (!started) {
            continue;
        }
        packets += received;
        for (size_t i = 0; i < received; ++i) {
            bytes += frames[i].len_;
        }

        const auto now = Clock::now();
        const double elapsed = std::chrono::duration<double>(now - start).count();
        if ((expected_packets != 0 && packets >= expected_packets) || elapsed >= seconds) {
            const CpuTimes cpu_end = read_cpu_times(cpu_id);
            uint64_t kernel_drops = 0;
            if constexpr (!std::is_same_v<Backend, falcon::SocketBackend>) {
                kernel_drops = backend.kernelDrops();
            }

            QueueResult result;
            result.packets = packets;
            result.bytes = bytes;
            result.kernel_drops = kernel_drops;
            result.elapsed_s = elapsed;
            result.cpu_percent = cpu_usage_percent(cpu_start, cpu_end);
            result.pps = packets / elapsed;
            result.gbps = bytes * 8.0 / elapsed / 1e9;
            return result;
        }
    }
}

template <typename Backend>
int run_multi(const std::string& target, double seconds, uint64_t expected_packets_per_queue,
              int num_queues, falcon::AfXdpMode xdp_mode = falcon::AfXdpMode::kCopy) {
    std::vector<pid_t> children;
    std::vector<int> pipes;

    for (int q = 0; q < num_queues; ++q) {
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            std::perror("pipe");
            return 1;
        }

        pid_t pid = fork();
        if (pid == 0) {
            // Child
            close(pipefd[0]);
            QueueResult result;
            if constexpr (std::is_same_v<Backend, falcon::AfXdpBackend>) {
                result = run_queue<Backend>(target, seconds, expected_packets_per_queue,
                                            q, q, xdp_mode);
            } else {
                result = run_queue<Backend>(target, seconds, expected_packets_per_queue,
                                            q, 0, xdp_mode);
            }
            write(pipefd[1], &result, sizeof(result));
            close(pipefd[1]);
            _exit(0);
        }
        // Parent
        close(pipefd[1]);
        children.push_back(pid);
        pipes.push_back(pipefd[0]);
    }

    // Collect results
    std::vector<QueueResult> results(num_queues);
    for (int i = 0; i < num_queues; ++i) {
        read(pipes[i], &results[i], sizeof(QueueResult));
        close(pipes[i]);
    }

    for (pid_t pid : children) {
        waitpid(pid, nullptr, 0);
    }

    // Aggregate and report
    uint64_t total_packets = 0, total_bytes = 0, total_drops = 0;
    double max_elapsed = 0.0;
    double total_cpu = 0.0;

    std::printf("\nqueue,packets,pps,gbps,cpu_percent,kernel_drops\n");
    for (int q = 0; q < num_queues; ++q) {
        const auto& r = results[q];
        std::printf("%d,%llu,%.0f,%.3f,%.1f,%llu\n",
                    q,
                    (unsigned long long)r.packets,
                    r.pps, r.gbps, r.cpu_percent,
                    (unsigned long long)r.kernel_drops);
        total_packets += r.packets;
        total_bytes += r.bytes;
        total_drops += r.kernel_drops;
        total_cpu += r.cpu_percent;
        if (r.elapsed_s > max_elapsed) max_elapsed = r.elapsed_s;
    }

    std::printf("\ntotal,packets,%llu\n", (unsigned long long)total_packets);
    std::printf("total,bytes,%llu\n", (unsigned long long)total_bytes);
    std::printf("total,kernel_drops,%llu\n", (unsigned long long)total_drops);
    std::printf("total,pps,%.0f\n", total_packets / max_elapsed);
    std::printf("total,gbps,%.3f\n", total_bytes * 8.0 / max_elapsed / 1e9);
    std::printf("total,cpu_percent_avg,%.1f\n", total_cpu / num_queues);
    std::printf("total,cpu_percent_sum,%.1f\n", total_cpu);

    if (expected_packets_per_queue != 0) {
        const uint64_t expected = expected_packets_per_queue * num_queues;
        std::printf("offered_packets,%llu\n", (unsigned long long)expected);
        std::printf("lost_packets,%llu\n", (unsigned long long)(expected > total_packets ? expected - total_packets : 0));
    }

    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 5 && argc != 6) {
        std::fprintf(stderr, "usage: falcon-rxbench-mq socket <port> <seconds> <queues>\n"
                             "       falcon-rxbench-mq packet <interface> <seconds> <queues>\n"
                             "       falcon-rxbench-mq xdp <interface> <seconds> <queues>\n"
                             "       falcon-rxbench-mq xdp-zc <interface> <seconds> <queues>\n"
                             "       append [expected_packets_per_queue] for controlled finite run\n");
        return 1;
    }

    const std::string backend = argv[1];
    const std::string target = argv[2];
    const double seconds = std::atof(argv[3]);
    const int num_queues = std::atoi(argv[4]);
    const uint64_t expected_packets = argc == 6 ? std::strtoull(argv[5], nullptr, 10) : 0;

    if (seconds <= 0.0 || num_queues <= 0 || num_queues > 64) {
        std::fprintf(stderr, "invalid seconds or queue count\n");
        return 1;
    }

    try {
        if (backend == "socket") {
            return run_multi<falcon::SocketBackend>(target, seconds, expected_packets, num_queues);
        }
        if (backend == "packet") {
            return run_multi<falcon::AfPacketBackend>(target, seconds, expected_packets, num_queues);
        }
        if (backend == "xdp") {
            return run_multi<falcon::AfXdpBackend>(target, seconds, expected_packets, num_queues);
        }
        if (backend == "xdp-zc") {
            return run_multi<falcon::AfXdpBackend>(target, seconds, expected_packets, num_queues,
                                                   falcon::AfXdpMode::kZeroCopy);
        }
        std::fprintf(stderr, "unknown backend: %s\n", backend.c_str());
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "falcon-rxbench-mq: %s\n", error.what());
        return 1;
    }
}
