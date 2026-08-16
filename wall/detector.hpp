// FalconWall detector plugin framework (compile-time plugins).
//
// Design patterns used:
//   - Strategy:    every detector is an interchangeable algorithm behind the
//                  Detector interface.
//   - Registry:    a single global registry holds all registered detectors.
//   - Self-registration (RAII): each detector registers itself via a static
//                  registrar object, so the watch loop never needs editing.
//
// To add a detector, write a class deriving from Detector and call
// REGISTER_DETECTOR(MyDetector) once. Then add its .cpp to the Makefile.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

// Mirrors `struct ip_stats` in fw_prog.c. Field order and types MUST match
// the BPF struct exactly, or the map values will be misread.
struct IpStats {
    uint64_t window_start;
    uint64_t prev_packets;
    uint64_t packets;
    uint64_t prev_bytes;
    uint64_t bytes;
    uint64_t syn;
    uint64_t udp;
    uint64_t icmp;
};

// A detector inspects one source IP's stats and decides whether to ban it.
class Detector {
public:
    virtual ~Detector() = default;
    virtual const char* name() const = 0;
    // Return true if this IP should be banned.
    virtual bool match(uint32_t ip, const IpStats& s) const = 0;
};

class DetectorRegistry {
public:
    static DetectorRegistry& get();

    void add(std::unique_ptr<Detector> d);
    const std::vector<std::unique_ptr<Detector>>& all() const;

    DetectorRegistry(const DetectorRegistry&) = delete;
    DetectorRegistry& operator=(const DetectorRegistry&) = delete;

private:
    DetectorRegistry() = default;
    std::vector<std::unique_ptr<Detector>> detectors_;
};

// Self-registers a detector when a translation unit is loaded.
struct DetectorRegistrar {
    explicit DetectorRegistrar(std::unique_ptr<Detector> d) {
        DetectorRegistry::get().add(std::move(d));
    }
};

#define REGISTER_DETECTOR(Class) \
    static DetectorRegistrar _registrar_##Class(std::make_unique<Class>())
