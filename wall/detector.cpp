// Detector registry implementation + built-in detectors.
//
// Each detector is a Strategy. Adding a new one is: subclass Detector, override
// name()/match(), then REGISTER_DETECTOR(YourDetector). Nothing else changes.

#include "detector.hpp"

DetectorRegistry& DetectorRegistry::get() {
    static DetectorRegistry instance;
    return instance;
}

void DetectorRegistry::add(std::unique_ptr<Detector> d) {
    detectors_.push_back(std::move(d));
}

const std::vector<std::unique_ptr<Detector>>& DetectorRegistry::all() const {
    return detectors_;
}

// ---- Built-in detectors ---------------------------------------------------
//
// The per-IP stats reflect a ~1.07s sliding window, so "per second" thresholds
// are approximate. Tune the constants below to taste.

namespace {

// Bans an IP sending more than ~10k packets per second.
class RateDetector : public Detector {
public:
    const char* name() const override { return "rate"; }
    bool match(uint32_t ip, const IpStats& s) const override {
        (void)ip;
        return s.packets > 10000;
    }
};

// Bans an IP whose traffic is >80% TCP SYN (classic SYN flood), with a floor
// to avoid false positives on low traffic.
class SynFloodDetector : public Detector {
public:
    const char* name() const override { return "synflood"; }
    bool match(uint32_t ip, const IpStats& s) const override {
        (void)ip;
        return s.packets > 50 && s.syn * 10 > s.packets * 8;
    }
};

// Bans an IP sending more than ~5k UDP packets per second.
class UdpFloodDetector : public Detector {
public:
    const char* name() const override { return "udpflood"; }
    bool match(uint32_t ip, const IpStats& s) const override {
        (void)ip;
        return s.udp > 5000;
    }
};

// Bans an IP sending more than ~1k ICMP packets per second.
class IcmpFloodDetector : public Detector {
public:
    const char* name() const override { return "icmpflood"; }
    bool match(uint32_t ip, const IpStats& s) const override {
        (void)ip;
        return s.icmp > 1000;
    }
};

} // namespace

REGISTER_DETECTOR(RateDetector);
REGISTER_DETECTOR(SynFloodDetector);
REGISTER_DETECTOR(UdpFloodDetector);
REGISTER_DETECTOR(IcmpFloodDetector);
