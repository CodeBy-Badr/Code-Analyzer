#ifndef ENTROPY_CALCULATOR_HPP
#define ENTROPY_CALCULATOR_HPP

#include <vector>
#include <cstdint>
#include <cmath>
#include <string>

namespace Analyzer {

struct EntropyResult {
    double overall_entropy;          // 0.0 to 8.0
    double max_window_entropy;       // Peak entropy in sliding window
    double min_window_entropy;       // Lowest entropy
    double variance;                 // Entropy variance across windows
    bool is_likely_packed;           // True if overall > 7.1 or peak > 7.5
    std::vector<double> window_curve;// Sliding window entropy data points
    uint64_t byte_counts[256];       // Byte frequency histogram
};

class EntropyCalculator {
public:
    static constexpr size_t DEFAULT_WINDOW_SIZE = 512;
    static constexpr double PACKED_THRESHOLD = 7.15;
    static constexpr double HIGH_ENTROPY_PEAK = 7.60;

    static double calculate_buffer_entropy(const uint8_t* data, size_t size);
    
    static EntropyResult analyze_entropy(
        const uint8_t* data, 
        size_t size, 
        size_t window_size = DEFAULT_WINDOW_SIZE
    );
};

} // namespace Analyzer

#endif // ENTROPY_CALCULATOR_HPP

