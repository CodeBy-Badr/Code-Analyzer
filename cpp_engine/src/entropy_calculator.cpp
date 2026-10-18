#include "../include/entropy_calculator.hpp"
#include <cstring>
#include <numeric>
#include <algorithm>

namespace Analyzer {

double EntropyCalculator::calculate_buffer_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    uint64_t counts[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    double dsize = static_cast<double>(size);

    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / dsize;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

EntropyResult EntropyCalculator::analyze_entropy(const uint8_t* data, size_t size, size_t window_size) {
    EntropyResult result;
    result.overall_entropy = 0.0;
    result.max_window_entropy = 0.0;
    result.min_window_entropy = 8.0;
    result.variance = 0.0;
    result.is_likely_packed = false;
    std::memset(result.byte_counts, 0, sizeof(result.byte_counts));

    if (!data || size == 0) {
        result.min_window_entropy = 0.0;
        return result;
    }

    // 1. Overall histogram and entropy
    for (size_t i = 0; i < size; ++i) {
        result.byte_counts[data[i]]++;
    }

    double dsize = static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (result.byte_counts[i] > 0) {
            double p = static_cast<double>(result.byte_counts[i]) / dsize;
            result.overall_entropy -= p * std::log2(p);
        }
    }

    // 2. Sliding window analysis
    if (window_size > size) {
        window_size = size;
    }

    size_t step = window_size / 2;
    if (step == 0) step = 1;

    double sum = 0.0;
    for (size_t offset = 0; offset + window_size <= size; offset += step) {
        double w_entropy = calculate_buffer_entropy(data + offset, window_size);
        result.window_curve.push_back(w_entropy);
        sum += w_entropy;

        if (w_entropy > result.max_window_entropy) {
            result.max_window_entropy = w_entropy;
        }
        if (w_entropy < result.min_window_entropy) {
            result.min_window_entropy = w_entropy;
        }
    }

    if (!result.window_curve.empty()) {
        double mean = sum / static_cast<double>(result.window_curve.size());
        double sq_diff_sum = 0.0;
        for (double w : result.window_curve) {
            sq_diff_sum += (w - mean) * (w - mean);
        }
        result.variance = sq_diff_sum / static_cast<double>(result.window_curve.size());
    } else {
        result.min_window_entropy = result.overall_entropy;
        result.max_window_entropy = result.overall_entropy;
    }

    // 3. Packer / encryption heuristic decision
    if (result.overall_entropy >= PACKED_THRESHOLD || 
        result.max_window_entropy >= HIGH_ENTROPY_PEAK) {
        result.is_likely_packed = true;
    }

    return result;
}

} // namespace Analyzer

