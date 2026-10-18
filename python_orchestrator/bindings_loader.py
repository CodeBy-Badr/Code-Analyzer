"""
Dual-mode bindings loader for C++ Feature Extraction Engine.
Supports:
1. pybind11 native extension module (.pyd)
2. C-bindings dynamic link library (.dll / .so) via ctypes
3. Pure Python fallback mode
"""

import os
import sys
import json
import math
import ctypes
from typing import Dict, Any, List, Optional

# Add cpp_engine to search path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
CPP_ENGINE_DIR = os.path.join(PROJECT_ROOT, "cpp_engine")

if CPP_ENGINE_DIR not in sys.path:
    sys.path.insert(0, CPP_ENGINE_DIR)


class CSimpleFeatures(ctypes.Structure):
    _fields_ = [
        ("overall_entropy", ctypes.c_double),
        ("max_window_entropy", ctypes.c_double),
        ("is_packed", ctypes.c_uint32),
        ("file_size", ctypes.c_uint64),
        ("total_strings", ctypes.c_uint32),
        ("suspicious_apis_count", ctypes.c_uint32),
        ("urls_count", ctypes.c_uint32),
        ("ip_count", ctypes.c_uint32),
        ("has_injection", ctypes.c_uint32),
        ("has_ransomware", ctypes.c_uint32),
        ("has_evasion", ctypes.c_uint32),
        ("threat_score", ctypes.c_uint32),
        ("ml_features", ctypes.c_double * 12),
    ]


class FeatureEngineLoader:
    def __init__(self):
        self.mode = "UNINITIALIZED"
        self._pybind_mod = None
        self._dll_handle = None
        self._load_engine()

    def _load_engine(self):
        # 1. Try pybind11 module first
        try:
            import feature_engine
            self._pybind_mod = feature_engine
            self.mode = "PYBIND11"
            return
        except Exception:
            pass

        # 2. Try C-bindings DLL via ctypes
        dll_name = "features_engine.dll" if os.name == "nt" else "libfeatures_engine.so"
        dll_path = os.path.join(CPP_ENGINE_DIR, dll_name)

        if os.path.exists(dll_path):
            try:
                self._dll_handle = ctypes.CDLL(dll_path)
                
                # Setup signatures
                self._dll_handle.calculate_shannon_entropy_c.argtypes = [
                    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
                ]
                self._dll_handle.calculate_shannon_entropy_c.restype = ctypes.c_double

                self._dll_handle.extract_features_from_buffer.argtypes = [
                    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(CSimpleFeatures)
                ]
                self._dll_handle.extract_features_from_buffer.restype = ctypes.c_bool

                self._dll_handle.extract_features_from_file.argtypes = [
                    ctypes.c_char_p, ctypes.POINTER(CSimpleFeatures)
                ]
                self._dll_handle.extract_features_from_file.restype = ctypes.c_bool

                self._dll_handle.analyze_to_json_c.argtypes = [
                    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_char_p,
                    ctypes.c_char_p, ctypes.c_size_t
                ]
                self._dll_handle.analyze_to_json_c.restype = ctypes.c_bool

                self.mode = "CTYPES_DLL"
                return
            except Exception:
                pass

        # 3. Pure Python Fallback
        self.mode = "PYTHON_FALLBACK"

    def calculate_entropy(self, data: bytes) -> float:
        if self.mode == "PYBIND11":
            return self._pybind_mod.calculate_entropy(data)
        elif self.mode == "CTYPES_DLL":
            buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
            return self._dll_handle.calculate_shannon_entropy_c(buf, len(data))
        else:
            if not data:
                return 0.0
            counts = [0] * 256
            for b in data:
                counts[b] += 1
            entropy = 0.0
            length = float(len(data))
            for c in counts:
                if c > 0:
                    p = c / length
                    entropy -= p * math.log2(p)
            return entropy

    def analyze_buffer(self, data: bytes, name: str = "memory_buffer") -> Dict[str, Any]:
        if self.mode == "PYBIND11":
            return self._pybind_mod.analyze_buffer(data, name)
        elif self.mode == "CTYPES_DLL":
            buf_len = 1024 * 1024 # 1MB buffer for JSON
            out_buf = ctypes.create_string_buffer(buf_len)
            c_data = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
            success = self._dll_handle.analyze_to_json_c(
                c_data, len(data), name.encode("utf-8"), out_buf, buf_len
            )
            if success:
                try:
                    return json.loads(out_buf.value.decode("utf-8"))
                except Exception:
                    pass
        return self._python_fallback_analyze(data, name)

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        if self.mode == "PYBIND11":
            return self._pybind_mod.analyze_file(filepath)
        elif self.mode == "CTYPES_DLL":
            buf_len = 1024 * 1024
            out_buf = ctypes.create_string_buffer(buf_len)
            success = self._dll_handle.analyze_to_json_c(
                None, 0, filepath.encode("utf-8"), out_buf, buf_len
            )
            if success:
                try:
                    return json.loads(out_buf.value.decode("utf-8"))
                except Exception:
                    pass

        with open(filepath, "rb") as f:
            data = f.read(32 * 1024 * 1024)
        return self._python_fallback_analyze(data, filepath)

    def get_feature_vector(self, filepath: str) -> List[float]:
        rep = self.analyze_file(filepath)
        return rep.get("ml_feature_vector", [0.0] * 12)

    def _python_fallback_analyze(self, data: bytes, name: str) -> Dict[str, Any]:
        entropy = self.calculate_entropy(data)
        is_pe = (len(data) >= 64 and data[:2] == b"MZ")
        is_elf = (len(data) >= 4 and data[:4] == b"\x7fELF")
        is_packed = entropy > 7.15

        # Extract printable ascii strings
        strings = []
        cur = []
        for b in data:
            if 32 <= b <= 126:
                cur.append(chr(b))
            else:
                if len(cur) >= 4:
                    strings.append("".join(cur))
                cur = []
        if len(cur) >= 4:
            strings.append("".join(cur))

        # Check IOCs
        suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "WinExec"]
        detected_apis = [api for api in suspicious_apis if any(api in s for s in strings)]
        
        matches = []
        threat_score = 0
        if is_packed:
            matches.append({
                "rule_name": "Packed_Binary",
                "category": "PACKER",
                "mitre": "T1027",
                "severity": 3,
                "description": "High Shannon entropy indicates packing or encryption."
            })
            threat_score += 30

        if detected_apis:
            matches.append({
                "rule_name": "Suspicious_APIs",
                "category": "INJECTION",
                "mitre": "T1055",
                "severity": 3,
                "description": "Contains process manipulation APIs."
            })
            threat_score += 35

        return {
            "file_path": name,
            "file_size": len(data),
            "is_pe": is_pe,
            "is_elf": is_elf,
            "overall_entropy": round(entropy, 4),
            "max_window_entropy": round(entropy, 4),
            "is_packed": is_packed,
            "total_strings": len(strings),
            "ascii_strings": len(strings),
            "unicode_strings": 0,
            "avg_string_len": round(sum(len(s) for s in strings) / max(1, len(strings)), 2),
            "threat_score": min(100, threat_score),
            "ml_feature_vector": [
                min(1.0, entropy / 8.0),
                min(1.0, entropy / 8.0),
                1.0 if is_packed else 0.0,
                min(1.0, math.log10(len(data) + 1) / 10.0),
                min(1.0, math.log10(len(strings) + 1) / 6.0),
                0.2,
                min(1.0, len(detected_apis) / 10.0),
                0.0,
                1.0 if detected_apis else 0.0,
                0.0,
                0.0,
                min(1.0, threat_score / 100.0)
            ],
            "iocs": {
                "urls": [],
                "ip_addresses": [],
                "onion_domains": [],
                "suspicious_commands": [],
                "suspicious_apis": detected_apis,
                "registry_keys": [],
                "ransomware_keywords": []
            },
            "rule_matches": matches
        }


# Singleton engine instance
engine = FeatureEngineLoader()

