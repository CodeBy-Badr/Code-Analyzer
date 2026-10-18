CC ?= gcc
CXX ?= g++
CFLAGS ?= -O2 -Wall -fPIC
CXXFLAGS ?= -O3 -Wall -std=c++17 -fPIC

C_SRC = c_agent/src/pe_parser.c c_agent/src/elf_parser.c c_agent/src/ipc_transport.c c_agent/src/fs_monitor.c c_agent/src/main.c
CPP_SRC = cpp_engine/src/entropy_calculator.cpp cpp_engine/src/string_tokenizer.cpp cpp_engine/src/signature_detector.cpp cpp_engine/src/binary_feature_extractor.cpp cpp_engine/src/c_bindings.cpp

PYBIND_INCLUDES = $(shell python -m pybind11 --includes 2>/dev/null)
EXT_SUFFIX = $(shell python -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))" 2>/dev/null)

all: c_agent_bin cpp_dll pybind_ext samples_bin

c_agent_bin:
	$(CC) $(CFLAGS) -I c_agent/include $(C_SRC) -o c_agent/c_agent

cpp_dll:
	$(CXX) $(CXXFLAGS) -shared -I cpp_engine/include $(CPP_SRC) -o cpp_engine/libfeatures_engine.so

pybind_ext:
	$(CXX) $(CXXFLAGS) -shared -I cpp_engine/include $(PYBIND_INCLUDES) cpp_engine/src/entropy_calculator.cpp cpp_engine/src/string_tokenizer.cpp cpp_engine/src/signature_detector.cpp cpp_engine/src/binary_feature_extractor.cpp cpp_engine/src/pybind_module.cpp -o cpp_engine/feature_engine$(EXT_SUFFIX)

samples_bin:
	$(CC) -O2 samples/clean_utility.c -o samples/clean_utility
	$(CC) -O2 samples/simulated_packer.c -o samples/simulated_packer

clean:
	rm -f c_agent/c_agent c_agent/c_agent.exe cpp_engine/*.so cpp_engine/*.dll cpp_engine/*.pyd samples/*.exe samples/clean_utility samples/simulated_packer

.PHONY: all c_agent_bin cpp_dll pybind_ext samples_bin clean

