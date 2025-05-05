#pragma once

#include "XEDParse.h"
//#include "Zydis/Zydis.h"
//#include "XEDParse.cpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <assert.h>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <psapi.h>


extern bool chain;


std::vector<std::string> SplitAssemblyCode(
    _In_ const std::string& asm_code
);
struct Section {
    uintptr_t startAddress;  // Section baþlangýç adresi
    size_t length;           // Section uzunluðu
    std::vector<BYTE> data;  // Hex verisini saklamak için vector
};

int* searchPattern(
    _In_ const char* fileBin,
    _In_  std::vector<BYTE> pattern,
    _In_ std::string asm_code
);


uintptr_t kernelAddress(
    _In_ const char* driverName
);

std::string get_driver_path(
    _In_ const char* driverName
);

bool asmValidation(
    _In_ const std::string& asm_code
);
