#include "raptor.h"

int* searchPattern(const char* fileBin, std::vector<BYTE> userPattern, std::string asm_code) {

	std::string filename = get_driver_path(fileBin).c_str(); // for userland rop gadget tools give a full path of any other userland program 
	std::string outputFileName = "FoundedGadgets.txt";

	HANDLE loadFile = LoadLibraryA((LPCSTR)filename.c_str());
	if (!loadFile)
	{
		std::cout <<"Auf Wiedersehen\n";
		printf("[!] Failed to get a handle to the file - Error Code (%d)\n", GetLastError());
		CloseHandle(loadFile);
		exit(1);
	}

	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)loadFile + ((IMAGE_DOS_HEADER*)loadFile)->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	unsigned long long baseAddr = kernelAddress(fileBin); // change it with loadFile variable for userland gadgets
	if (!baseAddr) {
		std::cout << fileBin << " bulunamadý." << std::endl;
		exit(1);
	}
	


	std::ofstream filein(outputFileName, std::ios::binary);
	if (!filein) {
		std::cout << "Error opening the file for reading.";
		return nullptr;
	}

	
	std::vector<BYTE> pattern;  // Searching pattern example: 48, 89, e0  
	for (BYTE byte : userPattern) {
		pattern.push_back(byte);
	}

	if(!chain) // we are gonna put some print if it is not chain
	{

		std::cout << fileBin << " Address: 0x" << std::hex << baseAddr << std::endl << "Assembly: " << asm_code << std::endl,
			filein << fileBin << " Address: 0x" << std::hex << baseAddr << std::endl<< "Assembly: " << asm_code << std::endl;


	// Dosyanýn baþlangýç adresini ve toplam boyutunu yazdýr
	//std::cout << "Base Address: " << loadFile << std::endl;
	//std::cout << "Size of Image: " << (DWORD)ntHeaders->OptionalHeader.SizeOfImage << " bytes\n";

		std::cout <<"Hex Code: ", 
			filein << "Hex Code: ";



		for (BYTE byte : pattern) {
			std::cout << std::hex << "0x" << static_cast<int>(byte) << " ",
				filein << std::hex << "0x" << static_cast<int>(byte) << " ";
		}


		std::cout << std::endl << std::endl,
			filein << std::endl << std::endl;

	

}// no chain part is end

	bool something = 0; // something may go wrong ehehe

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			uintptr_t sectionStart = (uintptr_t)((BYTE*)loadFile + sectionHeader[i].VirtualAddress);
			size_t sectionSize = sectionHeader[i].Misc.VirtualSize;

			Section newSection;
			newSection.startAddress = sectionStart;
			newSection.length = sectionSize;


			for (size_t j = 0; j < sectionSize; j++) {
				newSection.data.push_back(*((BYTE*)sectionStart + j));
			}

			// target pattern (example 0x59, 0xC3)

			size_t patternSize = pattern.size();

			for (size_t offset = 0; offset <= sectionSize - patternSize; offset++) {
				bool match = true;

				// compare patterns
				for (size_t k = 0; k < patternSize; k++) {
					if (newSection.data[offset + k] != pattern[k]) {
						match = false;
						break;
					}
				}

				if (match) {
					something = TRUE;

					// this offset is taken from section's address, not libraries baseAddress
					//std::cout  << std::endl << "myOffset -> 0x" <<std::hex<< offset << "\t";
					//std::cout << "SectionStart -> " << sectionStart << std::endl;

					//uintptr_t foundAddress = sectionStart + offset;  // Bulunduðu adres
					//std::cout << "\nPattern found at offset: 0x" <<std::hex<< offset
					//	<< ", Address: 0x" << (void*)foundAddress << std::endl;

					// Gadget's userland address
					uintptr_t userAddress = sectionStart + offset; 
					//std::cout << "User Address: 0x" << (void*)userAddress << "\t\t" ;

					// Gadget's offset from the file's beginning
					size_t myOffset = userAddress - (size_t)loadFile;
					//std::cout << "FinalOffset -> 0x" << myOffset << "\t";

					// Gadget's kernel address
					size_t kernelAddres = myOffset + baseAddr;
					//std::cout << "kernelAddres -> 0x" << kernelAddres << std::endl;

					if (chain)
						return (int*)myOffset;

					std::cout << std::endl << "Address -> 0x" << std::hex << kernelAddres << "\t" << asm_code << "\tOffset: " << "0x" << myOffset,
						filein << std::endl << "Address -> 0x" << std::hex << kernelAddres << "\t" << asm_code << "\tOffset: " << "0x" << myOffset;

				}
			}
		}
	}


		if (!something) {
			std::cout << "Nothing founded or something went wrong. Please check your input file or change it\n ";

			if(!chain)
			filein << "Nothing Founded :/\n"; 

			exit(1);
		}

		if(!chain)
		std::cout << "\nOutput written to file " << outputFileName << std::endl;

	return nullptr;
}



unsigned long long kernelAddress(const char* driverName) {
	LPVOID drivers[1024];
	DWORD cbNeeded;

	// Get loaded drivers
	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
		int driverCount = cbNeeded / sizeof(drivers[0]);
		char driverBaseName[MAX_PATH];

		for (int i = 0; i < driverCount; i++) {
			// get name of driver
			if (GetDeviceDriverBaseNameA(drivers[i], driverBaseName, sizeof(driverBaseName))) {
				if (_stricmp(driverBaseName, driverName) == 0) {
					return (unsigned long long)drivers[i]; // address of founded driver
				}
			}
		}
	}

	return 0; // Driver not founded 

}


std::string resolve_env_variable(const std::string& path) {
	char envValue[MAX_PATH];

	std::string envVariables[] = { "SystemRoot", "ProgramFiles", "APPDATA", "TEMP", "USERPROFILE" };

	for (const auto& envVar : envVariables) {
		size_t pos = path.find(envVar);
		if (pos != std::string::npos) {
			if (GetEnvironmentVariableA(envVar.c_str(), envValue, sizeof(envValue))) {
				std::string resolvedPath = path;
				resolvedPath.replace(pos, envVar.length(), envValue);
				return resolvedPath;
			}
		}
	}
	return path; 
}




std::string get_driver_path(const char* driverName) {
	LPVOID drivers[1024];
	DWORD cbNeeded;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
		int driverCount = cbNeeded / sizeof(drivers[0]);
		char driverBaseName[MAX_PATH];
		char driverPath[MAX_PATH];

		for (int i = 0; i < driverCount; i++) {
			if (GetDeviceDriverBaseNameA(drivers[i], driverBaseName, sizeof(driverBaseName))) {
				if (_stricmp(driverBaseName, driverName) == 0) {
					if (GetDeviceDriverFileNameA(drivers[i], driverPath, sizeof(driverPath))) {
						std::string resolvedPath = resolve_env_variable(driverPath); 
						size_t backslashPos = resolvedPath.find("\\C:\\");
						if (backslashPos != std::string::npos) {
							return resolvedPath.substr(backslashPos + 1);
						}
						return resolvedPath;
					}
				}
			}
		}
	}

	std::cout << "Driver Not Founded :/\n";
	return "";
}