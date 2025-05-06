#include "raptor.h"

bool chain = false;

std::vector<BYTE>  AssemblyToHex(const std::string& asm_code) {

    if (asm_code == "") {
        std::cout << "God sake enter something!?!?!?!?\n";
        exit(1);
    }

    XEDPARSE parse;
    RtlZeroMemory(&parse, sizeof(parse));
    parse.x64 = true;  // 64-bit
    std::vector<BYTE> pattern = { };  // Search pattern  such 48 89 e0

    //std::cout << "Sended Assembly Code: " << asm_code << std::endl;
    std::vector<std::string> commands = SplitAssemblyCode(asm_code);

    //std::cout << "Filtered:\n";
    for (const auto& cmd : commands) {
        RtlCopyMemory(parse.instr, cmd.data(), cmd.length());
        //printf("This is your asm code :blink:  -> %s\t", parse.instr);

        if (XEDParseAssemble(&parse) == XEDPARSE_OK) {
            // machine code to HEX
            std::string hex_result;
            for (size_t i = 0; i < parse.dest_size; i++) {
                char buffer[3];
                snprintf(buffer, sizeof(buffer), "%02X", parse.dest[i]);
                hex_result += buffer;
                hex_result += " ";

                memset(parse.instr, 0, sizeof(parse.instr));
            }

            //std::cout<<"Hex's here !?!?!?! -> " << std::hex << hex_result << std::endl;

            for (size_t i = 0; i < parse.dest_size; i++) {
                std::string byteStr = hex_result.substr(i * 3, 2); 
                BYTE byteValue = static_cast<BYTE>(std::stoi(byteStr, nullptr, 16));
                pattern.push_back(byteValue);

            }
        }
        else {

            std::cout << "You get error ehhh " << std::endl;
            exit(1);
        }
    }

    return pattern;
}

int main(int argc, char* argv[])
{

    if (argc < 2 || argc > 3) {
        std::cout << "Usage: RopGadget.exe \"{Assembly;Assembly;Assembly}\" {TargetDriver} (Default: ntoskrnl.exe)\n";
        std::cout << "If you want to create rop chain -> RopGadget.exe chain\n\n";

        std::cout << "Example usage -> RopGadget.exe \"pop rbx;ret\" win32k.sys\n";
        if (argc > 3) {
            std::cout << "Don't, just don't...\n";
            return 1;
        }
        return 1;
    }

    if (argv[1] == (std::string)"chain") {

        std::cout << "Rop chain!?!?" << std::endl;

        chain = TRUE;

        std::cout << "Type Driver name or anything hit enter. (default driver ntoskrnl.exe)\n";
        std::string library = "";
        std::cin >> library;

        if (library.length() > MAX_PATH) {
            std::cout << "it would be better to change the driver name\n"; exit(1);
        }

        if (get_driver_path(library.c_str()) == "") {
            std::cout << "Driver couldn't founded. Default driver is loaded\n";
            library = "ntoskrnl.exe";
        }

        
        //std::cout << "Values are going to be hex, asm instruction should be divided with \";\" and \ngadgets offset will be returned in the chain. All lines are going to be 64 bit\n";

        std::string chainLine;

        std::cout << "Type \"end\" for out\n";
        std::vector<uint64_t> chainStorage;
        std::cin.ignore();

        while (TRUE) {
            std::cout << "Type asm instruction or value. asm;asm \n";
            std::string chainLine;
            std::getline(std::cin, chainLine);

            if (chainLine == "end") goto outside;

            //std::cout << "You entered: " << chainLine << std::endl;

            if (asmValidation(chainLine)) {

                // valid
                //get first gadget
                std::vector<BYTE> pattern = { };  // initialize
                pattern = AssemblyToHex((const std::string&)chainLine);
                int* firstGadgetOffset = searchPattern(library.c_str(), pattern, chainLine); // it will return first gadget's offset for all the time

                chainStorage.push_back(reinterpret_cast<uint64_t>(firstGadgetOffset));

                //std::cout << "galiba basardin\n"; // YOU DID IT BASTARD
                //for (uint64_t value : chainStorage) {
                //    std::cout << std::hex << value << std::endl;
            //}

            }
            else {

                //this is not asm code
                //chainStorage.push_back((uint64_t)chainLine.c_str());
                try {
                    chainStorage.push_back(std::stoull(chainLine, nullptr, 0));
                }
                catch (const std::exception& e) {
                    std::cout << "Invalid input or failed to parse input: " << e.what() << std::endl;
                    exit(1);
                }
            }
            std::cout << "Values added\n";

        }

    outside:

        std::cout << "Your rop chain: only driver's Offsets and Values\n\n";

        for (uint64_t value : chainStorage) {
            std::cout << "0x" << std::hex<< value << std::endl;
        }

        return 0;
    }

    else {

        //std::cout << "hop burdayım"<<std::endl<< argv[1]<<std::endl;
        std::string asm_code = argv[1];  // Assembly commands
        std::string library = (argc == 3) ? argv[2] : "ntoskrnl.exe";  // if lib entered assign it, or ntoskrnl.exe

        std::vector<BYTE> pattern = { };  // initialize

        //library = "C:\\Windows\\System32\\ntoskrnl.exe";
        //searchPattern(library.c_str());

        pattern = AssemblyToHex(asm_code);
        //std::cout << "Pattern inside: ";
        //for (BYTE byte : pattern) {
        //    std::cout << std::hex << static_cast<int>(byte) << " "; // Hex formatında yazdır
        //}
    
        searchPattern(library.c_str(), pattern, asm_code);

    }
    
    return 0;

}



std::vector<std::string> SplitAssemblyCode(const std::string& asm_code) {
    std::vector<std::string> instructions;
    std::stringstream ss(asm_code);
    std::string item;

    // Virgüle göre böl ve komutları listeye ekle
    while (std::getline(ss, item, ';')) {
        // Gereksiz boşlukları kaldır
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        instructions.push_back(item);
    }
    return instructions;
}

bool asmValidation(const std::string& asm_code) {
    if (asm_code == "") {
        std::cout << "God sake enter something!?!?!?!?\n";
        exit(1);
    }

    XEDPARSE parse;
    RtlZeroMemory(&parse, sizeof(parse));
    parse.x64 = true;  // 64-bit

    std::vector<std::string> commands = SplitAssemblyCode(asm_code);

    for (const auto& cmd : commands) {
        RtlCopyMemory(parse.instr, cmd.data(), cmd.length());


        if (XEDParseAssemble(&parse) == XEDPARSE_OK) {

            return XEDPARSE_OK;
        }
        else {
            return XEDPARSE_ERROR;
        }
    }
}