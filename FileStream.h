#ifndef FILESTREAM_H_INCLUDED
#define FILESTREAM_H_INCLUDED

#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <dirent.h>
#include <sstream>

#include "AES.h"
#include "CBC-MAC.h"

class FileStream {
    std::string KEY_1 = "1234567890-=qwertyuiop[]asdfghjk";
    std::string KEY_2 = "1234567890-=qwertyuiop[]asdfghjq";
    std::string KEY_3 = "1234567890-=qwertyuiop[]asdfghjk";

    CBCMAC *tag;
    AES *aes;

    std::vector<std::vector<char>> fileBlocks;

    void printBar(double load) {
        COORD p = { 0, 5 };
        SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), p );
        std::cout << "[";
        for (int j = 0; j < 10; j++) {
            std::cout << ((j < load) ? "#" : " ");
        }
        std::cout << "]";
    }
public:
    FileStream(const int keySize = AES::KEY_SIZE_256) {
        aes = new AES(keySize);
        tag = new CBCMAC(keySize);
    }
    ~FileStream() {
        delete aes;
        delete tag;
    }

    void SetKeys(std::string k1, std::string k2, std::string k3) {
        KEY_1 = k1;
        KEY_2 = k2;
        KEY_3 = k3;
    }

    void PackFile(std::string fileName) {
        std::string pack = fileName + "_pack";
        std::cout << "Pack file: " << pack << std::endl;
        if(!CreateDirectory(pack.c_str(), NULL) && ERROR_ALREADY_EXISTS != GetLastError()) {
            return;
        }

        std::ifstream fin(fileName, std::ifstream::binary);
        std::vector<char> buffer(1000000,0);

        std::streamsize s;
        while(fin.read(buffer.data(), buffer.size())) {
            s = fin.gcount();
            fileBlocks.push_back(buffer);
        }
        if (s = fin.gcount()) {
            buffer.resize(s);
            fin.read(buffer.data(), s);
            fileBlocks.push_back(buffer);
        }


        COORD p = { 0, 4 };
        SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), p );
        std::cout << "Pack...\n";
        std::ofstream fout;
        tag->SetKey(KEY_1, KEY_2);
        std::string tagStr = "";
        double step = 10.0/fileBlocks.size()+1;
        double load = 0;
        for (int i = fileBlocks.size()-1; i >= 0; i--) {
            fout.open(pack + "/" + std::to_string(i+1) + ".pk", std::ifstream::binary);
            std::string str(fileBlocks[i].begin(), fileBlocks[i].end());
            if (i != fileBlocks.size()-1) {
                str = tagStr + str;
            }
            tag->SetText(str, INPUT_TYPE::TEXT_FROM_STRING);
            tagStr = tag->GetTag();
            fout.write(str.c_str(), str.size());
            fout.close();

            load += step;
            printBar(load);
        }
        printBar(10);
        fout.open(pack + "/0.pk", std::ifstream::binary);
        fout.write(tagStr.c_str(), tagStr.size());
        fout.close();
    }

    std::string readFile(const std::string& fileName) {
        std::ifstream f(fileName);
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        std::string s(size, ' ');
        f.seekg(0);
        f.read(&s[0], size); // по стандарту можно в C++11, по факту работает и на старых компиляторах
        return s;
    }

    void UnpackFile(std::string fileName) {
        std::string unpack = fileName + ".mp3";
        std::cout << "Unpack file: " << unpack << std::endl;
        int file_count = 0;
        DIR *dp;
        struct dirent *ep;
        dp = opendir (fileName.c_str());

        if (dp != NULL)
        {
            while (ep = readdir(dp))
                file_count++;

            (void) closedir(dp);
        }
        file_count -= 2;

        std::string tagStr = "";
        tag->SetKey(KEY_1, KEY_2);
        std::ofstream fout(unpack, std::ifstream::binary);
        double step = 10.0/file_count;
        double load = 0;
        for (int i = 0; i < file_count; ++i) {
            std::string name = fileName + "/" + std::to_string(i)+".pk";
            std::string content = readFile(name);

            if (i != 0) {
                if (!tag->Check(content, INPUT_TYPE::TEXT_FROM_STRING, tagStr)) {
                    exit(-1);
                } else {
                    fout.write(i == file_count-1 ? content.c_str() : content.c_str() + 16,
                               i == file_count-1 ? content.size() : content.size() - 16);
                }
            }
            if (i != file_count-1) {
                tagStr = content.substr(0, 16);
            }
            load+=step;
            printBar(load);
        }
        printBar(10);
        fout.close();
    }

};

#endif // FILESTREAM_H_INCLUDED
