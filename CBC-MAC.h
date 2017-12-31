#ifndef CBC-MAC_H_INCLUDED
#define CBC-MAC_H_INCLUDED

#include "AES.h"
class CBCMAC {
    AES *encryptEngine;
    std::string key1="", key2="";
public:
    CBCMAC(const int keySize = AES::KEY_SIZE_256) {
        encryptEngine = new AES(keySize);
    }
    ~CBCMAC() {
        delete encryptEngine;
    }

    void SetText(std::string input, INPUT_TYPE type = TEXT_FROM_FILE) {
        encryptEngine->SetText(input, type);
    }

    void SetKey(std::string k1, std::string k2) {
        key1 = k1;
        key2 = k2;
        //encryptEngine.SetKey(k);
    }

    void GenerateKey() {
        for (int i = 0; i < encryptEngine->GetKeySize(); i++) {
            key1 += (unsigned char)(32 + rand() % 94);
            key2 += (unsigned char)(32 + rand() % 94);
        }
    }

    std::string GetTag() {
        encryptEngine->SetKey(key1);
        encryptEngine->KeyExpansion();

        std::string state = "0000000000000000";

        for (auto i = 0; i < encryptEngine->text.size(); ++i) {
            //for (auto j = 0; j < encryptEngine.BLOCK_SIZE; ++j) {
            //    state[j] ^= encryptEngine.text[i][j];
            //}
            state = XOR(state, encryptEngine->text[i]);
            state = encryptEngine->EncodeBlock(state);
        }
        encryptEngine->SetKey(key2);
        encryptEngine->KeyExpansion();
        state = encryptEngine->EncodeBlock(state);
        return state;
    }

    bool Check(std::string input, INPUT_TYPE type = TEXT_FROM_FILE, std::string tag = "") {
        SetText(input, type);
        std::string s = GetTag();
        return s == tag;
    }

private:
    std::string XOR(std::string s1, std::string s2) {
        std::string res;
        for (auto j = 0; j < encryptEngine->BLOCK_SIZE; ++j) {
            res += s1[j] ^ s2[j];
        }
        return res;
    }
};

#endif // CBC-MAC_H_INCLUDED
