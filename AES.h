#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include <string>
#include <vector>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <map>
#include <cstdlib>
enum INPUT_TYPE {TEXT_FROM_FILE, TEXT_FROM_STRING};


const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
const unsigned char sboxinv[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};



class AES {
public:
    std::vector<std::string> text;
    std::vector<std::string> textOut;
    const static int BLOCK_SIZE = 16;

    const static int KEY_SIZE_128 = 16;
    const static int KEY_SIZE_192 = 24;
    const static int KEY_SIZE_256 = 32;

    const static int Nb = 4;

    const static int Nk_128 = 4;
    const static int Nk_192 = 6;
    const static int Nk_256 = 8;

    const static int Nr_128 = 10;
    const static int Nr_192 = 12;
    const static int Nr_256 = 14;

private:
    int Nk = 8;
    int Nr = 14;
    int KEY_SIZE = 32;

    std::vector<unsigned char> key;
    std::vector<uint32_t> w;
public:
    AES(const int type = AES::KEY_SIZE_256) {
        SetKeySize(type);
    }

    AES() {}

    int GetKeySize() {
        return KEY_SIZE;
    }
    int GetNr() {
        return Nr;
    }
    int GetNk() {
        return Nk;
    }
    int GetNb() {
        return Nb;
    }

    void SetKeySize(int type = KEY_SIZE_256) {
        if (type == KEY_SIZE_128) {
            Nk = 4;
            Nr = 10;
            KEY_SIZE = 16;
        } else if (type == KEY_SIZE_192) {
            Nk = 6;
            Nr = 12;
            KEY_SIZE = 24;
        } else if (type == KEY_SIZE_256) {
            Nk = 8;
            Nr = 14;
            KEY_SIZE = 32;
        }
    }

    void SetText(std::string input, INPUT_TYPE type = TEXT_FROM_FILE) {
        if (type == TEXT_FROM_FILE) {
            SetTextFromFile(input);
        } else if (type == TEXT_FROM_STRING) {
            SetTextFromString(input) ;
        }
    }

    void CopyText() {
        text.clear();
        for (auto i = 0; i < textOut.size(); ++i) {
            text.push_back(textOut[i]);
        }
    }

    void PrintOut() {
        for (auto i = 0; i < textOut.size(); ++i) {
            std::cout << textOut[i] << std::endl;
        }
    }

    void GenKey() {
        for (int i = 0; i < KEY_SIZE; i++) {
            key.push_back(32 + rand() % 94);
        }
        std::ofstream stream ("key.txt");
        for(int i = 0; i < key.size(); ++i) {
            stream << key[i];
        }
    }

    void SetKey(std::string k) {
        if (k.size() < KEY_SIZE) {
            std::cout <<"ERROR: bad key size.\n";
            return;
        }
        key.clear();
        for (int i = 0; i < KEY_SIZE; i++) {
            key.push_back(k[i]);
        }
    }

    void Encode() {
        textOut.clear();

        KeyExpansion();
        for (auto i = 0; i < text.size(); ++i) {
            textOut.push_back(EncodeBlock(text[i]));
        }
    }

    std::string EncodeBlock(std::string in) {
        std::vector<unsigned char> state;
        for (int i = 0; i < in.size(); ++i) {
            state.push_back(in[i]);
        }

        state = AddRoutnKey(state, 0);

        for (auto i = 1; i <= Nr-2; ++i) {
            state = SubByte(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoutnKey(state, i*Nb);
        }

        state = SubByte(state);
        state = ShiftRows(state);
        state = AddRoutnKey(state, (Nr-1)*Nb);

        std::string res = "";
        for (int i = 0; i < state.size(); ++i) {
            res += state[i];
        }
        return res;
    }

    void Decode() {
        textOut.clear();

        KeyExpansion();
        for (auto i = 0; i < text.size(); ++i) {
            textOut.push_back(DecodeBlock(text[i]));
        }
    }

    std::string DecodeBlock(std::string in) {
        std::vector<unsigned char> state;
        for (int i = 0; i < in.size(); ++i) {
            state.push_back(in[i]);
        }

        state = AddRoutnKey(state, (Nr-1)*Nb);

        for (auto i = Nr-2; i >= 1; --i) {
            state = ShiftRowsInv(state);
            state = SubByteInv(state);
            state = AddRoutnKey(state, i*Nb);
            state = MixColumnsInv(state);
        }

        state = ShiftRowsInv(state);
        state = SubByteInv(state);
        state = AddRoutnKey(state, 0);

        std::string res = "";
        for (int i = 0; i < state.size(); ++i) {
            res += state[i];
        }
        return res;
    }

    void KeyExpansion() {
        //for (int i = 0;i<key.size(); ++i)
        //    std::cout << key[i] << " ";
        //std::cout <<std::endl;
        w.clear();
        w.resize(Nb * (Nr+1));
        int i = 0;
        while (i < Nk) {
            w[i] = FourCharToInt(key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]);
            i++;
        }

        i = Nk;
        uint32_t temp;
        while (i < Nb * (Nr + 1)) {
            temp = w[i];
            if (i % Nk == 0) {
                temp = SubWord(RotWord(temp)) ^ Rcon(i / Nk);
            } else if (Nk > 6 && i % Nk == 4) {
                temp = SubWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
            ++i;
        }
        //for (int i = 0;i<w.size(); ++i) {
        //    std::cout << w[i] << " ";
        //}
        //std::cout <<std::endl;
    }
private:
    void SetTextFromFile(std::string input) {
        std::string str;
        std::ifstream t(input);

        t.seekg(0, std::ios::end);
        str.reserve(t.tellg());
        t.seekg(0, std::ios::beg);

        str.assign((std::istreambuf_iterator<char>(t)),
                    std::istreambuf_iterator<char>());
        Split(str);
    }

    void SetTextFromString(std::string input) {
        Split(input);
    }

    void Split(std::string input) {
        text.clear();
        int i = 0;
        while (i < input.size()) {
            text.push_back(input.substr(i, BLOCK_SIZE));
            i += BLOCK_SIZE;
            if (text[text.size()-1].size() < BLOCK_SIZE) {
                while (text[text.size()-1].size() < BLOCK_SIZE) {
                    text[text.size()-1] += char(0);
                }
            }
        }

        //for (int j = 0; j < text.size(); ++j) {
        //    std::cout << text[j] << std::endl;
        //}
    }

    uint32_t FourCharToInt(std::vector<unsigned char> chars) {
        uint32_t res = 0;
        res = chars[0];
        res |=  chars[1] << 8;
        res |=  chars[2] << 16;
        res |=  chars[3] << 24;
        return res;
    }

    uint32_t FourCharToInt(unsigned char char0, unsigned char char1,
                           unsigned char char2, unsigned char char3) {
        uint32_t res = 0;
        res = char0;
        res |=  char1 << 8;
        res |=  char2 << 16;
        res |=  char3 << 24;
        return res;
    }

    std::vector<unsigned char> IntToFourChar(uint32_t ints) {
        std::vector<unsigned char> chars(4);
        chars[0] = (unsigned char)ints;
        chars[1] = (unsigned char)(ints >> 8);
        chars[2] = (unsigned char)(ints >> 16);
        chars[3] = (unsigned char)(ints >> 24);
        return chars;
    }

    uint32_t RotWord(uint32_t in) {
        std::vector<unsigned char> ch = IntToFourChar(in);
        ch.push_back(ch[0]);
        ch.erase(ch.begin());
        return FourCharToInt(ch);
    }

    uint32_t SubWord(uint32_t in) {
        std::vector<unsigned char> ch = IntToFourChar(in);
        ch[0] = sbox[ch[0]];
        ch[1] = sbox[ch[1]];
        ch[2] = sbox[ch[2]];
        ch[3] = sbox[ch[3]];
        return FourCharToInt(ch);
    }

    uint32_t Rcon(uint32_t in) {
        std::map<uint32_t, uint32_t> powerOfX = {
            { 0, 0x01},
            { 1, 0x02},
            { 2, 0x04},
            { 3, 0x08},
            { 4, 0x10},
            { 5, 0x20},
            { 6, 0x40},
            { 7, 0x80},
            { 8, 0x1b},
            { 9, 0x36},
            {10, 0x6c},
            {11, 0xd8},
            {12, 0xab},
            {13, 0x4d},
            {14, 0x9a}
        };
        return FourCharToInt(powerOfX[in], 0, 0, 0);
    }

    std::vector<unsigned char> AddRoutnKey(std::vector<unsigned char> state, int rk) {
        std::vector<unsigned char> res;
        res.resize(16);
        for (auto i = 0; i < 16; ++i) {
            res[i] = state[i] ^ w[rk+i%4];
        }
        return res;
    }

    std::vector<unsigned char> SubByte(std::vector<unsigned char> state) {
        for (auto i = 0; i < 16; ++i) {
            state[i] = sbox[state[i]];
        }
        return state;
    }

    std::vector<unsigned char> SubByteInv(std::vector<unsigned char> state) {
        for (auto i = 0; i < 16; ++i) {
            state[i] = sboxinv[state[i]];
        }
        return state;
    }

    std::vector<unsigned char> ShiftRows(std::vector<unsigned char> state) {
        std::vector<unsigned char> res;
        res.resize(16);

        res[0]  = state[0];  res[1]  = state[1];  res[2]  = state[2];  res[3]  = state[3];
        res[4]  = state[5];  res[5]  = state[6];  res[6]  = state[7];  res[7]  = state[4];
        res[8]  = state[10]; res[9]  = state[11]; res[10] = state[8];  res[11] = state[9];
        res[12] = state[15]; res[13] = state[12]; res[14] = state[13]; res[15] = state[14];
        return res;
    }

    std::vector<unsigned char> ShiftRowsInv(std::vector<unsigned char> state) {
        std::vector<unsigned char> res;
        res.resize(16);

        res[0]  = state[0];  res[1]  = state[1];  res[2]  = state[2];  res[3]  = state[3];
        res[4]  = state[7];  res[5]  = state[4];  res[6]  = state[5];  res[7]  = state[6];
        res[8]  = state[10]; res[9]  = state[11]; res[10] = state[8];  res[11] = state[9];
        res[12] = state[13]; res[13] = state[14]; res[14] = state[15]; res[15] = state[12];
        return res;
    }

    std::vector<unsigned char> MixColumns(std::vector<unsigned char> state) {
        unsigned char i, a, b, c, d, e;

        for (i = 0; i < 16; i += 4) {
            a = state[i];
            b = state[i + 1];
            c = state[i + 2];
            d = state[i + 3];

            e = a ^ b ^ c ^ d;

            state[i    ] ^= e ^ rj_xtime(a^b);
            state[i + 1] ^= e ^ rj_xtime(b^c);
            state[i + 2] ^= e ^ rj_xtime(c^d);
            state[i + 3] ^= e ^ rj_xtime(d^a);
        }
        return state;
    }

    std::vector<unsigned char> MixColumnsInv(std::vector<unsigned char> state) {
        unsigned char i, a, b, c, d, e, x, y, z;

        for (i = 0; i < 16; i += 4) {
            a = state[i];
            b = state[i + 1];
            c = state[i + 2];
            d = state[i + 3];

            e = a ^ b ^ c ^ d;
            z = rj_xtime(e);
            x = e ^ rj_xtime(rj_xtime(z^a^c));
            y = e ^ rj_xtime(rj_xtime(z^b^d));

            state[i    ] ^= x ^ rj_xtime(a^b);
            state[i + 1] ^= y ^ rj_xtime(b^c);
            state[i + 2] ^= x ^ rj_xtime(c^d);
            state[i + 3] ^= y ^ rj_xtime(d^a);
        }
        return state;
    }

    inline unsigned char rj_xtime(unsigned char x) {
        return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
    }
};



#endif // AES_H_INCLUDED
