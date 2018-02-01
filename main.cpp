#include <iostream>
#include "AES.h"
#include "CBC-MAC.h"
#include "FileStream.h"
#include "bass.h"

using namespace std;

std::ifstream::pos_type filesize(const char* filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

int main() {
    FileStream fs;

    int action = -1;
    cout << "Enter action 0 - pack, 1 - unpack: ";
    cin >> action;
    cout << "Enter filename: ";
    std::string filename;
    cin >> filename;
    if (action == 0) {
        if (HIWORD(BASS_GetVersion())!=BASSVERSION) {
            return 1;
        }
        if (!BASS_Init (-1, 22050, BASS_DEVICE_3D , 0, NULL)) {
            return 1;
        }

        HSTREAM stream;
        stream = BASS_StreamCreateFile(FALSE, filename.c_str(), 0, 0, 0);
        if (!stream) {
            return -1;
        }

        QWORD len = BASS_ChannelGetLength(stream, BASS_POS_BYTE);
        double time = BASS_ChannelBytes2Seconds(stream, len);
        int timeInByte = filesize(filename.c_str());
        cout << "TIME: " << time << " sec.\n";
        cout << "Set buffer in seconds: ";
        double buf = 0;
        cin >> buf;
        int bufInByte = timeInByte * buf / time;

        if (buf > 0) {
            fs.bufferInByte = bufInByte;
        }
        BASS_ChannelStop(stream);
        BASS_StreamFree(stream);
        BASS_Free();

        fs.PackFile(filename);
    } else if (action == 1) {
        fs.UnpackFile(filename);
    }



    /*AES aes(AES::KEY_SIZE_256);
    aes.SetText("input.txt", TEXT_FROM_FILE);
    aes.SetKey("1234567890-=qwertyuiop[]asdfghjk");
    //aes.KeyExpansion();

    aes.Encode();
    //aes.PrintOut();

    aes.CopyText();
    cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";
    aes.Decode();
    //aes.PrintOut();


    CBCMAC mac(AES::KEY_SIZE_256);
    mac.SetText("input.txt", TEXT_FROM_FILE);
    mac.SetKey("1234567890-=qwertyuiop[]asdfghjk", "qazwsxedcrfvtgbyqazwsxedcrfvtgby");
    string tag = mac.GetTag();
    //cout << tag;
    cout << "################" << endl;

    cout << mac.Check("input1.txt", TEXT_FROM_FILE, tag);*/
    return 0;
}
