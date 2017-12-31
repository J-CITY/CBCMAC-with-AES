#include <iostream>
#include "AES.h"
#include "CBC-MAC.h"
#include "FileStream.h"

using namespace std;

int main() {
    FileStream fs;

   // fs.PackFile("in1.mp3");
    fs.UnpackFile("in1.mp3_pack");

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
