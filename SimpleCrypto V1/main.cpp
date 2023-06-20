#include <openssl/md5.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
using namespace std;

string calculateMD5Hash(const string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, input.c_str(), input.length());
    MD5_Final(digest, &context);

    stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(digest[i]);
    }

    return ss.str();
}

string calculateSHA1Hash(const string& input) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, input.c_str(), input.length());
    SHA1_Final(digest, &context);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(digest[i]);
    }

    return ss.str();
}

string calculateSHA256Hash(const string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, input.c_str(), input.length());
    SHA256_Final(digest, &context);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(digest[i]);
    }

    return ss.str();
}

int main() {
    string input;
    cout << "Enter a string: ";
    getline(cin, input);

    string md5Hash = calculateMD5Hash(input);
    string sha1Hash = calculateSHA1Hash(input);
    string sha256Hash = calculateSHA256Hash(input);

    cout << "MD5 hash: " << md5Hash << endl;
    cout << "SHA1 hash: " << sha1Hash << endl;
    cout << "SHA256 hash: " << sha256Hash << endl;

    return 0;
}
