#include <digestpp.hpp>
#include <hmac.hpp>
#include <vector>

int main() {
    std::string key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    std::string data = "data";

    digestpp::sha512 h(256);
    digestppX::hmac<digestpp::sha512> hm(h, key, 1024/8, 256/8);
    uint8_t out[512/8];
    hm.absorb(data).final(out);
    return 0;
}
