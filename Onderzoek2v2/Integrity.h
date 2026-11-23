#pragma once
#include <string>
#include <hmac.h>
#include <cmac.h>
#include <evp.h>

class Integrity {
public:
    Integrity(const std::string& key);
    ~Integrity() = default;

    std::string computeHMAC_SHA256(const std::string& message);
    std::string computeCMAC(const std::string& message);
    std::string computePoly1305(const std::string& message);

private:
    std::string secret_key;
};