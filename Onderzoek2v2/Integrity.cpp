#include "Integrity.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <cctype>


#include <err.h> //vanuit libraries openssl
#include <evp.h>
#include <hmac.h>
#include <core_names.h>
#include <params.h>
void hexStringToBytes(const std::string& hex, unsigned char* out, size_t outLen) {
    if (hex.size() != outLen * 2)
        throw std::runtime_error("Invalid hex string length");

    for (size_t i = 0; i < outLen; ++i) {
        out[i] = static_cast<unsigned char>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    }
}

static bool isHexString(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) return false;
    for (unsigned char c : s) if (!std::isxdigit(c)) return false;
    return true;
}

Integrity::Integrity(const std::string& key) {
    if (isHexString(key)) {
        size_t outLen = key.size() / 2;
        if (outLen == 0) {
            secret_key.clear();
        }
        else {
            secret_key.resize(outLen);
            hexStringToBytes(key, reinterpret_cast<unsigned char*>(&secret_key[0]), outLen);
        }
    }
    else {
        secret_key = key;
    }
}

//HMAC-SH256 integrity method
std::string Integrity::computeHMAC_SHA256(const std::string& message) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    HMAC(EVP_sha256(),
        reinterpret_cast<const unsigned char*>(secret_key.data()), static_cast<int>(secret_key.size()),
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        result, &len);

    std::stringstream ss;
    for (unsigned int i = 0; i < len; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return ss.str();
}

//CMAC integrity method (AES-256)
std::string Integrity::computeCMAC(const std::string& message) {
    // Require 32 bytes for AES-256 CMAC
    if (secret_key.size() < 32) {
        throw std::runtime_error("secret_key too short for AES-256 CMAC (requires 32 bytes)");
    }

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    if (!mac) throw std::runtime_error("EVP_MAC_fetch failed for CMAC");

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");

    unsigned char key[32] = { 0 };
    memcpy(key, secret_key.data(), 32);

    // specify AES-256 cipher explicitly
    char cipher_name[] = "AES-256-CBC";
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", cipher_name, sizeof(cipher_name));
    params[1] = OSSL_PARAM_construct_octet_string("key", key, 32);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, nullptr, 0, params) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256] = { 0 };
        if (err) ERR_error_string_n(err, buf, sizeof(buf));
        EVP_MAC_CTX_free(ctx);
        std::string emsg = "EVP_MAC_init failed";
        if (buf[0]) emsg += std::string(": ") + buf;
        throw std::runtime_error(emsg);
    }

    if (EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        EVP_MAC_CTX_free(ctx);
        throw std::runtime_error("EVP_MAC_update failed");
    }

    unsigned char out[16];
    size_t outlen = sizeof(out);
    if (EVP_MAC_final(ctx, out, &outlen, sizeof(out)) <= 0) {
        EVP_MAC_CTX_free(ctx);
        throw std::runtime_error("EVP_MAC_final failed");
    }

    EVP_MAC_CTX_free(ctx);

    std::stringstream ss;
    for (size_t i = 0; i < outlen; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)out[i];

    return ss.str();
}


//Poly1305
std::string Integrity::computePoly1305(const std::string& message) {
    //std::string macHex;

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
    if (!mac) throw std::runtime_error("EVP_MAC_fetch failed for POLY1305");

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");

    unsigned char key[32] = { 0 };
    memcpy(key, secret_key.data(), std::min(secret_key.size(), size_t(32)));

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string("key", key, 32);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, nullptr, 0, params) <= 0) {
        EVP_MAC_CTX_free(ctx);
        throw std::runtime_error("EVP_MAC_init failed");
    }

    if (EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(message.data()), message.size()) <= 0) {
        EVP_MAC_CTX_free(ctx);
        throw std::runtime_error("EVP_MAC_update failed");
    }

    size_t outlen = 16;
    unsigned char out[16];
    if (EVP_MAC_final(ctx, out, &outlen, sizeof(out)) <= 0) {
        EVP_MAC_CTX_free(ctx);
        throw std::runtime_error("EVP_MAC_final failed");
    }

    EVP_MAC_CTX_free(ctx);

    std::stringstream ss;
    for (size_t i = 0; i < outlen; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)out[i];

    return ss.str();
}