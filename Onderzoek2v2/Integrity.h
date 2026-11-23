#pragma once
// Integrity.h - header-only (Integrity.cpp is hierin opgenomen, je hoeft .cpp niet meer in het project te hebben)

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

class Integrity {
public:
    // Sleutel: hex-tekst (bv. 64 tekens = 32 bytes) of een gewone tekst.
    explicit Integrity(const std::string& key) {
        if (isHexString(key)) {
            const size_t outLen = key.size() / 2;
            secret_key.resize(outLen);
            hexStringToBytes(key, reinterpret_cast<unsigned char*>(&secret_key[0]), outLen);
        }
        else {
            secret_key = key;
        }
    }
    ~Integrity() = default;

    // HMAC-SHA256 -> 64 hex-tekens
    std::string computeHMAC_SHA256(const std::string& message) const {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int len = 0;

        HMAC(EVP_sha256(),
            secret_key.data(), static_cast<int>(secret_key.size()),
            reinterpret_cast<const unsigned char*>(message.data()), message.size(),
            result, &len);

        return toHex(result, len);
    }

    // CMAC met AES-256 -> 32 hex-tekens (sleutel moet minstens 32 bytes zijn)
    std::string computeCMAC(const std::string& message) const {
        if (secret_key.size() < 32)
            throw std::runtime_error("secret_key too short for AES-256 CMAC (requires 32 bytes)");

        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
        if (!mac) throw std::runtime_error("EVP_MAC_fetch failed for CMAC");

        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");

        unsigned char key[32] = { 0 };
        std::memcpy(key, secret_key.data(), 32);

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

        return finishMac(ctx, message);
    }

    // Poly1305 -> 32 hex-tekens (sleutel wordt met nullen aangevuld/afgekapt tot 32 bytes)
    std::string computePoly1305(const std::string& message) const {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
        if (!mac) throw std::runtime_error("EVP_MAC_fetch failed for POLY1305");

        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");

        unsigned char key[32] = { 0 };
        std::memcpy(key, secret_key.data(), (std::min)(secret_key.size(), size_t(32)));

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_octet_string("key", key, 32);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(ctx, nullptr, 0, params) <= 0) {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_init failed");
        }

        return finishMac(ctx, message);
    }

private:
    std::string secret_key;

    // --- hulpfuncties ---
    static bool isHexString(const std::string& s) {
        if (s.empty() || (s.size() % 2) != 0) return false;
        for (unsigned char c : s)
            if (!std::isxdigit(c)) return false;
        return true;
    }

    static void hexStringToBytes(const std::string& hex, unsigned char* out, size_t outLen) {
        if (hex.size() != outLen * 2)
            throw std::runtime_error("Invalid hex string length");
        for (size_t i = 0; i < outLen; ++i)
            out[i] = static_cast<unsigned char>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    }

    static std::string toHex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        return ss.str();
    }

    // update + final + opruimen (gedeeld door CMAC en Poly1305); ctx is al geinitialiseerd
    static std::string finishMac(EVP_MAC_CTX* ctx, const std::string& message) {
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

        return toHex(out, outlen);
    }
};