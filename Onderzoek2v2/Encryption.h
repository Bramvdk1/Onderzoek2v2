#pragma once
// Encryption.h - header-only
// Bevat AES-256-CBC (Windows CNG / BCrypt), ChaCha20 (eigen implementatie, uit Client1.cpp)
// en RSA-2048 OAEP (OpenSSL 3.x EVP-API). Definieer NO_OPENSSL om RSA weg te laten.

#include <winsock2.h>   // vóór windows.h
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef NO_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>   // alleen voor RSA_PKCS1_OAEP_PADDING en de EVP_PKEY_CTX_set_rsa_* macro's
#endif

#pragma comment(lib, "bcrypt.lib")

class Encryption {
public:
    // Standaard testsleutels (zoals in je clients). Geef eigen sleutels mee indien gewenst.
    Encryption() {
        for (int i = 0; i < 32; ++i) aesKey_[i] = chachaKey_[i] = static_cast<BYTE>(i + 1);
        for (int i = 0; i < 16; ++i) aesIv_[i] = static_cast<BYTE>((i + 1) * 10);
    }

    // ------------------------------------------------------------------
    //  AES-256-CBC
    // ------------------------------------------------------------------
    std::string aesEncrypt(const std::string& plain) const {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        DWORD keyObjLen = 0, dataLen = 0, encLen = 0;
        PUCHAR keyObj = nullptr;
        PUCHAR enc = nullptr;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(DWORD), &dataLen, 0);

        keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
        BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen,
            (PUCHAR)aesKey_, sizeof(aesKey_), 0);

        // CBC past de IV in-place aan, dus per aanroep een verse kopie gebruiken
        BYTE iv[16];
        memcpy(iv, aesIv_, sizeof(iv));
        BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(), nullptr,
            iv, sizeof(iv), nullptr, 0, &encLen, BCRYPT_BLOCK_PADDING);

        enc = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, encLen);

        memcpy(iv, aesIv_, sizeof(iv));
        BCryptEncrypt(hKey, (PUCHAR)plain.data(), (ULONG)plain.size(), nullptr,
            iv, sizeof(iv), enc, encLen, &dataLen, BCRYPT_BLOCK_PADDING);

        std::string out((char*)enc, dataLen);

        if (enc) HeapFree(GetProcessHeap(), 0, enc);
        if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return out;
    }

    std::string aesDecrypt(const std::string& cipher) const {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        DWORD keyObjLen = 0, dataLen = 0, decLen = 0;
        PUCHAR keyObj = nullptr;
        PUCHAR dec = nullptr;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(DWORD), &dataLen, 0);

        keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyObjLen);
        BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, keyObjLen,
            (PUCHAR)aesKey_, sizeof(aesKey_), 0);

        BYTE iv[16];
        memcpy(iv, aesIv_, sizeof(iv));
        BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(), nullptr,
            iv, sizeof(iv), nullptr, 0, &decLen, BCRYPT_BLOCK_PADDING);

        dec = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, decLen);

        memcpy(iv, aesIv_, sizeof(iv));
        BCryptDecrypt(hKey, (PUCHAR)cipher.data(), (ULONG)cipher.size(), nullptr,
            iv, sizeof(iv), dec, decLen, &dataLen, BCRYPT_BLOCK_PADDING);

        std::string out((char*)dec, dataLen);

        if (dec) HeapFree(GetProcessHeap(), 0, dec);
        if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return out;
    }

    // ------------------------------------------------------------------
    //  ChaCha20   -   formaat: [12-byte nonce][ciphertext]
    // ------------------------------------------------------------------
    std::string chacha20Encrypt(const std::string& plain) const {
        BYTE nonce[12];
        NTSTATUS st = BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (st != 0) return std::string();

        std::vector<BYTE> cipher(plain.size());
        chacha20XorStream(chachaKey_, nonce, 1, (const BYTE*)plain.data(), cipher.data(), plain.size());

        std::string out;
        out.reserve(12 + cipher.size());
        out.append((char*)nonce, 12);
        out.append((char*)cipher.data(), cipher.size());

        SecureZeroMemory(cipher.data(), cipher.size());
        return out;
    }

    std::string chacha20Decrypt(const std::string& cipher) const {
        if (cipher.size() < 12) return std::string();
        const BYTE* nonce = (const BYTE*)cipher.data();
        const BYTE* ct = (const BYTE*)cipher.data() + 12;
        size_t ctlen = cipher.size() - 12;

        std::vector<BYTE> plain(ctlen);
        chacha20XorStream(chachaKey_, nonce, 1, ct, plain.data(), ctlen);
        std::string out((char*)plain.data(), ctlen);

        SecureZeroMemory(plain.data(), plain.size());
        return out;
    }

#ifndef NO_OPENSSL
    // ------------------------------------------------------------------
    //  RSA-2048 met OAEP-padding (SHA-256), via OpenSSL 3.x EVP-API
    //  Versleutelt met de publieke sleutel, ontsleutelt met de private sleutel.
    //  Maximale invoer: 256 - 2*32 - 2 = 190 bytes. Uitvoer is altijd 256 bytes.
    // ------------------------------------------------------------------

    // Maakt een nieuw sleutelpaar (duurt ca. 0,1 - 1 s). Wordt automatisch aangeroepen bij het
    // eerste gebruik van rsaEncrypt/rsaDecrypt, maar je kunt het ook vooraf doen.
    void rsaGenerateKey(unsigned int bits = 2048) {
        EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(bits));
        if (!raw) throw std::runtime_error("RSA: sleutelgeneratie mislukt" + opensslError());
        rsaKey_.reset(raw);
    }

    size_t rsaMaxPlainSize() {
        ensureRsaKey();
        return static_cast<size_t>(EVP_PKEY_get_size(rsaKey_.get())) - 2 * 32 - 2;
    }

    std::string rsaEncrypt(const std::string& plain) {
        if (plain.size() > rsaMaxPlainSize())
            throw std::runtime_error("RSA: bericht te lang (max " + std::to_string(rsaMaxPlainSize()) + " bytes)");

        RsaCtxPtr ctx = makeRsaCtx();
        if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) throw std::runtime_error("RSA: encrypt_init mislukt" + opensslError());
        setOaep(ctx.get());

        const unsigned char* in = reinterpret_cast<const unsigned char*>(plain.data());

        // 1e aanroep: grootte van de uitvoer opvragen, 2e aanroep: echt versleutelen
        size_t outLen = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outLen, in, plain.size()) <= 0)
            throw std::runtime_error("RSA: encrypt (grootte) mislukt" + opensslError());

        std::vector<unsigned char> out(outLen);
        if (EVP_PKEY_encrypt(ctx.get(), out.data(), &outLen, in, plain.size()) <= 0)
            throw std::runtime_error("RSA: encrypt mislukt" + opensslError());

        return std::string(reinterpret_cast<char*>(out.data()), outLen);
    }

    // Gooit een exception als het bericht beschadigd is of de padding niet klopt.
    std::string rsaDecrypt(const std::string& cipher) {
        RsaCtxPtr ctx = makeRsaCtx();
        if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) throw std::runtime_error("RSA: decrypt_init mislukt" + opensslError());
        setOaep(ctx.get());

        const unsigned char* in = reinterpret_cast<const unsigned char*>(cipher.data());

        size_t outLen = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outLen, in, cipher.size()) <= 0)
            throw std::runtime_error("RSA: decrypt (grootte) mislukt" + opensslError());

        std::vector<unsigned char> out(outLen);
        if (EVP_PKEY_decrypt(ctx.get(), out.data(), &outLen, in, cipher.size()) <= 0)
            throw std::runtime_error("RSA: decrypt mislukt (verkeerde sleutel of beschadigd bericht)" + opensslError());

        std::string result(reinterpret_cast<char*>(out.data()), outLen);
        OPENSSL_cleanse(out.data(), out.size());
        return result;
    }
#endif // NO_OPENSSL

private:
    BYTE aesKey_[32];
    BYTE aesIv_[16];
    BYTE chachaKey_[32];

#ifndef NO_OPENSSL
    // --- RSA interne hulpmiddelen ---
    // unique_ptr's met OpenSSL-deleters: alles wordt automatisch opgeruimd, ook bij een exception
    struct RsaKeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
    struct RsaCtxDeleter { void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); } };
    using RsaKeyPtr = std::unique_ptr<EVP_PKEY, RsaKeyDeleter>;
    using RsaCtxPtr = std::unique_ptr<EVP_PKEY_CTX, RsaCtxDeleter>;

    RsaKeyPtr rsaKey_;   // bevat zowel publieke als private sleutel; leeg tot eerste gebruik

    void ensureRsaKey() {
        if (!rsaKey_) rsaGenerateKey();
    }

    RsaCtxPtr makeRsaCtx() {
        ensureRsaKey();
        RsaCtxPtr ctx(EVP_PKEY_CTX_new(rsaKey_.get(), nullptr));
        if (!ctx) throw std::runtime_error("RSA: EVP_PKEY_CTX_new mislukt" + opensslError());
        return ctx;
    }

    // OAEP met SHA-256 (zowel voor de hash als voor MGF1)
    static void setOaep(EVP_PKEY_CTX* ctx) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
            throw std::runtime_error("RSA: OAEP-instellingen mislukt" + opensslError());
    }

    // Laatste OpenSSL-foutmelding als tekst (": ..." of leeg)
    static std::string opensslError() {
        unsigned long err = ERR_get_error();
        if (!err) return std::string();
        char buf[256] = { 0 };
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(": ") + buf;
    }
#endif // NO_OPENSSL

    // --- ChaCha20 interne functies ---
    static uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    static void chacha20Block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], BYTE out[64]) {
        static const uint32_t constants[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        uint32_t state[16];
        uint32_t working[16];
        for (int i = 0; i < 4; ++i) state[i] = constants[i];
        for (int i = 0; i < 8; ++i) state[4 + i] = key[i];
        state[12] = counter;
        state[13] = nonce[0];
        state[14] = nonce[1];
        state[15] = nonce[2];

        memcpy(working, state, sizeof(state));

        for (int i = 0; i < 10; ++i) {
            quarterRound(working[0], working[4], working[8], working[12]);
            quarterRound(working[1], working[5], working[9], working[13]);
            quarterRound(working[2], working[6], working[10], working[14]);
            quarterRound(working[3], working[7], working[11], working[15]);
            quarterRound(working[0], working[5], working[10], working[15]);
            quarterRound(working[1], working[6], working[11], working[12]);
            quarterRound(working[2], working[7], working[8], working[13]);
            quarterRound(working[3], working[4], working[9], working[14]);
        }

        for (int i = 0; i < 16; ++i) {
            uint32_t res = working[i] + state[i];
            out[i * 4 + 0] = (BYTE)(res & 0xff);
            out[i * 4 + 1] = (BYTE)((res >> 8) & 0xff);
            out[i * 4 + 2] = (BYTE)((res >> 16) & 0xff);
            out[i * 4 + 3] = (BYTE)((res >> 24) & 0xff);
        }
    }

    static void chacha20XorStream(const BYTE key32[32], const BYTE nonce12[12], uint32_t counter,
        const BYTE* in, BYTE* out, size_t len) {
        uint32_t keyWords[8];
        uint32_t nonceWords[3];

        for (int i = 0; i < 8; ++i) {
            keyWords[i] = (uint32_t)key32[i * 4 + 0]
                | ((uint32_t)key32[i * 4 + 1] << 8)
                | ((uint32_t)key32[i * 4 + 2] << 16)
                | ((uint32_t)key32[i * 4 + 3] << 24);
        }
        for (int i = 0; i < 3; ++i) {
            nonceWords[i] = (uint32_t)nonce12[i * 4 + 0]
                | ((uint32_t)nonce12[i * 4 + 1] << 8)
                | ((uint32_t)nonce12[i * 4 + 2] << 16)
                | ((uint32_t)nonce12[i * 4 + 3] << 24);
        }

        BYTE block[64];
        size_t offset = 0;
        uint32_t ctr = counter;

        while (offset < len) {
            chacha20Block(keyWords, ctr, nonceWords, block);
            size_t chunk = (len - offset > 64) ? 64 : (len - offset);
            for (size_t i = 0; i < chunk; ++i)
                out[offset + i] = in[offset + i] ^ block[i];
            offset += chunk;
            ++ctr;
        }

        SecureZeroMemory(block, sizeof(block));
        SecureZeroMemory(keyWords, sizeof(keyWords));
        SecureZeroMemory(nonceWords, sizeof(nonceWords));
    }
};