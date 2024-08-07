#ifndef DIGESTPPX_HMAC_HPP
#define DIGESTPPX_HMAC_HPP


#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include "detail/traits.hpp"


namespace digestppX
{


template<class Hasher>
class hmac
{
public:
    hmac(Hasher& h, const std::string& key, size_t block_size, size_t hash_size)
        : h(h), block_size(block_size), hash_size(hash_size)
    {
        reset(key);
    }

    template<typename C>
    hmac(Hasher& h, const C* key, size_t key_len, size_t block_size, size_t hash_size)
        : h(h), block_size(block_size), hash_size(hash_size)
    {
        reset(key, key_len);
    }

    template<typename C, typename std::enable_if<digestpp::detail::is_byte<C>::value>::type* = nullptr>
    void reset(const C* key, size_t key_len)
    {
        reset(std::string(reinterpret_cast<const char*>(key), key_len));
    }

    void reset(const std::string& key)
    {
        h.reset();

        // Calculate K0
        auto ixor = key;
        if (ixor.size() > block_size)
        {
            h.absorb(ixor).digest(&ixor[0]);
            ixor.resize(hash_size);
            h.reset();
        }
        ixor.resize(block_size);

        // Xor with pads
        oxor = ixor;
        std::transform(ixor.begin(), ixor.end(), ixor.begin(), [](char c) { return c ^ 0x36; });
        std::transform(oxor.begin(), oxor.end(), oxor.begin(), [](char c) { return c ^ 0x5c; });

        h.absorb(ixor);
    }

    template<typename... Args>
    hmac& absorb(Args&&... args)
    {
        h.absorb(std::forward<Args>(args)...);
        return *this;
    }

    template<typename OI>
    void final(OI it)
    {
        std::string inner_hash(hash_size, 0);
        h.digest(&inner_hash[0]);
        h.reset();
        h.absorb(oxor).absorb(inner_hash).digest(it);
    }

private:
    Hasher& h;
    std::string oxor;
    size_t block_size;
    size_t hash_size;
};


}  // namespace digestppX


#endif  // DIGESTX_HMAC_HPP
