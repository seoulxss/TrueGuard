#include "Hashing.h"

std::expected<std::vector<std::uint8_t>, TG::TG_STATUS> TG::Wrapper::GenerateHash(const std::vector<std::uint8_t>& Data)
{
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, Data.data(), Data.size());
	uint8_t output[BLAKE3_OUT_LEN];
	blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
	std::vector<std::uint8_t> out;

	for (uint8_t& i : output)
		out.emplace_back(i);

	return out;
}

TG::Hashing::BlakeHash::BlakeHash()
{
	m_pHasher = std::make_unique<blake3_hasher>();
}

TG::Hashing::BlakeHash::~BlakeHash()
{
	m_pHasher.reset();
}

void TG::Hashing::BlakeHash::Update(const std::vector<std::uint8_t>& data) const
{
	blake3_hasher_update(m_pHasher.get(), data.data(), data.size());
}

void TG::Hashing::BlakeHash::Update(const void* data, const size_t size) const
{
	blake3_hasher_update(m_pHasher.get(), data, size);
}

std::vector<std::uint8_t> TG::Hashing::BlakeHash::Finalize() const
{
	std::vector<std::uint8_t> out(BLAKE3_OUT_LEN);
	blake3_hasher_finalize(m_pHasher.get(), out.data(), out.size());
	return out;
}
