#pragma once
#include "../Definitions.h"
#include <blake3.h>
#include <memory>

namespace TG::Wrapper
{
	//! Generates a Blake3 hash,
	//! @return Either the hash or an error value
	std::expected<std::vector<std::uint8_t>, TG_STATUS> GenerateHash(const std::vector<std::uint8_t>& Data);



}

namespace TG::Hashing
{
	class BlakeHash
	{
	public:
		BlakeHash();
		~BlakeHash();

		void Update(std::vector<std::uint8_t>& data) const;
		void Update(void* data, size_t size) const;
		std::vector<std::uint8_t> Finalize() const;

	private:
		std::unique_ptr<blake3_hasher> m_pHasher = nullptr;
	};

}
