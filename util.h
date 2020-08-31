#pragma once

#include <cstdint>
#include <cstddef>

namespace SigScan {
	uintptr_t scanPattern ( std::uint8_t* base , const std::size_t size , char* pattern , char* mask );
	std::uintptr_t Dereference ( std::uintptr_t address , std::uint32_t offset );
}