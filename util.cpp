#include "util.h"

#include "NT.h"

namespace SigScan {
	std::uintptr_t scanPattern ( std::uint8_t* base , const std::size_t size , char* pattern , char* mask ) {
		const auto patternSize = strlen ( mask );

		if ( !patternSize ) { return NULL; }

		for ( std::size_t i = {}; i < size - patternSize; i++ )
		{
			for ( std::size_t j = {}; j < patternSize; j++ )
			{
				if ( mask [ j ] != '?' && *reinterpret_cast< std::uint8_t* >( base + i + j ) != static_cast< std::uint8_t >( pattern [ j ] ) )
					break;

				if ( j == patternSize - 1 )
					return reinterpret_cast< std::uintptr_t >( base ) + i;
			}
		}

		return {};
	}

	std::uintptr_t Dereference ( std::uintptr_t address , std::uint32_t offset ) {

		if ( !address ) { return NULL; }

		return address + ( int ) ( ( *( int* ) ( address + offset ) + offset ) + sizeof ( int ) );
	}
}
