#include "NT.h"

NTSTATUS Nt::findKernelModuleByName ( const char* moduleName , std::uintptr_t* moduleStart , std::size_t* moduleSize ) {
	std::size_t size {};

	ZwQuerySystemInformation ( 0xB , nullptr , size , reinterpret_cast< PULONG >( &size ) );

	const auto listHeader = ExAllocatePool ( NonPagedPool , size );
	if ( !listHeader )
		return STATUS_MEMORY_NOT_ALLOCATED;

	if ( const auto status = ZwQuerySystemInformation ( 0xB , listHeader , size , reinterpret_cast< PULONG >( &size ) ) )
		return status;

	auto currentModule = reinterpret_cast< PSYSTEM_MODULE_INFORMATION >( listHeader )->Module;
	for ( std::size_t i {}; i < reinterpret_cast< PSYSTEM_MODULE_INFORMATION >( listHeader )->Count; ++i , ++currentModule ) {
		const auto currentModuleName = reinterpret_cast< const char* >( currentModule->FullPathName + currentModule->OffsetToFileName );
		if ( !strcmp ( moduleName , currentModuleName ) ) {
			*moduleStart = reinterpret_cast< std::uintptr_t >( currentModule->ImageBase );
			*moduleSize = currentModule->ImageSize;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS Nt::findModuleExportByName ( const std::uintptr_t imageBase , const char* exportName , std::uintptr_t* functionPointer ) {
	if ( !imageBase )
		return STATUS_INVALID_PARAMETER_1;

	if ( reinterpret_cast< PIMAGE_DOS_HEADER >( imageBase )->e_magic != 0x5A4D )
		return STATUS_INVALID_IMAGE_NOT_MZ;

	const auto ntHeader = reinterpret_cast< PIMAGE_NT_HEADERS64 >( imageBase + reinterpret_cast< PIMAGE_DOS_HEADER >( imageBase )->e_lfanew );
	const auto exportDirectory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( imageBase + ntHeader->OptionalHeader.DataDirectory [ 0 ].VirtualAddress );
	if ( !exportDirectory )
		STATUS_INVALID_IMAGE_FORMAT;

	const auto exportedFunctions = reinterpret_cast< std::uint32_t* >( imageBase + exportDirectory->AddressOfFunctions );
	const auto exportedNames = reinterpret_cast< std::uint32_t* >( imageBase + exportDirectory->AddressOfNames );
	const auto exportedNameOrdinals = reinterpret_cast< std::uint16_t* >( imageBase + exportDirectory->AddressOfNameOrdinals );

	for ( std::size_t i {}; i < exportDirectory->NumberOfNames; ++i ) {
		const auto functionName = reinterpret_cast< const char* >( imageBase + exportedNames [ i ] );
		if ( !strcmp ( exportName , functionName ) ) {
			*functionPointer = imageBase + exportedFunctions [ exportedNameOrdinals [ i ] ];
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS Nt::findModuleSection ( std::uintptr_t imageAddress , const char* sectionName , std::uintptr_t* sectionBase , std::size_t* sectionSize ) {
	if ( !imageAddress || reinterpret_cast< PIMAGE_DOS_HEADER >( imageAddress )->e_magic != 0x5A4D )
		return {};

	const auto ntHeader = reinterpret_cast< PIMAGE_NT_HEADERS64 >( imageAddress + reinterpret_cast< PIMAGE_DOS_HEADER >(
		imageAddress )->e_lfanew );
	auto sectionHeader = IMAGE_FIRST_SECTION ( ntHeader );

	for ( std::uint16_t i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i , ++sectionHeader )
		if ( strstr ( reinterpret_cast< const char* >( &sectionHeader->Name ) , sectionName ) ) {
			*sectionBase = imageAddress + sectionHeader->VirtualAddress;
			*sectionSize = sectionHeader->Misc.VirtualSize;
			return STATUS_SUCCESS;
		}

	return STATUS_NOT_FOUND;
}

PDRIVER_OBJECT Nt::findDriverObjectByName ( const wchar_t* driverPath ) {
	UNICODE_STRING driverPathUnicode {};
	PDRIVER_OBJECT driverObject {};

	RtlInitUnicodeString ( &driverPathUnicode , driverPath );
	ObReferenceObjectByName ( &driverPathUnicode , OBJ_CASE_INSENSITIVE , nullptr , 0 ,
		*IoDriverObjectType , KernelMode , nullptr , reinterpret_cast< PVOID* >( &driverObject ) );
	ObfDereferenceObject ( driverObject );

	return driverObject;
}

NTSTATUS Nt::findProcessByName ( const char* processName , PEPROCESS* process ) {
	auto currentEntry = reinterpret_cast< std::uintptr_t >( PsInitialSystemProcess );

	do {
		if ( strstr ( reinterpret_cast< char* >( currentEntry ) + NtOffsets::processImageFileName , processName ) ) {
			const auto activeThreads = *reinterpret_cast< std::uint32_t* >( currentEntry + NtOffsets::processActiveThreads );
			if ( activeThreads > 0 ) {
				*process = reinterpret_cast< PEPROCESS >( currentEntry );
				return STATUS_SUCCESS;
			}
		}

		const auto list = reinterpret_cast< PLIST_ENTRY >( currentEntry + NtOffsets::processActiveProcessLinks );
		currentEntry = reinterpret_cast< std::uintptr_t >( list->Flink );
		currentEntry = currentEntry - NtOffsets::processActiveProcessLinks;

	} while ( currentEntry != reinterpret_cast< std::uintptr_t >( PsInitialSystemProcess ) );

	return STATUS_NOT_FOUND;
}