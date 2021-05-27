#pragma once
#include "Types.h"

// NOTE: In case anyone is wondering... no, there is no particular reason for these names. 
//		 I just like Peepo and it cheers me up after looking at code all day :WidePeepoHappy:
#define EXIT_WIDEPEEPOHAPPY EXIT_SUCCESS
#define EXIT_WIDEPEEPOSAD EXIT_FAILURE

namespace PeepoHappy
{
	// NOTE: Following the "UTF-8 Everywhere" guidelines
	namespace UTF8
	{
		// NOTE: Convert UTF-16 to UTF-8
		std::string Narrow(std::wstring_view);

		// NOTE: Convert UTF-8 to UTF-16
		std::wstring Widen(std::string_view);

		// NOTE: To avoid needless heap allocations for temporary wchar_t C-API function arguments
		//		 Example: DummyU16FuncW(UTF8::WideArg(stringU8).c_str(), ...)
		class WideArg : NonCopyable
		{
		public:
			WideArg(std::string_view);
			const wchar_t* c_str() const;

		private:
			std::unique_ptr<wchar_t[]> heapBuffer;
			std::array<wchar_t, 260> stackBuffer;
			int convertedLength;
		};

		// NOTE: Includes the program file path as first argument
		std::pair<int, const char**> GetCommandLineArguments();
	}

	namespace IO
	{
		std::pair<std::unique_ptr<u8[]>, size_t> ReadEntireFile(std::string_view filePath);
		bool WriteEntireFile(std::string_view filePath, const u8* fileContent, size_t fileSize);

		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor);
		std::string ChangeFileExtension(std::string_view filePath, std::string_view newExtension);
	}

	namespace Crypto
	{
		constexpr size_t Aes128KeySize = 16;
		constexpr size_t Aes128IVSize = 16;
		constexpr size_t Aes128Alignment = 16;

		constexpr size_t Align(size_t value, size_t alignment) { return (value + (alignment - 1)) & ~(alignment - 1); }

		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, std::array<u8, Aes128KeySize> key, std::array<u8, Aes128IVSize> iv);
		bool EncryptAes128Cbc(const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, std::array<u8, Aes128KeySize> key, std::array<u8, Aes128IVSize> iv);
	}

	namespace Compression
	{
		bool Inflate(const u8* inCompressedData, size_t inDataSize, u8* outDecompressedData, size_t outDataSize);
		size_t Deflate(const u8* inData, size_t inDataSize, u8* outCompressedData, size_t outDataSize);
	}
}
