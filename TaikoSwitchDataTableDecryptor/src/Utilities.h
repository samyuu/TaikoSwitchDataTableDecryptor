#pragma once
#include "Types.h"

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
		// NOTE: Sucks for modders, makes sense for them to do it though...
		constexpr size_t MaxDecompressedGameDataTableFileSize = 0x200000;

		std::pair<std::unique_ptr<u8[]>, size_t> ReadEntireFile(std::string_view filePath);
		bool WriteEntireFile(std::string_view filePath, const u8* fileContent, size_t fileSize);

		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor);
		std::string ChangeFileExtension(std::string_view filePath, std::string_view newExtension);
	}

	namespace Crypto
	{
		constexpr size_t AesKeySize = 16;

		// NOTE: Literally loaded directly into X8 right before calling nn::crypto::DecryptAes128Cbc()
		//		 they couldn't even bother trying to "hide" it by adding a few pointer indirection or scrambling first :KEKL:
		constexpr std::array<u8, AesKeySize> DataTableAesKey = { 0x57, 0x39, 0x73, 0x35, 0x38, 0x73, 0x68, 0x43, 0x54, 0x70, 0x76, 0x75, 0x6A, 0x6B, 0x4A, 0x74, };

		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, std::array<u8, AesKeySize> key, std::array<u8, AesKeySize> iv);
	}

	namespace Compression
	{
		bool Inflate(const u8* inCompressedData, size_t inDataSize, u8* outDecompressedData, size_t outDataSize);
		size_t Deflate(const u8* inData, size_t inDataSize, u8* outCompressedData, size_t outDataSize);
	}
}
