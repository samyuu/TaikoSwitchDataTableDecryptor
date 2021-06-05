#pragma once
#include "Types.h"

// NOTE: In case anyone is wondering... no, there is no particular reason for these names. 
//		 I just like Peepo and it cheers me up after looking at code all day :WidePeepoHappy:
#define EXIT_WIDEPEEPOHAPPY EXIT_SUCCESS
#define EXIT_WIDEPEEPOSAD EXIT_FAILURE

namespace PeepoHappy
{
	namespace ASCII
	{
		constexpr const char* WhiteSpaceCharacters = " \t\r\n";
		constexpr char CaseDifference = ('A' - 'a');
		constexpr char LowerCaseMin = 'a', LowerCaseMax = 'z';
		constexpr char UpperCaseMin = 'A', UpperCaseMax = 'Z';

		constexpr bool IsWhiteSpace(char c) { return (c == WhiteSpaceCharacters[0] || c == WhiteSpaceCharacters[1] || c == WhiteSpaceCharacters[2] || c == WhiteSpaceCharacters[3]); }
		constexpr bool IsLowerCase(char c) { return (c >= LowerCaseMin && c <= LowerCaseMax); }
		constexpr bool IsUpperCase(char c) { return (c >= UpperCaseMin && c <= UpperCaseMax); }
		constexpr char ToLowerCase(char c) { return IsUpperCase(c) ? (c - CaseDifference) : c; }
		constexpr char ToUpperCase(char c) { return IsLowerCase(c) ? (c + CaseDifference) : c; }

		constexpr bool CaseSensitiveComparison(char a, char b) { return (a == b); }
		constexpr bool CaseInsenitiveComparison(char a, char b) { return (ToLowerCase(a) == ToLowerCase(b)); }

		constexpr bool Matches(std::string_view a, std::string_view b) { if (a.size() != b.size()) return false; for (auto i = 0; i < a.size(); i++) { if (!CaseSensitiveComparison(a[i], b[i])) return false; } return true; }
		constexpr bool MatchesInsensitive(std::string_view a, std::string_view b) { if (a.size() != b.size()) return false; for (auto i = 0; i < a.size(); i++) { if (!CaseInsenitiveComparison(a[i], b[i])) return false; } return true; }
		constexpr bool StartsWith(std::string_view s, std::string_view prefix) { return (s.size() >= prefix.size() && Matches(s.substr(0, prefix.size()), prefix)); }
		constexpr bool StartsWithInsensitive(std::string_view s, std::string_view prefix) { return (s.size() >= prefix.size() && MatchesInsensitive(s.substr(0, prefix.size()), prefix)); }
		constexpr bool EndsWith(std::string_view s, std::string_view suffix) { return (s.size() >= suffix.size() && Matches(s.substr(s.size() - suffix.size()), suffix)); }
		constexpr bool EndsWithInsensitive(std::string_view s, std::string_view suffix) { return (s.size() >= suffix.size() && MatchesInsensitive(s.substr(s.size() - suffix.size()), suffix)); }

		constexpr std::string_view StripPrefix(std::string_view s, std::string_view prefix) { return StartsWith(s, prefix) ? s.substr(prefix.size(), s.size() - prefix.size()) : s; }
		constexpr std::string_view StripPrefixInsensitive(std::string_view s, std::string_view prefix) { return StartsWithInsensitive(s, prefix) ? s.substr(prefix.size(), s.size() - prefix.size()) : s; }
		constexpr std::string_view StripSuffix(std::string_view s, std::string_view suffix) { return EndsWith(s, suffix) ? s.substr(0, s.size() - suffix.size()) : s; }
		constexpr std::string_view StripSuffixInsensitive(std::string_view s, std::string_view suffix) { return EndsWithInsensitive(s, suffix) ? s.substr(0, s.size() - suffix.size()) : s; }

		constexpr std::string_view TrimLeft(std::string_view s) { auto f = s.find_first_not_of(WhiteSpaceCharacters); return (f == std::string_view::npos) ? s : s.substr(f); }
		constexpr std::string_view TrimRight(std::string_view s) { auto l = s.find_last_not_of(WhiteSpaceCharacters); return (l == std::string_view::npos) ? s : s.substr(0, l + 1); }
		constexpr std::string_view Trim(std::string_view s) { return TrimRight(TrimLeft(s)); }
	}

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

		// NOTE: By no means reliable but should be good enough to quickly detect UTF-16 text
		bool AppearsToUse8BitCodeUnits(std::string_view uncertainUTF8Text);

		// NOTE: Includes the program file path as first arguments
		std::pair<int, const char**> GetCommandLineArguments();

		std::string GetExecutableFilePath();
		std::string GetExecutableDirectory();
	}

	namespace Path
	{
		std::string_view GetFileExtension(std::string_view filePath);
		std::string_view GetFileName(std::string_view filePath, bool includeExtension = true);
		std::string_view TrimFileExtension(std::string_view filePath);
		std::string_view GetDirectoryName(std::string_view filePath);
		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor);
	}

	namespace IO
	{
		std::pair<std::unique_ptr<u8[]>, size_t> ReadEntireFile(std::string_view filePath);
		bool WriteEntireFile(std::string_view filePath, const u8* fileContent, size_t fileSize);

		void ParseIniFileContent(std::string_view iniFileContent, std::function<void(std::string_view section, std::string_view key, std::string_view value)> perEntryFunc);
	}

	namespace Crypto
	{
		constexpr size_t Aes128KeySize = 16;
		constexpr size_t Aes128IVSize = 16;
		constexpr size_t Aes128Alignment = 16;

		using Aes128KeyBytes = std::array<u8, Aes128KeySize>;
		using Aes128IVBytes = std::array<u8, Aes128IVSize>;

		constexpr size_t Align(size_t value, size_t alignment) { return (value + (alignment - 1)) & ~(alignment - 1); }

		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, Aes128KeyBytes key, Aes128IVBytes iv);
		bool EncryptAes128Cbc(const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, Aes128KeyBytes key, Aes128IVBytes iv);

		Aes128KeyBytes ParseAes128KeyHexByteString(std::string_view hexString);
	}

	namespace Compression
	{
		bool HasValidGZipHeader(const u8* fileContent, size_t fileSize);

		bool Inflate(const u8* inCompressedData, size_t inDataSize, u8* outDecompressedData, size_t outDataSize);
		size_t Deflate(const u8* inData, size_t inDataSize, u8* outCompressedData, size_t outDataSize);
	}
}
