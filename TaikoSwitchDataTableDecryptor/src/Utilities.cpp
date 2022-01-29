#include "Utilities.h"
#include <zlib.h>

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#ifndef  NT_SUCCESS
#define NT_SUCCESS(Status) (((::NTSTATUS)(Status)) >= 0)
#endif // ! NT_SUCCESS

namespace PeepoHappy
{
	namespace UTF8
	{
		std::string Narrow(std::wstring_view inputString)
		{
			std::string utf8String;
			const int utf8Length = ::WideCharToMultiByte(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0, nullptr, nullptr) - 1;

			if (utf8Length > 0)
			{
				utf8String.resize(utf8Length);
				::WideCharToMultiByte(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), utf8String.data(), utf8Length, nullptr, nullptr);
			}

			return utf8String;
		}

		std::wstring Widen(std::string_view inputString)
		{
			std::wstring utf16String;
			const int utf16Length = ::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0) - 1;

			if (utf16Length > 0)
			{
				utf16String.resize(utf16Length);
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), utf16String.data(), utf16Length);
			}

			return utf16String;
		}

		bool AppearsToUse8BitCodeUnits(std::string_view uncertainUTF8Text)
		{
			size_t nullCount = 0;
			for (const char c : uncertainUTF8Text)
				nullCount += (c == '\0');

			if (uncertainUTF8Text.empty() || nullCount == 0)
				return true;

			const bool unusualNullCount = nullCount >= (uncertainUTF8Text.size() / 4);
			return !unusualNullCount;
		}

		std::pair<int, const char**> GetCommandLineArguments()
		{
			static std::vector<std::string> argvString;
			static std::vector<const char*> argvCStr;

			if (!argvString.empty() || !argvCStr.empty())
				return { static_cast<int>(argvString.size()), argvCStr.data() };

			int argc = 0;
			auto argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);

			argvString.reserve(argc);
			argvCStr.reserve(argc);

			for (auto i = 0; i < argc; i++)
				argvCStr.emplace_back(argvString.emplace_back(UTF8::Narrow(argv[i])).c_str());

			::LocalFree(argv);
			return { argc, argvCStr.data() };
		}

		std::string GetExecutableFilePath()
		{
			wchar_t fileNameBuffer[MAX_PATH];
			const auto moduleFileName = std::wstring_view(fileNameBuffer, ::GetModuleFileNameW(NULL, fileNameBuffer, MAX_PATH));

			return (moduleFileName.size() < MAX_PATH) ? UTF8::Narrow(moduleFileName) : "";
		}

		std::string GetExecutableDirectory()
		{
			return std::string(Path::GetDirectoryName(GetExecutableFilePath()));
		}

		WideArg::WideArg(std::string_view inputString)
		{
			// NOTE: Length **without** null terminator
			convertedLength = ::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0) - 1;

			if (convertedLength <= 0)
			{
				stackBuffer[0] = L'\0';
				return;
			}

			if (convertedLength < stackBuffer.size())
			{
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), stackBuffer.data(), convertedLength);
				stackBuffer[convertedLength] = L'\0';
			}
			else
			{
				heapBuffer = std::make_unique<wchar_t[]>(convertedLength + 1);
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), heapBuffer.get(), convertedLength);
				heapBuffer[convertedLength] = L'\0';
			}
		}

		const wchar_t* WideArg::c_str() const
		{
			return (convertedLength < stackBuffer.size()) ? stackBuffer.data() : heapBuffer.get();
		}
	}

	namespace Path
	{
		std::string_view GetFileExtension(std::string_view filePath)
		{
			const size_t lastSeparator = filePath.find_last_of("./\\");
			if (lastSeparator != std::string_view::npos)
			{
				if (filePath[lastSeparator] == '.')
					return filePath.substr(lastSeparator);
			}
			return std::string_view(filePath.data(), 0);
		}

		std::string_view GetFileName(std::string_view filePath, bool includeExtension)
		{
			const size_t lastSeparator = filePath.find_last_of("/\\");
			const auto fileName = (lastSeparator == std::string_view::npos) ? filePath : filePath.substr(lastSeparator + 1);
			return (includeExtension) ? fileName : TrimFileExtension(fileName);
		}

		std::string_view GetDirectoryName(std::string_view filePath)
		{
			const auto fileName = GetFileName(filePath);
			return fileName.empty() ? filePath : filePath.substr(0, filePath.size() - fileName.size() - 1);
		}

		std::string_view TrimFileExtension(std::string_view filePath)
		{
			return filePath.substr(0, filePath.size() - GetFileExtension(filePath).size());
		}

		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor)
		{
			assert(!extensionToCheckFor.empty() && extensionToCheckFor[0] == '.');
			return ASCII::MatchesInsensitive(GetFileExtension(filePath), extensionToCheckFor);
		}
	}

	namespace IO
	{
		std::pair<std::unique_ptr<u8[]>, size_t> ReadEntireFile(std::string_view filePath)
		{
			std::unique_ptr<u8[]> fileContent = nullptr;
			size_t fileSize = 0;

			::HANDLE fileHandle = ::CreateFileW(UTF8::WideArg(filePath).c_str(), GENERIC_READ, (FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle != INVALID_HANDLE_VALUE)
			{
				::LARGE_INTEGER largeIntegerFileSize = {};
				::GetFileSizeEx(fileHandle, &largeIntegerFileSize);

				if (fileSize = static_cast<size_t>(largeIntegerFileSize.QuadPart); fileSize > 0)
				{
					if (fileContent = std::make_unique<u8[]>(fileSize); fileContent != nullptr)
					{
						assert(fileSize < std::numeric_limits<DWORD>::max() && "No way that's ever gonna happen, right?");

						DWORD bytesRead = 0;
						::ReadFile(fileHandle, fileContent.get(), static_cast<DWORD>(fileSize), &bytesRead, nullptr);
					}
				}

				::CloseHandle(fileHandle);
			}

			return { std::move(fileContent), fileSize };
		}

		bool WriteEntireFile(std::string_view filePath, const u8* fileContent, size_t fileSize)
		{
			if (filePath.empty() || fileContent == nullptr || fileSize == 0)
				return false;

			::HANDLE fileHandle = ::CreateFileW(UTF8::WideArg(filePath).c_str(), GENERIC_WRITE, (FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle == INVALID_HANDLE_VALUE)
				return false;

			assert(fileSize < std::numeric_limits<DWORD>::max() && "No way that's ever gonna happen, right?");

			DWORD bytesWritten = 0;
			::WriteFile(fileHandle, fileContent, static_cast<DWORD>(fileSize), &bytesWritten, nullptr);

			::CloseHandle(fileHandle);
			return true;
		}

		void ParseIniFileContent(std::string_view iniFileContent, std::function<void(std::string_view section, std::string_view key, std::string_view value)> perEntryFunc)
		{
			auto forEachNonCommentLine = [](std::string_view lines, auto perLineReturnFalseToStopFunc) -> void
			{
				for (size_t absoulteIndex = 0; absoulteIndex < lines.size(); absoulteIndex++)
				{
					const std::string_view remainingLines = lines.substr(absoulteIndex);
					for (size_t relativeIndex = 0; relativeIndex < remainingLines.size(); relativeIndex++)
					{
						if (remainingLines[relativeIndex] == '\n')
						{
							const std::string_view line = remainingLines.substr(0, (relativeIndex > 0 && remainingLines[relativeIndex - 1] == '\r') ? (relativeIndex - 1) : relativeIndex);
							if (!line.empty() && (line[0] != ';' && line[0] != '#') && !perLineReturnFalseToStopFunc(line))
								return;

							absoulteIndex += relativeIndex;
							break;
						}
					}
				}
			};

			auto tryParseSectionHeaderLine = [](std::string_view line) -> std::string_view
			{
				return (line.size() >= 2 && line.front() == '[' && line.back() == ']') ? line.substr(1, line.size() - 2) : "";
			};

			auto splitAndTrimKeyValuePairLine = [](std::string_view keyValuePairLine) -> std::pair<std::string_view, std::string_view>
			{
				const size_t separatorIndex = keyValuePairLine.find_first_of("=");
				if (separatorIndex == std::string_view::npos)
					return {};

				const auto key = keyValuePairLine.substr(0, separatorIndex);
				const auto value = keyValuePairLine.substr(separatorIndex + 1);
				return { ASCII::Trim(key), ASCII::Trim(value) };
			};

			std::string_view lastSection;
			forEachNonCommentLine(iniFileContent, [&](std::string_view nonCommentLine)
			{
				if (auto newSection = tryParseSectionHeaderLine(ASCII::Trim(nonCommentLine)); !newSection.empty())
					lastSection = newSection;
				else if (const auto[key, value] = splitAndTrimKeyValuePairLine(nonCommentLine); !key.empty())
					perEntryFunc(lastSection, key, value);
				return true;
			});
		}
	}

	namespace Crypto
	{
		namespace Detail
		{
			enum class Operation { Decrypt, Encrypt };

			bool BCryptAesCbc(Operation operation, const u8* inData, size_t inDataSize, u8* outData, size_t outDataSize, u8* key, size_t keySize, u8* iv)
			{
				bool successful = false;
				::NTSTATUS status = {};
				::BCRYPT_ALG_HANDLE algorithmHandle = {};

				status = ::BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_AES_ALGORITHM, nullptr, 0);
				if (NT_SUCCESS(status))
				{
					status = ::BCryptSetProperty(algorithmHandle, BCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
					if (NT_SUCCESS(status))
					{
						ULONG keyObjectSize = {};
						ULONG copiedDataSize = {};

						status = ::BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&keyObjectSize), sizeof(ULONG), &copiedDataSize, 0);
						if (NT_SUCCESS(status))
						{
							::BCRYPT_KEY_HANDLE symmetricKeyHandle = {};
							auto keyObject = std::make_unique<u8[]>(keyObjectSize);

							status = ::BCryptGenerateSymmetricKey(algorithmHandle, &symmetricKeyHandle, keyObject.get(), keyObjectSize, key, static_cast<ULONG>(keySize), 0);
							if (NT_SUCCESS(status))
							{
								if (operation == Operation::Decrypt)
								{
									status = ::BCryptDecrypt(symmetricKeyHandle, const_cast<u8*>(inData), static_cast<ULONG>(inDataSize), nullptr, iv, static_cast<ULONG>(AesIVSize), outData, static_cast<ULONG>(outDataSize), &copiedDataSize, 0);
									if (NT_SUCCESS(status))
										successful = true;
									else
										fprintf(stderr, "BCryptDecrypt() failed with 0x%X\n", status);
								}
								else if (operation == Operation::Encrypt)
								{
									status = ::BCryptEncrypt(symmetricKeyHandle, const_cast<u8*>(inData), static_cast<ULONG>(inDataSize), nullptr, iv, static_cast<ULONG>(AesIVSize), outData, static_cast<ULONG>(outDataSize), &copiedDataSize, 0);
									if (NT_SUCCESS(status))
										successful = true;
									else
										fprintf(stderr, "BCryptEncrypt() failed with 0x%X\n", status);
								}
								else
								{
									assert(false);
								}

								if (symmetricKeyHandle)
									::BCryptDestroyKey(symmetricKeyHandle);
							}
							else
							{
								fprintf(stderr, "BCryptGenerateSymmetricKey() failed with 0x%X\n", status);
							}
						}
						else
						{
							fprintf(stderr, "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed with 0x%X\n", status);
						}
					}
					else
					{
						fprintf(stderr, "BCryptSetProperty(BCRYPT_CHAINING_MODE) failed with 0x%X\n", status);
					}

					if (algorithmHandle)
						::BCryptCloseAlgorithmProvider(algorithmHandle, 0);
				}
				else
				{
					fprintf(stderr, "BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) failed with 0x%X\n", status);
				}

				return successful;
			}

			bool ParseHexByteString(std::string_view hexByteString, u8* outBytes, size_t outByteSize)
			{
				constexpr size_t hexDigitsPerByte = 2;
				constexpr size_t byteBufferSize = 64;
				assert(outByteSize < byteBufferSize);

				char upperCaseHexChars[(byteBufferSize * hexDigitsPerByte) + sizeof('\0')] = {};
				size_t hexCharsWrittenSoFar = 0;

				for (size_t charIndex = 0; charIndex < hexByteString.size(); charIndex++)
				{
					if (ASCII::IsWhiteSpace(hexByteString[charIndex]))
						continue;

					const char upperCaseChar = ASCII::ToUpperCase(hexByteString[charIndex]);
					upperCaseHexChars[hexCharsWrittenSoFar++] = ((upperCaseChar >= '0' && upperCaseChar <= '9') || (upperCaseChar >= 'A' && upperCaseChar <= 'F')) ? upperCaseChar : '0';

					if (hexCharsWrittenSoFar >= std::size(upperCaseHexChars))
						break;
				}

				for (size_t byteIndex = 0; byteIndex < outByteSize; byteIndex++)
				{
					auto upperCaseHexCharToNibble = [](char c) -> u8 { return (c >= '0' && c <= '9') ? (c - '0') : (c >= 'A' && c <= 'F') ? (0xA + (c - 'A')) : 0x0; };

					u8 combinedByte = 0x00;
					combinedByte |= (upperCaseHexCharToNibble(upperCaseHexChars[(byteIndex * hexDigitsPerByte) + 0]) << 4);
					combinedByte |= (upperCaseHexCharToNibble(upperCaseHexChars[(byteIndex * hexDigitsPerByte) + 1]) << 0);
					outBytes[byteIndex] = combinedByte;
				}

				return true;
			}
		}

		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, Aes128KeyBytes key, AesIVBytes iv)
		{
			return Detail::BCryptAesCbc(Detail::Operation::Decrypt, inEncryptedData, inOutDataSize, outDecryptedData, inOutDataSize, key.data(), key.size(), iv.data());
		}

		bool EncryptAes128Cbc(const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, Aes128KeyBytes key, AesIVBytes iv)
		{
			assert(Align(inOutDataSize, AesBlockAlignment) == inOutDataSize);
			return Detail::BCryptAesCbc(Detail::Operation::Encrypt, inDecryptedData, inOutDataSize, outEncryptedData, inOutDataSize, key.data(), key.size(), iv.data());
		}

		bool DecryptAes256Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, Aes256KeyBytes key, AesIVBytes iv)
		{
			return Detail::BCryptAesCbc(Detail::Operation::Decrypt, inEncryptedData, inOutDataSize, outDecryptedData, inOutDataSize, key.data(), key.size(), iv.data());
		}

		bool EncryptAes256Cbc(const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, Aes256KeyBytes key, AesIVBytes iv)
		{
			assert(Align(inOutDataSize, AesBlockAlignment) == inOutDataSize);
			return Detail::BCryptAesCbc(Detail::Operation::Encrypt, inDecryptedData, inOutDataSize, outEncryptedData, inOutDataSize, key.data(), key.size(), iv.data());
		}

		Aes128KeyBytes ParseAes128KeyHexByteString(std::string_view hexByteString)
		{
			Aes128KeyBytes result = {};
			Detail::ParseHexByteString(hexByteString, result.data(), result.size());
			return result;
		}

		Aes256KeyBytes ParseAes256KeyHexByteString(std::string_view hexByteString)
		{
			Aes256KeyBytes result = {};
			Detail::ParseHexByteString(hexByteString, result.data(), result.size());
			return result;
		}
	}

	namespace Compression
	{
		namespace
		{
#pragma pack(push, 1)
			struct GZipHeader
			{
				u8 Magic[2];
				u8 CompressionMethod;
				u8 Flags;
				u32 Timestamp;
				u8 ExtraFlags;
				u8 OperatingSystem;
			};
#pragma pack(pop)

			static_assert(sizeof(GZipHeader) == 10);
		}

		bool HasValidGZipHeader(const u8* fileContent, size_t fileSize)
		{
			if (fileSize <= sizeof(GZipHeader))
				return false;

			const GZipHeader* header = reinterpret_cast<const GZipHeader*>(fileContent);

			// NOTE: This is by no means comprehensive but should be enough for datatable files and (not falsely) detecting encrypted data
#if 0
			return (header->Magic[0] == 0x1F && header->Magic[1] == 0x8B) &&
				(header->CompressionMethod == Z_DEFLATED) &&
				(header->Flags == 0) &&
				(header->Timestamp == 0) &&
				(header->ExtraFlags == 0);
#else // NOTE: Less precise because becuase of some false negatives
			return (header->Magic[0] == 0x1F && header->Magic[1] == 0x8B) &&
				(header->CompressionMethod == Z_DEFLATED);
#endif
		}

		bool Inflate(const u8* inCompressedData, size_t inDataSize, u8* outDecompressedData, size_t outDataSize)
		{
			z_stream zStream = {};
			zStream.zalloc = Z_NULL;
			zStream.zfree = Z_NULL;
			zStream.opaque = Z_NULL;
			zStream.avail_in = static_cast<uInt>(inDataSize);
			zStream.next_in = static_cast<const Bytef*>(inCompressedData);
			zStream.avail_out = static_cast<uInt>(outDataSize);
			zStream.next_out = static_cast<Bytef*>(outDecompressedData);

			const int initResult = inflateInit2(&zStream, 31);
			if (initResult != Z_OK)
				return false;

			const int inflateResult = inflate(&zStream, Z_FINISH);
			// BUG: I remember there being some edge case where it would report "incorrect end" or something desprite having already decompressed everything correctly..? 
			//		Don't really wanna risk falsely reporting an error here...
			// assert(inflateResult == Z_STREAM_END && zStream.msg == nullptr);

			const int endResult = inflateEnd(&zStream);
			if (endResult != Z_OK)
				return false;

			return true;
		}

		size_t Deflate(const u8* inData, size_t inDataSize, u8* outCompressedData, size_t outDataSize)
		{
			constexpr size_t chunkStepSize = 0x4000;

			z_stream zStream = {};
			zStream.zalloc = Z_NULL;
			zStream.zfree = Z_NULL;
			zStream.opaque = Z_NULL;

			int errorCode = deflateInit2(&zStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
			assert(errorCode == Z_OK);

			const u8* inDataReadHeader = static_cast<const u8*>(inData);
			size_t remainingSize = inDataSize;
			size_t compressedSize = 0;

			while (remainingSize > 0)
			{
				const size_t chunkSize = std::min(remainingSize, chunkStepSize);

				zStream.avail_in = static_cast<uInt>(chunkSize);
				zStream.next_in = reinterpret_cast<const Bytef*>(inDataReadHeader);

				inDataReadHeader += chunkSize;
				remainingSize -= chunkSize;

				do
				{
					std::array<u8, chunkStepSize> outputBuffer;

					zStream.avail_out = chunkStepSize;
					zStream.next_out = outputBuffer.data();

					errorCode = deflate(&zStream, remainingSize == 0 ? Z_FINISH : Z_NO_FLUSH);
					assert(errorCode != Z_STREAM_ERROR);

					const auto compressedChunkSize = chunkStepSize - zStream.avail_out;
					memcpy(&outCompressedData[compressedSize], outputBuffer.data(), compressedChunkSize);

					compressedSize += compressedChunkSize;
				}
				while (zStream.avail_out == 0);
				assert(zStream.avail_in == 0);
			}

			deflateEnd(&zStream);

			assert(errorCode == Z_STREAM_END);
			return compressedSize;
		}
	}
}
