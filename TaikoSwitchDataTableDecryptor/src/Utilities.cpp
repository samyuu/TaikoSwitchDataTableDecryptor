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

		std::vector<std::string> GetArgV()
		{
			return std::vector<std::string>();
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

		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor)
		{
			assert(!extensionToCheckFor.empty() && extensionToCheckFor[0] == '.');

			if (extensionToCheckFor.size() >= filePath.size())
				return false;

			const auto stringA = filePath.substr(filePath.size() - extensionToCheckFor.size());
			const auto stringB = extensionToCheckFor;
			return std::equal(stringA.begin(), stringA.end(), stringB.begin(), stringB.end(), [](char a, char b) { return ::tolower(a) == ::tolower(b); });
		}

		std::string ChangeFileExtension(std::string_view filePath, std::string_view newExtension)
		{
			const size_t lastSeparator = filePath.find_last_of("./\\");
			if (lastSeparator != std::string_view::npos)
			{
				if (filePath[lastSeparator] == '.')
					return std::string(filePath.substr(0, lastSeparator)) + std::string(newExtension);
			}

			return std::string(filePath) + std::string(newExtension);
		}
	}

	namespace Crypto
	{
		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, std::array<u8, Aes128KeySize> key, std::array<u8, Aes128KeySize> iv)
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

						status = ::BCryptGenerateSymmetricKey(algorithmHandle, &symmetricKeyHandle, keyObject.get(), keyObjectSize, key.data(), static_cast<ULONG>(key.size()), 0);
						if (NT_SUCCESS(status))
						{
							status = ::BCryptDecrypt(symmetricKeyHandle, const_cast<u8*>(inEncryptedData), static_cast<ULONG>(inOutDataSize), nullptr, iv.data(), static_cast<ULONG>(iv.size()), outDecryptedData, static_cast<ULONG>(inOutDataSize), &copiedDataSize, 0);
							if (NT_SUCCESS(status))
							{
								successful = true;
							}
							else
							{
								fprintf(stderr, "BCryptDecrypt() failed with 0x%X", status);
							}

							if (symmetricKeyHandle)
								::BCryptDestroyKey(symmetricKeyHandle);
						}
						else
						{
							fprintf(stderr, "BCryptGenerateSymmetricKey() failed with 0x%X", status);
						}
					}
					else
					{
						fprintf(stderr, "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed with 0x%X", status);
					}
				}
				else
				{
					fprintf(stderr, "BCryptSetProperty(BCRYPT_CHAINING_MODE) failed with 0x%X", status);
				}

				if (algorithmHandle)
					::BCryptCloseAlgorithmProvider(algorithmHandle, 0);
			}
			else
			{
				fprintf(stderr, "BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) failed with 0x%X", status);
			}

			return successful;
		}
	}

	namespace Compression
	{
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
