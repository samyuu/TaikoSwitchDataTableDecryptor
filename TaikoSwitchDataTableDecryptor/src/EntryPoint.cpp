#include "Types.h"
#include "Utilities.h"

namespace TaikoSwitchDataTableDecryptor
{
	// NOTE: Sucks for modders, makes sense for them to do it though...
	constexpr size_t MaxDecompressedGameDataTableFileSize = 0x200000;

	constexpr std::string_view EncrpytionKeysIniFileName = "TaikoSwitchDataTableEncrpytionKeys.ini";

	struct NamedEncryptionKey
	{
		std::string_view Name;
		size_t KeyByteSize;
		PeepoHappy::Crypto::Aes128KeyBytes Key128;
		PeepoHappy::Crypto::Aes256KeyBytes Key256;
	};

	bool DecryptUsingNamedKey(const NamedEncryptionKey& namedKey, const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, PeepoHappy::Crypto::AesIVBytes iv)
	{
		if (namedKey.KeyByteSize == namedKey.Key128.size())
			return PeepoHappy::Crypto::DecryptAes128Cbc(inEncryptedData, outDecryptedData, inOutDataSize, namedKey.Key128, iv);
		else if (namedKey.KeyByteSize == namedKey.Key256.size())
			return PeepoHappy::Crypto::DecryptAes256Cbc(inEncryptedData, outDecryptedData, inOutDataSize, namedKey.Key256, iv);
		else
			assert(false);

		return false;
	}

	bool EncryptUsingNamedKey(const NamedEncryptionKey& namedKey, const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, PeepoHappy::Crypto::AesIVBytes iv)
	{
		if (namedKey.KeyByteSize == namedKey.Key128.size())
			return PeepoHappy::Crypto::EncryptAes128Cbc(inDecryptedData, outEncryptedData, inOutDataSize, namedKey.Key128, iv);
		else if (namedKey.KeyByteSize == namedKey.Key256.size())
			return PeepoHappy::Crypto::EncryptAes256Cbc(inDecryptedData, outEncryptedData, inOutDataSize, namedKey.Key256, iv);
		else
			assert(false);

		return false;
	}

	std::vector<NamedEncryptionKey> ReadAndParseEncrpytionKeysIniFile(std::unique_ptr<u8[]>& outIniFileContent)
	{
		std::vector<NamedEncryptionKey> namedKeys;

#if 1 // NOTE: I think this makes more sense here, don't wanna fail to load the file just because of a different working directory
		auto[iniFileContent, iniFileSize] = PeepoHappy::IO::ReadEntireFile(PeepoHappy::UTF8::GetExecutableDirectory() + "/" + std::string(EncrpytionKeysIniFileName));
#else
		auto[iniFileContent, iniFileSize] = PeepoHappy::IO::ReadEntireFile(EncrpytionKeysIniFileName);
#endif

		if (iniFileContent != nullptr)
		{
			const auto iniFileStringView = std::string_view(reinterpret_cast<const char*>(iniFileContent.get()), iniFileSize);

			if (!PeepoHappy::UTF8::AppearsToUse8BitCodeUnits(iniFileStringView.substr(0, std::min<size_t>(32, iniFileStringView.size()))))
				fprintf(stderr, "INI file does not appear to be UTF-8 encoded\n");

			PeepoHappy::IO::ParseIniFileContent(iniFileStringView, [&namedKeys](std::string_view iniSection, std::string_view iniKey, std::string_view iniValue)
			{
				if (iniSection == "datatable_keys")
				{
					NamedEncryptionKey newKey;
					newKey.Name = iniKey;
					newKey.Key128 = PeepoHappy::Crypto::ParseAes128KeyHexByteString(iniValue);
					newKey.Key256 = PeepoHappy::Crypto::ParseAes256KeyHexByteString(iniValue);

					const bool upperHalfOf256KeyAllZeros = std::all_of(newKey.Key256.begin() + (PeepoHappy::Crypto::Aes256KeySize / 2), newKey.Key256.end(), [](u8 byte) { return byte == 0x00; });
					newKey.KeyByteSize = upperHalfOf256KeyAllZeros ? PeepoHappy::Crypto::Aes128KeySize : PeepoHappy::Crypto::Aes256KeySize;

					namedKeys.push_back(std::move(newKey));
				}
			});

			if (namedKeys.empty())
				fprintf(stderr, "No encrpytion key definition(s) found\n");
		}
		else
		{
			fprintf(stderr, "Failed to read '%.*s'\n", static_cast<int>(EncrpytionKeysIniFileName.size()), EncrpytionKeysIniFileName.data());
		}

		outIniFileContent = std::move(iniFileContent);
		return namedKeys;
	}

	// NOTE: { "datatable/musicinfo.bin", NamedKey{"jp_ver169", ...} } -> "datatable/musicinfo jp_ver169.json"
	std::string FormatJsonOutputFilePathUsingNamedKey(std::string_view binFilePath, const NamedEncryptionKey* key)
	{
		std::string formattedFilePath { PeepoHappy::Path::TrimFileExtension(binFilePath) };
		if (key != nullptr && !key->Name.empty())
		{
			formattedFilePath += " ";
			formattedFilePath += key->Name;
		}
		formattedFilePath += ".json";
		return formattedFilePath;
	}

	// NOTE: ("datatable/musicinfo jp_ver169.json") -> { "datatable/musicinfo.bin", NamedKey{"jp_ver169", ...} } 
	std::pair<std::string, const NamedEncryptionKey*> ParseJsonInputFilePathUsingNamedKeysAndFormatBinOutputFilePath(std::string_view jsonFilePath, const std::vector<NamedEncryptionKey>& namedKeys)
	{
		const auto fileNameWithoutExtension = PeepoHappy::Path::GetFileName(jsonFilePath, false);
		const auto filePathWithoutExtension = PeepoHappy::Path::TrimFileExtension(jsonFilePath);

		for (const auto& namedKey : namedKeys)
		{
			if (PeepoHappy::ASCII::EndsWithInsensitive(fileNameWithoutExtension, namedKey.Name))
			{
				const auto filePathWithoutKeySuffix = PeepoHappy::ASCII::TrimRight(filePathWithoutExtension.substr(0, filePathWithoutExtension.size() - namedKey.Name.size()));
				return { std::string(filePathWithoutKeySuffix) + ".bin", &namedKey };
			}
		}
		return { std::string(PeepoHappy::Path::TrimFileExtension(jsonFilePath)) + ".bin", nullptr };
	}

	const NamedEncryptionKey* TryOutAllAvailableEncrpytionKeysUntilGZipHeaderIsFound(const u8* encryptedFileContent, size_t fileSize, PeepoHappy::Crypto::AesIVBytes iv, const std::vector<NamedEncryptionKey>& namedKeys)
	{
		std::array<u8, 16> decryptedHeaderBuffer = {};
		if (fileSize <= decryptedHeaderBuffer.size())
		{
			fprintf(stderr, "Unexpected end of encrypted file\n");
			return nullptr;
		}

		// NOTE: ~~Backwards because newer version keys which are more likely to be used are most likely defined last~~
		//		 turns out everyone already got into the habbit of placing new ones at the top
		for (const NamedEncryptionKey& namedKey : namedKeys)
		{
			decryptedHeaderBuffer = {};
			if (!DecryptUsingNamedKey(namedKey, encryptedFileContent, decryptedHeaderBuffer.data(), decryptedHeaderBuffer.size(), iv))
			{
				fprintf(stderr, "Failed to decrypt input file header\n");
				return nullptr;
			}

			if (PeepoHappy::Compression::HasValidGZipHeader(decryptedHeaderBuffer.data(), decryptedHeaderBuffer.size()))
				return &namedKey;
		}

		return nullptr;
	}

	bool DecompressAndWriteDataTableJsonFile(const u8* compressedData, size_t compressedDataSize, std::string_view jsonOutputFilePath)
	{
		auto decompressedBuffer = std::make_unique<u8[]>(MaxDecompressedGameDataTableFileSize);
		if (!PeepoHappy::Compression::Inflate(compressedData, compressedDataSize, decompressedBuffer.get(), MaxDecompressedGameDataTableFileSize))
		{
			fprintf(stderr, "Failed to decompress input file\n");
			return false;
		}

		const size_t jsonLength = strnlen(reinterpret_cast<const char*>(decompressedBuffer.get()), MaxDecompressedGameDataTableFileSize);
		const std::string_view jsonString = std::string_view(reinterpret_cast<const char*>(decompressedBuffer.get()), jsonLength);

		if (jsonLength <= 0)
		{
			fprintf(stderr, "Empty json... did decompression fail?\n");
			return false;
		}

		if (!PeepoHappy::IO::WriteEntireFile(jsonOutputFilePath, reinterpret_cast<const u8*>(jsonString.data()), jsonString.size()))
		{
			fprintf(stderr, "Failed to write JSON output file\n");
			return false;
		}

		return true;
	}

	int ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(std::string_view binInputFilePath, const std::vector<NamedEncryptionKey>& namedKeys)
	{
		const auto[binFileContent, binFileSize] = PeepoHappy::IO::ReadEntireFile(binInputFilePath);
		if (binFileContent == nullptr)
		{
			fprintf(stderr, "Failed to read input file\n");
			return EXIT_WIDEPEEPOSAD;
		}
		else if (binFileSize <= 10)
		{
			fprintf(stderr, "Unexpected end of file\n");
			return EXIT_WIDEPEEPOSAD;
		}

		if (binFileSize >= MaxDecompressedGameDataTableFileSize)
		{
			fprintf(stderr, "Input file too large. DataTable files are limited to %zu bytes\n", MaxDecompressedGameDataTableFileSize);
			return EXIT_WIDEPEEPOSAD;
		}

		if (PeepoHappy::Compression::HasValidGZipHeader(binFileContent.get(), binFileSize))
		{
			printf("Input file not encrypted. This should still work fine but likely means the file comes from either an earlier version or different game\n");
			if (!DecompressAndWriteDataTableJsonFile(binFileContent.get(), binFileSize, FormatJsonOutputFilePathUsingNamedKey(binInputFilePath, nullptr)))
				return EXIT_WIDEPEEPOSAD;
		}
		else
		{
			PeepoHappy::Crypto::AesIVBytes iv = {};
			memcpy(iv.data(), binFileContent.get(), iv.size());

			const size_t binFileSizeWithoutIV = (binFileSize - iv.size());
			const u8* binFileContentWithoutIV = (binFileContent.get() + iv.size());

			const NamedEncryptionKey* foundNamedKey = TryOutAllAvailableEncrpytionKeysUntilGZipHeaderIsFound(binFileContentWithoutIV, binFileSizeWithoutIV, iv, namedKeys);
			if (foundNamedKey == nullptr)
			{
				printf("No matching encrpytion key definition found for input file\n");
				return EXIT_WIDEPEEPOSAD;
			}

			auto decryptedBuffer = std::make_unique<u8[]>(binFileSizeWithoutIV);
			if (!DecryptUsingNamedKey(*foundNamedKey, binFileContentWithoutIV, decryptedBuffer.get(), binFileSizeWithoutIV, iv))
				fprintf(stderr, "Failed to decrypt input file\n");

			if (!DecompressAndWriteDataTableJsonFile(decryptedBuffer.get(), binFileSizeWithoutIV, FormatJsonOutputFilePathUsingNamedKey(binInputFilePath, foundNamedKey)))
				return EXIT_WIDEPEEPOSAD;
		}

		return EXIT_WIDEPEEPOHAPPY;
	}

	int ReadAndWriteJsonToCompressedAndOrEncryptedBinFile(std::string_view jsonInputFilePath, const std::vector<NamedEncryptionKey>& namedKeys)
	{
		const auto[jsonFileContent, jsonFileSize] = PeepoHappy::IO::ReadEntireFile(jsonInputFilePath);
		if (jsonFileContent == nullptr)
		{
			fprintf(stderr, "Failed to read input file\n");
			return EXIT_WIDEPEEPOSAD;
		}
		else if ((jsonFileSize + PeepoHappy::Crypto::AesIVSize) >= MaxDecompressedGameDataTableFileSize)
		{
			fprintf(stderr, "Input file too large. DataTable files are limited to %zu bytes\n", MaxDecompressedGameDataTableFileSize);
			return EXIT_WIDEPEEPOSAD;
		}


		auto singleAllocationCombinedBuffers = std::make_unique<u8[]>(MaxDecompressedGameDataTableFileSize * 2);
		u8* compressedBuffer = (singleAllocationCombinedBuffers.get() + 0);
		u8* encryptedBufferWithIV = (singleAllocationCombinedBuffers.get() + MaxDecompressedGameDataTableFileSize);
		u8* encryptedBuffer = (encryptedBufferWithIV + PeepoHappy::Crypto::AesIVSize);

		const size_t compressedSize = PeepoHappy::Compression::Deflate(jsonFileContent.get(), jsonFileSize, compressedBuffer, MaxDecompressedGameDataTableFileSize);
		const size_t alignedSize = PeepoHappy::Crypto::Align(compressedSize, PeepoHappy::Crypto::AesBlockAlignment);
		const size_t alignedSizeWithIV = (alignedSize + PeepoHappy::Crypto::AesIVSize);
		const size_t numberOfAlignmentBytesAdded = (alignedSize - compressedSize);

		if (compressedSize <= 0)
		{
			fprintf(stderr, "Failed to compress JSON file\n");
			return EXIT_WIDEPEEPOSAD;
		}

		const auto[binOutputFilePath, keyUsedForInitialDecrpytion] = ParseJsonInputFilePathUsingNamedKeysAndFormatBinOutputFilePath(jsonInputFilePath, namedKeys);
		if (keyUsedForInitialDecrpytion == nullptr)
		{
			printf("No known encrpytion key signature found in input file name. Output file will not be encrpyted\n");
			if (!PeepoHappy::IO::WriteEntireFile(binOutputFilePath, compressedBuffer, compressedSize))
			{
				fprintf(stderr, "Failed to write compressed output file\n");
				return EXIT_WIDEPEEPOSAD;
			}
		}
		else
		{
			assert(compressedSize < MaxDecompressedGameDataTableFileSize && "The compressed data could technically be larger... but that seems highly unlikely for plain text JSON");
			assert((alignedSize + PeepoHappy::Crypto::AesIVSize) <= MaxDecompressedGameDataTableFileSize);

			constexpr PeepoHappy::Crypto::AesIVBytes dummyIV = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
			memcpy(encryptedBufferWithIV, dummyIV.data(), dummyIV.size());

#if 1 // HACK: Manually add PKCS7 padding (?)
			if (keyUsedForInitialDecrpytion->KeyByteSize == keyUsedForInitialDecrpytion->Key256.size())
			{
				for (size_t i = 0; i < numberOfAlignmentBytesAdded; i++)
					compressedBuffer[compressedSize + i] = static_cast<u8>(numberOfAlignmentBytesAdded);
			}
#endif

			if (!EncryptUsingNamedKey(*keyUsedForInitialDecrpytion, compressedBuffer, encryptedBuffer, alignedSize, dummyIV))
			{
				fprintf(stderr, "Failed to encrypt JSON file\n");
				return EXIT_WIDEPEEPOSAD;
			}

			if (!PeepoHappy::IO::WriteEntireFile(binOutputFilePath, encryptedBufferWithIV, alignedSizeWithIV))
			{
				fprintf(stderr, "Failed to write encrypted output file\n");
				return EXIT_WIDEPEEPOSAD;
			}
		}

		return EXIT_WIDEPEEPOHAPPY;
	}

	int EntryPoint()
	{
		const auto[argc, argv] = PeepoHappy::UTF8::GetCommandLineArguments();

		if (argc <= 1)
		{
			printf("Description:\n");
			printf("    A program to decrypt+decompress and compress+encrypt DataTable JSON files\n");
			printf("    used by the Switch release of Taiko no Tatsujin (and possibly more)\n");
			printf("\n");
			printf("Usage:\n");
			printf("    TaikoSwitchDataTableDecryptor.exe \"{input_datatable_file}.bin\"\n");
			printf("    TaikoSwitchDataTableDecryptor.exe \"{input_datatable_file} {key_name}.json\"\n");
			printf("\n");
			printf("Notes:\n");
			printf("    The '%.*s' file defines a set of known encrpytion keys.\n", static_cast<int>(EncrpytionKeysIniFileName.size()), EncrpytionKeysIniFileName.data());
			printf("    Encrypted '.bin' input files are tested against all available keys,\n");
			printf("    if a matching one is found its key name is appened to the name of the output '.json' file.\n");
			printf("    When a '.json' input file name ends with a known key name, the same key will be used to re-encrypt the output '.bin'.\n");
			printf("    If no matching key is found then files will be neither decrypted no encrpyted (Providing compatibility with older Taiko versions)\n");
			printf("\n");
			printf("    Decompressed DataTable JSON input files mustn't be larger than ~2MB (0x200000 bytes)\n");
			printf("    because of fixed size buffers used by the game during decompression.\n");
			printf("\n");
			printf("Credits:\n");
			printf("    This program is licensed under the MIT License and makes use of the zlib library.\n");
			printf("    The source code is available at " "https://github.com/samyuu/TaikoSwitchDataTableDecryptor" "\n");
			printf("\n");
			return EXIT_WIDEPEEPOSAD;
		}

		std::unique_ptr<u8[]> stringViewOwningIniFileContent = nullptr;
		std::vector<NamedEncryptionKey> namedKeys = ReadAndParseEncrpytionKeysIniFile(stringViewOwningIniFileContent);

		const std::string_view inputFilePath = std::string_view(argv[1]);
		if (PeepoHappy::Path::HasFileExtension(inputFilePath, ".bin"))
			return ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(inputFilePath, namedKeys);

		if (PeepoHappy::Path::HasFileExtension(inputFilePath, ".json"))
			return ReadAndWriteJsonToCompressedAndOrEncryptedBinFile(inputFilePath, namedKeys);

		fprintf(stderr, "Unexpected file extension\n");
		return EXIT_WIDEPEEPOSAD;
	}
}

int main()
{
	return TaikoSwitchDataTableDecryptor::EntryPoint();
}
