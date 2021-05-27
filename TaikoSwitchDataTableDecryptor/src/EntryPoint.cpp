#include "Types.h"
#include "Utilities.h"

namespace TaikoSwitchDataTableDecryptor
{
	namespace
	{
		// NOTE: Sucks for modders, makes sense for them to do it though...
		constexpr size_t MaxDecompressedGameDataTableFileSize = 0x200000;

		// NOTE: Extracted from "JP v1.4.3". I just hope it's at least the same for all versions, though not like it takes more than 5 minutes to find anyway...
		constexpr std::array<u8, PeepoHappy::Crypto::Aes128KeySize> DataTableAesKey = { 0x57, 0x39, 0x73, 0x35, 0x38, 0x73, 0x68, 0x43, 0x54, 0x70, 0x76, 0x75, 0x6A, 0x6B, 0x4A, 0x74 };
	}

	bool HasValidGZipHeader(const u8* fileContent, size_t fileSize)
	{
		if (constexpr size_t minHeaderSize = 9; fileSize <= minHeaderSize)
			return false;

		constexpr std::array<u8, 2> gzibMagic = { 0x1F, 0x8B };

		const bool validMagic = (memcmp(fileContent, gzibMagic.data(), gzibMagic.size()) == 0);
		const bool validCompressionMethod = (fileContent[2] == /*Z_DEFLATED*/ 0x08);

		return (validMagic && validCompressionMethod);
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
		const auto jsonString = std::string_view(reinterpret_cast<const char*>(decompressedBuffer.get()), jsonLength);

		if (!PeepoHappy::IO::WriteEntireFile(jsonOutputFilePath, reinterpret_cast<const u8*>(jsonString.data()), jsonString.size()))
		{
			fprintf(stderr, "Failed to write JSON output file\n");
			return false;
		}

		return true;
	}

	int ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(std::string_view encryptedAndOrCompressedInputFilePath, std::string_view jsonOutputFilePath)
	{
		const auto[fileContent, fileSize] = PeepoHappy::IO::ReadEntireFile(encryptedAndOrCompressedInputFilePath);
		if (fileContent == nullptr)
		{
			fprintf(stderr, "Failed to read input file\n");
			return EXIT_WIDEPEEPOSAD;
		}
		else if (fileSize <= 8)
		{
			fprintf(stderr, "Unexpected end of file\n");
			return EXIT_WIDEPEEPOSAD;
		}

		if (fileSize >= MaxDecompressedGameDataTableFileSize)
		{
			fprintf(stderr, "Input file too large. DataTable files are limited to %zu bytes\n", MaxDecompressedGameDataTableFileSize);
			return EXIT_WIDEPEEPOSAD;
		}

		if (HasValidGZipHeader(fileContent.get(), fileSize))
		{
			if (!DecompressAndWriteDataTableJsonFile(fileContent.get(), fileSize, jsonOutputFilePath))
				return EXIT_WIDEPEEPOSAD;
		}
		else
		{
			std::array<u8, PeepoHappy::Crypto::Aes128IVSize> iv = {};
			memcpy(iv.data(), fileContent.get(), iv.size());

			const size_t fileSizeWithoutIV = (fileSize - iv.size());
			const u8* fileContentWithoutIV = (fileContent.get() + iv.size());

			auto decryptedBuffer = std::make_unique<u8[]>(fileSizeWithoutIV);
			if (!PeepoHappy::Crypto::DecryptAes128Cbc(fileContentWithoutIV, decryptedBuffer.get(), fileSizeWithoutIV, DataTableAesKey, iv))
				fprintf(stderr, "Failed to decrypt input file\n");

			if (!DecompressAndWriteDataTableJsonFile(decryptedBuffer.get(), fileSizeWithoutIV, jsonOutputFilePath))
				return EXIT_WIDEPEEPOSAD;
		}

		return EXIT_WIDEPEEPOHAPPY;
	}

	int ReadAndWriteJsonFileToCompressedAndEncryptedBin(std::string_view jsonInputFilePath, std::string_view compressedAndEncryptedOutputFilePath)
	{
		const auto[fileContent, fileSize] = PeepoHappy::IO::ReadEntireFile(jsonInputFilePath);
		if (fileContent == nullptr)
		{
			fprintf(stderr, "Failed to read input file\n");
			return EXIT_WIDEPEEPOSAD;
		}
		else if ((fileSize + PeepoHappy::Crypto::Aes128IVSize) >= MaxDecompressedGameDataTableFileSize)
		{
			fprintf(stderr, "Input file too large. DataTable files are limited to %zu bytes\n", MaxDecompressedGameDataTableFileSize);
			return EXIT_WIDEPEEPOSAD;
		}

		auto singleAllocationCombinedBuffers = std::make_unique<u8[]>(MaxDecompressedGameDataTableFileSize * 2);
		u8* compressedBuffer = (singleAllocationCombinedBuffers.get() + 0);
		u8* encryptedBufferWithIV = (singleAllocationCombinedBuffers.get() + MaxDecompressedGameDataTableFileSize);
		u8* encryptedBuffer = (encryptedBufferWithIV + PeepoHappy::Crypto::Aes128IVSize);

		const size_t compressedSize = PeepoHappy::Compression::Deflate(fileContent.get(), fileSize, compressedBuffer, MaxDecompressedGameDataTableFileSize);
		const size_t alignedSize = PeepoHappy::Crypto::Align(compressedSize, PeepoHappy::Crypto::Aes128Alignment);
		const size_t alignedSizeWithIV = (alignedSize + PeepoHappy::Crypto::Aes128IVSize);

		if (compressedSize <= 0)
		{
			fprintf(stderr, "Failed to compress JSON file\n");
			return EXIT_WIDEPEEPOSAD;
		}

		assert(compressedSize < MaxDecompressedGameDataTableFileSize && "The compressed data could technically be larger... but that seems highly unlikely for plain text JSON");
		assert((alignedSize + PeepoHappy::Crypto::Aes128IVSize) <= MaxDecompressedGameDataTableFileSize);

		constexpr std::array<u8, PeepoHappy::Crypto::Aes128IVSize> dummyIV = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
		memcpy(encryptedBufferWithIV, dummyIV.data(), dummyIV.size());

		if (!PeepoHappy::Crypto::EncryptAes128Cbc(compressedBuffer, encryptedBuffer, alignedSize, DataTableAesKey, dummyIV))
		{
			fprintf(stderr, "Failed to encrypt JSON file\n");
			return EXIT_WIDEPEEPOSAD;
		}

		if (!PeepoHappy::IO::WriteEntireFile(compressedAndEncryptedOutputFilePath, encryptedBufferWithIV, alignedSizeWithIV))
		{
			fprintf(stderr, "Failed to write encrypted output file\n");
			return EXIT_WIDEPEEPOSAD;
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
			printf("    TaikoSwitchDataTableDecryptor.exe \"{input_datatable_file}.json\"\n");
			printf("\n");
			printf("Notes:\n");
			printf("    Decompressed DataTable JSON input files mustn't be larger than ~2MB (0x200000 bytes)\n");
			printf("    because of fixed size buffers used by the game during decompression.\n");
			printf("\n");
			printf("Credits:\n");
			printf("    Programmed and reverse engineered by samyuu\n");
			printf("    This program is licensed under the MIT License and makes use of the zlib library.\n");
			printf("    The source code is available at " "https://github.com/samyuu/TaikoSwitchDataTableDecryptor" "\n");
			printf("\n");
			return EXIT_WIDEPEEPOSAD;
		}

		const auto inputPath = std::string_view(argv[1]);
		if (PeepoHappy::IO::HasFileExtension(inputPath, ".bin"))
			return ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(inputPath, PeepoHappy::IO::ChangeFileExtension(inputPath, ".json"));

		if (PeepoHappy::IO::HasFileExtension(inputPath, ".json"))
			return ReadAndWriteJsonFileToCompressedAndEncryptedBin(inputPath, PeepoHappy::IO::ChangeFileExtension(inputPath, ".bin"));

		fprintf(stderr, "Unexpected file extension\n");
		return EXIT_WIDEPEEPOSAD;
	}
}

int main()
{
	return TaikoSwitchDataTableDecryptor::EntryPoint();
}
