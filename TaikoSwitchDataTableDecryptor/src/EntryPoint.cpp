#include "Types.h"
#include "Utilities.h"

namespace PeepoHappy
{
	bool HasValidGZipHeader(const u8* fileContent, size_t fileSize)
	{
		if (fileSize <= Crypto::AesKeySize)
			return false;

		constexpr std::array<u8, 2> gzibMagic = { 0x1F, 0x8B };

		const bool validMagic = (memcmp(fileContent, gzibMagic.data(), gzibMagic.size()) == 0);
		const bool validCompressionMethod = (fileContent[2] == /*Z_DEFLATED*/ 0x08);

		return (validMagic && validCompressionMethod);
	}

	bool DecompressAndWriteDataTableJsonFile(const u8* compressedData, size_t compressedDataSize, std::string_view jsonOutputFilePath)
	{
		auto decompressedBuffer = std::make_unique<u8[]>(IO::MaxDecompressedGameDataTableFileSize);
		if (Compression::Inflate(compressedData, compressedDataSize, decompressedBuffer.get(), IO::MaxDecompressedGameDataTableFileSize))
		{
			const size_t jsonLength = strnlen(reinterpret_cast<const char*>(decompressedBuffer.get()), IO::MaxDecompressedGameDataTableFileSize);
			const auto jsonString = std::string_view(reinterpret_cast<const char*>(decompressedBuffer.get()), jsonLength);

			if (IO::WriteEntireFile(jsonOutputFilePath, reinterpret_cast<const u8*>(jsonString.data()), jsonString.size()))
				return true;
		}

		return false;
	}

	int ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(std::string_view encryptedAndOrCompressedInputFilePath, std::string_view jsonOutputFilePath)
	{
		const auto[fileContent, fileSize] = IO::ReadEntireFile(encryptedAndOrCompressedInputFilePath);
		if (fileSize <= 8)
		{
			fprintf(stderr, "Bad file? :WidePeepoSad:");
			return EXIT_WIDEPEEPOSAD;
		}

		if (HasValidGZipHeader(fileContent.get(), fileSize))
		{
			if (!DecompressAndWriteDataTableJsonFile(fileContent.get(), fileSize, jsonOutputFilePath))
				return EXIT_WIDEPEEPOSAD;
		}
		else
		{
			std::array<u8, Crypto::AesKeySize> iv = {};
			memcpy(iv.data(), fileContent.get(), iv.size());

			const size_t fileSizeWithoutIV = (fileSize - iv.size());
			const u8* fileContentWithoutIV = (fileContent.get() + iv.size());

			auto decryptedBuffer = std::make_unique<u8[]>(fileSizeWithoutIV);
			Crypto::DecryptAes128Cbc(fileContentWithoutIV, decryptedBuffer.get(), fileSizeWithoutIV, Crypto::DataTableAesKey, iv);

			if (!DecompressAndWriteDataTableJsonFile(decryptedBuffer.get(), fileSizeWithoutIV, jsonOutputFilePath))
				return EXIT_WIDEPEEPOSAD;
		}

		return EXIT_WIDEPEEPOHAPPY;
	}

	int ReadAndWriteJsonFileToCompressedBin(std::string_view jsonInputFilePath, std::string_view compressedOutputFilePath)
	{
		auto compressedBuffer = std::make_unique<u8[]>(IO::MaxDecompressedGameDataTableFileSize);

		const auto[fileContent, fileSize] = IO::ReadEntireFile(jsonInputFilePath);
		const auto compressedSize = Compression::Deflate(fileContent.get(), fileSize, compressedBuffer.get(), IO::MaxDecompressedGameDataTableFileSize);

		if (compressedSize < 0)
			return EXIT_WIDEPEEPOSAD;

		if (!IO::WriteEntireFile(compressedOutputFilePath, compressedBuffer.get(), compressedSize))
			return EXIT_WIDEPEEPOSAD;

		return EXIT_WIDEPEEPOHAPPY;
	}

	int EntryPoint()
	{
		const auto[argc, argv] = UTF8::GetCommandLineArguments();

		if (argc <= 1)
		{
			fprintf(stderr, "Insufficient arguments :WidePeepoSad:\n");
			return EXIT_WIDEPEEPOSAD;
		}

		const auto inputPath = std::string_view(argv[1]);
		if (IO::HasFileExtension(inputPath, ".bin"))
			return ReadAndWriteEncryptedAndOrCompressedBinToJsonFile(inputPath, IO::ChangeFileExtension(inputPath, ".json"));

		if (IO::HasFileExtension(inputPath, ".json"))
			return ReadAndWriteJsonFileToCompressedBin(inputPath, IO::ChangeFileExtension(inputPath, ".bin"));

		fprintf(stderr, "Unknown file extension\n");
		return EXIT_WIDEPEEPOSAD;
	}
}

int main()
{
	return PeepoHappy::EntryPoint();
}
