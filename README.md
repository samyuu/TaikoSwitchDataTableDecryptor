# TaikoSwitchDataTableDecryptor

A Windows CLI program for decrypting, decompressing, re-encrypting and re-compressing DataTable JSON files used by Taiko no Tatsujin for the Nintendo Switch (and possibly others) intended for Game Modding.

DataTable `.bin` files (located under `LayeredFS/romfs/datatable`) are zlib Deflate compressed and (in later game versions) AES-128-CBC encrypted JSON files used for defining various game parameters. The exact encryption key used appears to change with every game update/region but can be easily extracted using a disassembler from the target executable.

Encryption keys for each region+version are defined inside `TaikoSwitchDataTableEncrpytionKeys.ini` and will have to be updated in the future to support newer (or older) versions.
Attempting to decrypt or re-encrypt a DataTable file from an undefined game version will fail.

# Usage

##### To convert from `.bin` to `.json` run:
`TaikoSwitchDataTableDecryptor.exe "{input_datatable_file}.bin"`

resulting in an output file `{input_file_directory}/{input_datatable_file} {key_name}.json`
where `{input_datatable_file}` is a file path to a DataTable file and `{key_name}` is the name of the automatically detected key used for decryption.
If the input file is not encrypted (as is the case for older game versions) then a key name will not be appended.


##### To convert from `.json` to `.bin` run:
`TaikoSwitchDataTableDecryptor.exe "{input_datatable_file} {key_name}.json`

resulting in an output file `{input_file_directory}/{input_datatable_file}.bin`
where `{key_name}` is the same name of the key used for re-encrpytion.
If no matching key name is found for the input file name then the resulting JSON file will not be encrypted.

## Usage Example
##### Unencrypted Taiko Switch (Early Versions) or possibly other Taiko games:
* `TaikoSwitchDataTableDecryptor.exe "musicinfo.bin"` -> `musicinfo.json`
* `TaikoSwitchDataTableDecryptor.exe "musicinfo.json"` -> `musicinfo.bin`

##### Encrypted Taiko Switch JP ver1.4.3:
* `TaikoSwitchDataTableDecryptor.exe "musicinfo.bin"` -> `musicinfo jp_ver143.json`
* `TaikoSwitchDataTableDecryptor.exe "musicinfo jp_ver143.json"` -> `musicinfo.bin`

This interface design is intentionally simplistic to support Windows Explorer drag-and-drop style conversion without the need to manually enter commands into a command prompt.
