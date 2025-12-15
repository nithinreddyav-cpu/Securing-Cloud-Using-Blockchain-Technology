// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileStorage {
    struct FileData {
        string encryptionKey;
        string fileName;
        bool exists;
    }

    mapping(string => FileData) private files;

    event FileStored(string fileHash, string fileName);

    function storeFileData(string memory fileHash, string memory encryptionKey, string memory fileName) public returns (bool) {
        require(bytes(fileHash).length > 0, "File hash cannot be empty");
        require(bytes(encryptionKey).length > 0, "Encryption key cannot be empty");

        files[fileHash] = FileData({
            encryptionKey: encryptionKey,
            fileName: fileName,
            exists: true
        });

        emit FileStored(fileHash, fileName);
        return true;
    }

    function getFileData(string memory fileHash) public view returns (string memory, string memory) {
        require(files[fileHash].exists, "File not found");
        return (files[fileHash].encryptionKey, files[fileHash].fileName);
    }
}
