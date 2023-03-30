// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.9;

import { CTypeRecord, FieldType } from "../ICTypeRegistry.sol";

// this library defines the struct and the functions of a Verifiable Credential
library libCredential {
    // the prefix of did, which is 'did::zk'
    bytes7 constant DID_ZK_PREFIX = bytes7("did:zk:");

    // the version header of the eip191
    bytes25 constant EIP191_VERSION_E_HEADER = "Ethereum Signed Message:\n";

    // the prefix of the attestation message, which is CredentialVersionedDigest
    bytes25 constant EIP191_CRE_VERSION_DIGEST_PREFIX = bytes25("CredentialVersionedDigest");

    // the length of Digest, which likes 0x1b32b6e54e4420cfaf2feecdc0a15dc3fc0a7681687123a0f8cb348b451c2989
    bytes2 constant EIP191_CRE_DIGEST_LEN_V0 = 0x3332;

    // the length of the CredentialVersionedDigest, which likes CredentialVersionedDigest0x00011b32b6e54e4420cfaf2feecdc0a15dc3fc0a7681687123a0f8cb348b451c2989
    bytes2 constant EIP191_CRE_VERSION_DIGEST_LEN_V1 = 0x3539;

    struct SignatureDetail {
        bool isEip191;
        bytes signature;
    }

    struct Credential {
        bytes2 version;
        bytes32 ctype;
        bytes32 digest;
        bytes32 roothash;
        string[] data;
        // bytes[] data; // if use bytes, we dont't need to convert each field content to its dataType
        address claimer;
        address attester;
        uint64 issuanceDate;
        uint64 expirationDate;
        SignatureDetail sigDetail;
    }


    /**
     * @dev verify the roothash of the Credential
     * @param credential, the credential to be verified
     * @param ctypeRecord, the ctype needs to match
     */
    function verifyRootHash(Credential memory credential, CTypeRecord memory ctypeRecord) public pure returns (bool verifyResult){
        // the data is empty, means that the content of the VC won't be stored on-chain
        if (credential.data.length == 0){
            return true;
        }

        FieldType[] memory fieldType = ctypeRecord.fieldType;
        if (credential.data.length != fieldType.length){
            return false;
        }

        if (credential.roothash != _calcRoothash(credential.data, fieldType)){
            return false;
        }
        
        return true;
    }


    /**
     * @dev calculate the roothash of the Credential
     * @param data, the data to be calculated
     * @param fieldType, the ctype needs to match
     */
    // todo: whether save this or drop?
    function _calcRoothash(string[] memory data, FieldType[] memory fieldType) internal pure returns (bytes32 roothash){
        bytes32[] memory leaves = new bytes32[](fieldType.length);
        for (uint i = 0; i < fieldType.length; i++){
            if (fieldType[i] == FieldType.BOOL && (keccak256(abi.encodePacked(data[i])) == keccak256(abi.encodePacked("true")) || keccak256(abi.encodePacked(data[i])) == keccak256(abi.encodePacked("false")) ))
                {
                leaves[i] = keccak256(abi.encodePacked(keccak256(abi.encodePacked(data[i])) == keccak256(abi.encodePacked("true"))));
            }

            if (fieldType[i] == FieldType.STRING){
                leaves[i] = keccak256(abi.encodePacked(data[i]));
            }

            // todo, add range limit
            if (fieldType[i] == FieldType.UINT || fieldType[i] == FieldType.UINT8 || fieldType[i] == FieldType.UINT16 ||fieldType[i] == FieldType.UINT32||fieldType[i] == FieldType.UINT64||fieldType[i] == FieldType.UINT128||fieldType[i] == FieldType.UINT256){
                uint256 convertedNumber;
                bool isConvertSuccess;
                (convertedNumber, isConvertSuccess) = _strToUint(data[i]);
                leaves[i] = keccak256(abi.encodePacked(_toBytes(convertedNumber)));
            }

            // todo, add range limit
            if (fieldType[i] == FieldType.INT || fieldType[i] == FieldType.INT8 || fieldType[i] == FieldType.INT16 ||fieldType[i] == FieldType.INT32||fieldType[i] == FieldType.INT64||fieldType[i] == FieldType.INT128||fieldType[i] == FieldType.INT256){
                int convertedNumber;
                convertedNumber = _stringToInteger(data[i]);
                leaves[i] = keccak256(abi.encodePacked(convertedNumber));
            }
        }
        roothash = _computeRootHash(leaves);

    }

    /**
     * @dev verify the digest of the Credential
     * @param credential, the credential to be verified
     */
    function verifyDigest(
        Credential memory credential
    ) public pure returns (bool verifyResult) {
        // if the vcVersion is not valid, revert
        require(
            credential.version == 0x0001 || credential.version == 0x0000,
            "The vcVersion is invalid"
        );

        // convert sender address to bytes
        bytes memory userDidAsBytes;

        // concat and compute digest according to the vcVersion(different concat rule)
        bytes memory concatResult;

        if (credential.version == 0x0001) {
            userDidAsBytes = abi.encodePacked(credential.claimer);
            concatResult = abi.encodePacked(
                credential.roothash,
                DID_ZK_PREFIX,
                userDidAsBytes,
                _uint64ToBytes(credential.issuanceDate),
                _uint64ToBytes(credential.expirationDate),
                credential.ctype
            );
        } else if (credential.version == 0x0000) {
            userDidAsBytes = abi.encodePacked(
                "0x",
                _getChecksum(credential.claimer)
            );
            concatResult = abi.encodePacked(
                credential.roothash,
                DID_ZK_PREFIX,
                userDidAsBytes,
                _uint64ToBytes(credential.expirationDate),
                credential.ctype
            );
        }
        bytes32 digest = keccak256(concatResult);
        return digest == credential.digest;
    }

    /**
     * @dev verify the signature, check if it is a valid proof of the digest, check whether the attester signed this digest
     * @param credential, the credential to be verified
     */
    function verifySignature(
        Credential memory credential
    ) public pure returns (bool) {
        bytes32 ethSignedMessageHash;
        if (credential.sigDetail.isEip191 == false) {
            ethSignedMessageHash = credential.digest;
        } else {
            if (credential.version == 0x0001) {
                bytes memory versionedDigest = abi.encodePacked(
                    credential.version,
                    credential.digest
                );
                ethSignedMessageHash = keccak256(
                    abi.encodePacked(
                        bytes1(0x19),
                        EIP191_VERSION_E_HEADER,
                        EIP191_CRE_VERSION_DIGEST_LEN_V1,
                        EIP191_CRE_VERSION_DIGEST_PREFIX,
                        versionedDigest
                    )
                );
            } else {
                ethSignedMessageHash = keccak256(
                    abi.encodePacked(
                        bytes1(0x19),
                        EIP191_VERSION_E_HEADER,
                        EIP191_CRE_DIGEST_LEN_V0,
                        credential.digest
                    )
                );
            }
        }
        return
            _recover(ethSignedMessageHash, credential.sigDetail.signature) ==
            credential.attester;
    }

    /**
     * @dev parse the signature, and recover the signer address
     * @param hash, the messageHash which the signer signed
     * @param sig, the signature
     */
    function _recover(
        bytes32 hash,
        bytes memory sig
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        // Check the signature length
        if (sig.length != 65) {
            return (address(0));
        }

        // Divide the signature in r, s and v variables
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            // solium-disable-next-line arg-overflow
            return ecrecover(hash, v, r, s);
        }
    }

    /**
     * @dev convert string to uint
     * @param _str, the string to be convert
     */
    function _strToUint(string memory _str) internal pure returns(uint256 res, bool err) {
        
        for (uint256 i = 0; i < bytes(_str).length; i++) {
            if ((uint8(bytes(_str)[i]) - 48) < 0 || (uint8(bytes(_str)[i]) - 48) > 9) {
                return (0, false);
            }
            res += (uint8(bytes(_str)[i]) - 48) * 10**(bytes(_str).length - i - 1);
        }
        
        return (res, true);
    }

    /**
     * @dev convert string to int
     * @param _value, the string to be convert
     */
    function _stringToInteger(string memory _value) internal pure returns (int) {
        bytes memory _bytesValue = bytes(_value);
        int256 _intValue = 0;
        bool _isNegative = false;

        for (uint256 i = 0; i < _bytesValue.length; i++) {
            uint256 _digit = uint256(uint8(_bytesValue[i]));

            if (_digit >= 48 && _digit <= 57) {
                _intValue = _intValue * 10 + int256(_digit - 48);
            } else if (_digit == 45 && i == 0) {
                _isNegative = true;
            } else {
                revert("Invalid integer value");
            }
        }

        if (_isNegative) {
            _intValue = -_intValue;
        }

        return _intValue;
    }


    /**
     * @dev computeRoothash
     * @param leaves, the leaves to be computed
     */
    function _computeRootHash(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "Leaves array should not be empty");

        uint256 n = leaves.length;
        bytes32[] memory nodes = new bytes32[](n * 2); 

        for (uint256 i = 0; i < n; i++) {
            nodes[n + i] = leaves[i];
        }

        for (uint256 i = n - 1; i > 0; i--) {
            nodes[i] = keccak256(abi.encodePacked(nodes[i * 2], nodes[i * 2 + 1]));
        }

        return nodes[1]; 
    }

    /**
     * @dev convert uint64 to bytes(with unfixed length), designed for timestamp when calculate
     * @param num, the uint64 to be convert
     */
    function _uint64ToBytes(uint64 num) public pure returns (bytes memory) {
        if (num == 0){
            bytes memory res = new bytes(1);
            return res;
        }
        uint len = 0;

        for (uint tmpNum = num; tmpNum > 0; tmpNum >>= 8) {
            len++;
        }
        bytes memory result = new bytes(len);
        for (uint i = 0; i < len; i++) {
            result[len - i - 1] = bytes1(uint8(num & 0xff));
            num >>= 8;
        }
        return result;
    }

    function _toBytes(uint256 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(32);
        assembly { mstore(add(b, 32), x) }
        return b;
    }

    /**
     * @dev Get a checksummed string hex representation of an account address.
     * @param account address The account to get the checksum for.
     */
    function _getChecksum(
        address account
    ) internal pure returns (string memory accountChecksum) {
        // call internal function for converting an account to a checksummed string.
        return _toChecksumString(account);
    }

    function _toChecksumString(
        address account
    ) internal pure returns (string memory asciiString) {
        // convert the account argument from address to bytes.
        bytes20 data = bytes20(account);

        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;
        bool leftCaps;
        bool rightCaps;
        uint8 asciiOffset;

        // get the capitalized characters in the actual checksum.
        bool[40] memory caps = _toChecksumCapsFlags(account);

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // locate and extract each capitalization status.
            leftCaps = caps[2 * i];
            rightCaps = caps[2 * i + 1];

            // get the offset from nibble value to ascii character for left nibble.
            asciiOffset = _getAsciiOffset(leftNibble, leftCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i] = bytes1(leftNibble + asciiOffset);

            // get the offset from nibble value to ascii character for right nibble.
            asciiOffset = _getAsciiOffset(rightNibble, rightCaps);

            // add the converted character to the byte array.
            asciiBytes[2 * i + 1] = bytes1(rightNibble + asciiOffset);
        }

        return string(asciiBytes);
    }

    function _toChecksumCapsFlags(
        address account
    ) internal pure returns (bool[40] memory characterCapitalized) {
        // convert the address to bytes.
        bytes20 a = bytes20(account);

        // hash the address (used to calculate checksum).
        bytes32 b = keccak256(abi.encodePacked(_toAsciiString(a)));

        // declare variable types.
        uint8 leftNibbleAddress;
        uint8 rightNibbleAddress;
        uint8 leftNibbleHash;
        uint8 rightNibbleHash;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i; i < a.length; i++) {
            // locate the byte and extract each nibble for the address and the hash.
            rightNibbleAddress = uint8(a[i]) % 16;
            leftNibbleAddress = (uint8(a[i]) - rightNibbleAddress) / 16;
            rightNibbleHash = uint8(b[i]) % 16;
            leftNibbleHash = (uint8(b[i]) - rightNibbleHash) / 16;

            characterCapitalized[2 * i] = (leftNibbleAddress > 9 &&
                leftNibbleHash > 7);
            characterCapitalized[2 * i + 1] = (rightNibbleAddress > 9 &&
                rightNibbleHash > 7);
        }
    }

    function _getAsciiOffset(
        uint8 nibble,
        bool caps
    ) internal pure returns (uint8 offset) {
        // to convert to ascii characters, add 48 to 0-9, 55 to A-F, & 87 to a-f.
        if (nibble < 10) {
            offset = 48;
        } else if (caps) {
            offset = 55;
        } else {
            offset = 87;
        }
    }

    // based on https://ethereum.stackexchange.com/a/56499/48410
    function _toAsciiString(
        bytes20 data
    ) internal pure returns (string memory asciiString) {
        // create an in-memory fixed-size bytes array.
        bytes memory asciiBytes = new bytes(40);

        // declare variable types.
        uint8 b;
        uint8 leftNibble;
        uint8 rightNibble;

        // iterate over bytes, processing left and right nibble in each iteration.
        for (uint256 i = 0; i < data.length; i++) {
            // locate the byte and extract each nibble.
            b = uint8(uint160(data) / (2 ** (8 * (19 - i))));
            leftNibble = b / 16;
            rightNibble = b - 16 * leftNibble;

            // to convert to ascii characters, add 48 to 0-9 and 87 to a-f.
            asciiBytes[2 * i] = bytes1(
                leftNibble + (leftNibble < 10 ? 48 : 87)
            );
            asciiBytes[2 * i + 1] = bytes1(
                rightNibble + (rightNibble < 10 ? 48 : 87)
            );
        }

        return string(asciiBytes);
    }
}
