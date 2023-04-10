// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;
import {ICTypeResolver} from "./ICTypeResolver.sol";

/**
 * @title The Resolver contract for a specific cType.
 */


contract CTypeResolver is ICTypeResolver {
    error RecordAlreadyExist();
    error RecordAlreadyNotExist();

    struct Schema {
        string name;
        uint age;
    }

    // The global mapping between digest and uploader and the cType Record.
    mapping(bytes32 => mapping(address => Schema)) private _db;

    function name(bytes32 digest, address uploader) external view returns (string memory) {
        return _db[digest][uploader].name;
    }

    function age(bytes32 digest, address uploader) external view returns (uint) {
        return _db[digest][uploader].age;
    }

    /**
     * @inheritdoc ICTypeResolver
     */
    function store(bytes memory originData, bytes32 digest) external {
        Schema memory schemaData = abi.decode(originData, (Schema));
        if ( keccak256(abi.encodePacked(_db[digest][msg.sender].name)) == keccak256(abi.encodePacked("")) ){
            revert RecordAlreadyExist();
        }
        _db[digest][msg.sender] = schemaData;
    }

    /**
     * @inheritdoc ICTypeResolver
     */
    function computeRootHash(bytes memory originData) external pure returns (bytes32 roothash) {
        Schema memory schemaData = abi.decode(originData, (Schema));
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] =  keccak256(abi.encodePacked(_computeName(schemaData.name)));
        leaves[1] =  keccak256(abi.encodePacked(_computeAge(schemaData.age)));
        roothash = _computeRootHash(leaves);
    }

    /**
     * @dev a helper function, helps compute the bytes form in dev environment
     *
     * @param nameData, the name of the schemaData
     * @param ageData, the age of the schemaData
     */
    function encode(string memory nameData, uint ageData) external pure returns (bytes memory encodeResult){
        Schema memory schemaData = Schema(nameData, ageData);
        encodeResult = abi.encode(schemaData);
    }

    /**
     * @inheritdoc ICTypeResolver
     */
    function replace(bytes memory originData, bytes32 digest) external returns (bool) {
        Schema memory schemaData = abi.decode(originData, (Schema));
        if ( keccak256(abi.encodePacked(_db[digest][msg.sender].name)) == keccak256(abi.encodePacked("")) ){
            _db[digest][msg.sender] = schemaData;
            return true;
        }
        revert RecordAlreadyNotExist();
    }

    function _computeName(string memory originData) internal pure returns (bytes32 leaveHash) {
        bytes memory nameRLP = encodeBytes(bytes(originData));
        leaveHash =  keccak256(abi.encodePacked(nameRLP));
    }

    function _computeAge(uint originData) internal pure returns (bytes32 leaveHash) {
        bytes memory ageRLP = encodeBytes(toBinary(originData));
        leaveHash = keccak256(abi.encodePacked(ageRLP));
    }


    function _computeRootHash(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "Merkle tree must have at least one leaf");

        if (leaves.length == 1) {
            return leaves[0];
        }

        uint256 nodes = leaves.length;
        bytes32[] memory levels = new bytes32[](leaves.length);

        // Copy the leaves into the lowest level of the tree
        for (uint256 i = 0; i < nodes; i++) {
            levels[i] = leaves[i];
        }

        // Repeatedly hash pairs of nodes until there is only one node left
        for (uint256 levelSize = nodes; levelSize > 1; levelSize = (levelSize + 1) / 2) {
            for (uint256 i = 0; i < levelSize; i += 2) {
                uint256 j = i / 2;
                if (i == levelSize - 1) {
                    levels[j] = levels[i];
                } else {
                    levels[j] = hashPair(levels[i], levels[i + 1]);
                }
            }
        }
        return levels[0];
    }

    function hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    /**
     * @dev Encode integer in big endian binary form with no leading zeroes.
     * @notice TODO: This should be optimized with assembly to save gas costs.
     * @param _x The integer to encode.
     * @return RLP encoded bytes.
     */
    function toBinary(uint _x) private pure returns (bytes memory) {
        bytes memory b = new bytes(32);
        assembly { 
            mstore(add(b, 32), _x) 
        }
        uint i;
        for (i = 0; i < 32; i++) {
            if (b[i] != 0) {
                break;
            }
        }
        bytes memory res = new bytes(32 - i);
        for (uint j = 0; j < res.length; j++) {
            res[j] = b[i++];
        }
        return res;
    }

    /**
     * @dev RLP encodes a byte string.
     * @param self The byte string to encode.
     * @return The RLP encoded string in bytes.
     */
    function encodeBytes(bytes memory self) internal pure returns (bytes memory) {
        bytes memory encoded;
        if (self.length == 1 && uint8(self[0]) < 128) {
            encoded = self;
        } else {
            encoded = concat(encodeLength(self.length, 128), self);
        }
        return encoded;
    }
        
     /**
     * @dev Concatenates two bytes.
     * @notice From: https://github.com/GNSPS/solidity-bytes-utils/blob/master/contracts/BytesLib.sol.
     * @param _preBytes First byte string.
     * @param _postBytes Second byte string.
     * @return Both byte string combined.
     */
    function concat(bytes memory _preBytes, bytes memory _postBytes) private pure returns (bytes memory) {
        bytes memory tempBytes;

        assembly {
            tempBytes := mload(0x40)

            let length := mload(_preBytes)
            mstore(tempBytes, length)

            let mc := add(tempBytes, 0x20)
            let end := add(mc, length)

            for {
                let cc := add(_preBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            length := mload(_postBytes)
            mstore(tempBytes, add(length, mload(tempBytes)))

            mc := end
            end := add(mc, length)

            for {
                let cc := add(_postBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            mstore(0x40, and(
              add(add(end, iszero(add(length, mload(_preBytes)))), 31),
              not(31)
            ))
        }

        return tempBytes;
    }

    /**
     * @dev Encode the first byte, followed by the `len` in binary form if `length` is more than 55.
     * @param len The length of the string or the payload.
     * @param offset 128 if item is string, 192 if item is list.
     * @return RLP encoded bytes.
     */
    function encodeLength(uint len, uint offset) private pure returns (bytes memory) {
        bytes memory encoded;
        if (len < 56) {
            encoded = new bytes(1);
            encoded[0] = bytes32(len + offset)[31];
        } else {
            uint lenLen;
            uint i = 1;
            while (len / i != 0) {
                lenLen++;
                i *= 256;
            }

            encoded = new bytes(lenLen + 1);
            encoded[0] = bytes32(lenLen + offset + 55)[31];
            for(i = 1; i <= lenLen; i++) {
                encoded[i] = bytes32((len / (256**(lenLen-i))) % 256)[31];
            }
        }
        return encoded;
    }
}