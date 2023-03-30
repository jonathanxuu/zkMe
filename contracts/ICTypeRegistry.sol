// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;

enum FieldType {
    BOOL,
    STRING,
    UINT,
    UINT8,
    UINT16,
    UINT32,
    UINT64,
    UINT128,
    UINT256,
    INT,
    INT8,
    INT16,
    INT32,
    INT64,
    INT128,
    INT256,
    ARRAY,
    ADDRESS
}

/**
 * @title A struct representing a record for a submitted CType.
 */
struct CTypeRecord {
    // The field name and DataType, the index must match
    string[] fieldData;
    FieldType[] fieldType;
}

/**
 * @title The global CType registry interface.
 */
interface ICTypeRegistry {
    /**
     * @dev Emitted when a new CType has been registered
     *
     * @param ctypeHash The CTypeHash which has been registered.
     * @param registerer The address of the account used to register the CType.
     */
    event Registered(bytes32 indexed ctypeHash, address registerer);

    /**
     * @dev Submits and Register a new CType
     *
     * @param ctypeRecord The field data of the CType, include the field Name and its DataType.
     * @param ctypeHash The CTypeHash which to been registered.
     */
    function register(
        CTypeRecord memory ctypeRecord,
        bytes32 ctypeHash
    ) external;

    /**
     * @dev Returns an existing CType by UID
     *
     * @param ctypeHash The UID of the CType to retrieve.
     * @param registerer The address of the register
     *
     * @return The CTypeRecord.
     */
    function getCType(
        bytes32 ctypeHash,
        address registerer
    ) external view returns (CTypeRecord memory);
}
