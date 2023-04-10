// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.9;
import {ICTypeRegistry} from "./ICTypeRegistry.sol";
import {ICTypeResolver} from "./ICTypeResolver.sol";

/**
 * @title The global CType registry.
 */
contract CTypeRegistry is ICTypeRegistry {
    error AlreadyExists();
    error ResolverNotValid();

    // The global mapping between CTypeHash and Register and the Resolver Contract
    mapping(bytes32 => mapping(address => ICTypeResolver)) private _registry;

    /**
     * @inheritdoc ICTypeRegistry
     */
    function register(
        bytes32 ctypeHash,
        ICTypeResolver CTypeResolver
    ) external {
        if (address(_registry[ctypeHash][msg.sender]) != address(0)) {
            revert AlreadyExists();
        }

        _registry[ctypeHash][msg.sender] = CTypeResolver;

        emit Registered(ctypeHash, msg.sender, CTypeResolver);
    }

    /**
     * @inheritdoc ICTypeRegistry
     */
    function getResolver(
        bytes32 ctypeHash,
        address registerer
    ) external view returns (ICTypeResolver CTypeResolver) {
        return _registry[ctypeHash][registerer];
    }
}
