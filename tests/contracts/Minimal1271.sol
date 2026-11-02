// SPDX-License-Identifier: MIT
// Compiled with solc 0.8.24+commit.e11b9ed9 (solc-static-linux) --optimize --bin.
// The hex next to this file is that output. The test does not download a compiler.
pragma solidity 0.8.24;

/// A 1-of-1 wallet used only by the local-chain test.
/// isValidSignature returns the EIP-1271 magic when ecrecover(hash, sig) is the owner.
contract Minimal1271 {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4) {
        if (signature.length != 65) return 0xffffffff;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) {
            v += 27;
        }
        if (ecrecover(hash, v, r, s) == owner) return 0x1626ba7e;
        return 0xffffffff;
    }
}

/// CREATE2 factory for the ERC-6492 local-chain test. No value is forwarded.
contract Create2Factory {
    function deploy(bytes32 salt, bytes memory initCode) external returns (address addr) {
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(addr) { revert(0, 0) }
        }
    }
}
