// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

contract AbiZoo {
    uint256 private stored;
    address private lastSender;

    event Stored(address indexed who, uint256 value);

    error TooLarge(uint256 value, uint256 limit);

    function takeAddress(address a) external pure returns (address) {
        return a;
    }

    function takeBool(bool b) external pure returns (bool) {
        return !b;
    }

    function takeUint8(uint8 v) external pure returns (uint256) {
        return uint256(v) + 1;
    }

    function takeUint16(uint16 v) external pure returns (uint256) {
        return uint256(v) * 2;
    }

    function takeUint24(uint24 v) external pure returns (uint24) {
        return v;
    }

    function takeUint32(uint32 v) external pure returns (uint256) {
        return uint256(v) << 1;
    }

    function takeUint64(uint64 v) external pure returns (uint64) {
        return v / 3;
    }

    function takeUint128(uint128 v) external pure returns (uint128) {
        return v;
    }

    function takeUint256(uint256 v) external pure returns (uint256) {
        return v * 3;
    }

    function takeInt8(int8 v) external pure returns (int256) {
        return int256(v) - 1;
    }

    function takeInt16(int16 v) external pure returns (int16) {
        return v;
    }

    function takeInt32(int32 v) external pure returns (int256) {
        return int256(v) * 5;
    }

    function takeInt64(int64 v) external pure returns (int64) {
        return v;
    }

    function takeInt128(int128 v) external pure returns (int128) {
        return v;
    }

    function takeInt256(int256 v) external pure returns (int256) {
        return v / -2;
    }

    function takeBytes1(bytes1 v) external pure returns (bytes1) {
        return v;
    }

    function takeBytes4(bytes4 v) external pure returns (bytes4) {
        return v;
    }

    function takeBytes16(bytes16 v) external pure returns (bytes16) {
        return v;
    }

    function takeBytes20(bytes20 v) external pure returns (bytes20) {
        return v;
    }

    function takeBytes32(bytes32 v) external pure returns (bytes32) {
        return v ^ bytes32(uint256(1));
    }

    function takeBytesCalldata(bytes calldata data) external pure returns (uint256) {
        return data.length;
    }

    function takeBytesMemory(bytes memory data) public pure returns (bytes32) {
        return keccak256(data);
    }

    function takeString(string calldata s) external pure returns (uint256) {
        return bytes(s).length;
    }

    function takeUintArray(uint256[] calldata xs) external pure returns (uint256 total) {
        for (uint256 i = 0; i < xs.length; i++) {
            total += xs[i];
        }
    }

    function takeAddressArray(address[] memory xs) public pure returns (address) {
        return xs.length == 0 ? address(0) : xs[0];
    }

    function takeUint8Array(uint8[] calldata xs) external pure returns (uint8) {
        return xs.length == 0 ? 0 : xs[0];
    }

    function mixed(address to, uint256 amount, bytes calldata data, bool flag) external returns (bool) {
        stored = amount + data.length;
        lastSender = to;
        return !flag;
    }

    function setStored(uint256 v) external {
        if (v > 1000) {
            revert TooLarge(v, 1000);
        }
        stored = v;
        lastSender = msg.sender;
        emit Stored(msg.sender, v);
    }

    function getStored() external view returns (uint256) {
        return stored;
    }

    function deposit() external payable {
        emit Stored(msg.sender, msg.value);
    }

    function depositFor(address who, uint16 tag) external payable {
        emit Stored(who, msg.value + tag);
    }

    function timestamp() external view returns (uint256) {
        return block.timestamp;
    }

    function balanceHere() external view returns (uint256) {
        return address(this).balance;
    }

    function hashPair(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    function digest(bytes calldata d) external pure returns (bytes32) {
        return sha256(d);
    }
}
