// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

contract Errors {
    error Custom(uint256 code, address who);
    error Empty();

    uint256 private counter;

    function failString(uint256 x) external pure returns (uint256) {
        require(x > 10, "Errors: x too small");
        return x;
    }

    function failCustom(uint256 x) external view {
        if (x == 0) {
            revert Empty();
        }
        if (x > counter) {
            revert Custom(x, msg.sender);
        }
    }

    function failPanic(uint256 a, uint256 b) external pure returns (uint256) {
        return a / b;
    }

    function failAssert(uint256 a) external pure returns (uint256) {
        assert(a != 7);
        return a;
    }

    function bump() external returns (uint256) {
        counter += 1;
        return counter;
    }
}

contract Edge {
    uint256 private hits;

    event Hit(address indexed from, uint256 value);

    function edgeA163(uint256 v) external returns (uint256) {
        hits += v;
        return hits;
    }

    function edgeB21611(address who) external view returns (uint256) {
        return who.balance;
    }

    function edgeC25091333() external payable {
        emit Hit(msg.sender, msg.value);
    }

    function payWithArgs(uint64 tag, bytes4 code) external payable returns (uint256) {
        return msg.value + tag + uint32(code);
    }

    fallback() external {
        hits += 1;
    }

    receive() external payable {
        emit Hit(msg.sender, msg.value);
    }
}
