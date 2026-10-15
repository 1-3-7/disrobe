// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.4.24 <0.7.0;

contract Legacy {
    mapping(address => uint256) public balances;
    address public owner;
    uint8 public level;
    bool public paused;

    event Moved(address indexed from, address indexed to, uint256 amount);

    constructor() public {
        owner = msg.sender;
    }

    function move(address to, uint256 amount) public returns (bool) {
        require(!paused, "paused");
        require(balances[msg.sender] >= amount, "balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Moved(msg.sender, to, amount);
        return true;
    }

    function setLevel(uint8 newLevel) public {
        require(msg.sender == owner, "owner");
        level = newLevel;
    }

    function setPaused(bool flag) public {
        require(msg.sender == owner, "owner");
        paused = flag;
    }

    function fund() public payable {
        balances[msg.sender] += msg.value;
    }

    function sum(uint256[] memory xs) public pure returns (uint256 total) {
        for (uint256 i = 0; i < xs.length; i++) {
            total += xs[i];
        }
    }

    function size(bytes memory data) public pure returns (uint256) {
        return data.length;
    }

    function greet(string memory who) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(who));
    }

    function narrow(int16 a, bytes4 b) public pure returns (int256) {
        return int256(a) + int256(uint32(b));
    }
}
