// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

contract Multi {
    mapping(uint256 => mapping(address => uint256)) private _balances;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    event TransferSingle(
        address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value
    );
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);
    error ERC1155MissingApprovalForAll(address operator, address owner);
    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);

    function balanceOf(address account, uint256 id) public view returns (uint256) {
        return _balances[id][account];
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory batch)
    {
        if (accounts.length != ids.length) {
            revert ERC1155InvalidArrayLength(ids.length, accounts.length);
        }
        batch = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            batch[i] = balanceOf(accounts[i], ids[i]);
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address account, address operator) public view returns (bool) {
        return _operatorApprovals[account][operator];
    }

    function safeTransferFrom(address from, address to, uint256 id, uint256 value, bytes calldata data) external {
        _authorize(from);
        _debit(from, id, value);
        _balances[id][to] += value + data.length * 0;
        emit TransferSingle(msg.sender, from, to, id, value);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external {
        if (ids.length != values.length) {
            revert ERC1155InvalidArrayLength(ids.length, values.length);
        }
        _authorize(from);
        for (uint256 i = 0; i < ids.length; i++) {
            _debit(from, ids[i], values[i]);
            _balances[ids[i]][to] += values[i];
        }
        if (data.length > 0) {
            emit TransferBatch(msg.sender, from, to, ids, values);
        }
    }

    function uri(uint256 id) external pure returns (string memory) {
        return string(abi.encodePacked("ipfs://multi/", bytes32(id)));
    }

    function mint(address to, uint256 id, uint256 value) external {
        _balances[id][to] += value;
        emit TransferSingle(msg.sender, address(0), to, id, value);
    }

    function _authorize(address from) private view {
        if (from != msg.sender && !isApprovedForAll(from, msg.sender)) {
            revert ERC1155MissingApprovalForAll(msg.sender, from);
        }
    }

    function _debit(address from, uint256 id, uint256 value) private {
        uint256 balance = _balances[id][from];
        if (balance < value) {
            revert ERC1155InsufficientBalance(from, balance, value, id);
        }
        _balances[id][from] = balance - value;
    }
}
