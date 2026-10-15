// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

interface IAsset {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract Vault {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    address public immutable asset;

    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(
        address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares
    );

    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    error AccessControlBadConfirmation();

    constructor(address asset_) {
        asset = asset_;
        _roles[DEFAULT_ADMIN_ROLE].members[msg.sender] = true;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role].members[account];
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _roles[role].adminRole;
    }

    function grantRole(bytes32 role, address account) external {
        _checkRole(getRoleAdmin(role));
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function revokeRole(bytes32 role, address account) external {
        _checkRole(getRoleAdmin(role));
        _revoke(role, account);
    }

    function renounceRole(bytes32 role, address callerConfirmation) external {
        if (callerConfirmation != msg.sender) {
            revert AccessControlBadConfirmation();
        }
        _revoke(role, callerConfirmation);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x7965db0b;
    }

    function totalAssets() public view returns (uint256) {
        return IAsset(asset).balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        uint256 held = totalAssets();
        return supply == 0 || held == 0 ? assets : (assets * supply) / held;
    }

    function maxDeposit(address) external pure returns (uint256) {
        return type(uint256).max;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(IAsset(asset).transferFrom(msg.sender, address(this), assets), "Vault: transfer failed");
        balanceOf[receiver] += shares;
        totalSupply += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        _checkRole(MANAGER_ROLE);
        shares = convertToShares(assets);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        require(IAsset(asset).transfer(receiver, assets), "Vault: transfer failed");
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function _checkRole(bytes32 role) private view {
        if (!hasRole(role, msg.sender)) {
            revert AccessControlUnauthorizedAccount(msg.sender, role);
        }
    }

    function _revoke(bytes32 role, address account) private {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }
}
