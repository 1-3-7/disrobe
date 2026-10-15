use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::exec::keccak_bytes;

const FUNCTIONS: &[(&str, &str)] = &[
    ("totalSupply()", "ERC-20"),
    ("balanceOf(address)", "ERC-20/ERC-721"),
    ("transfer(address,uint256)", "ERC-20"),
    ("transferFrom(address,address,uint256)", "ERC-20/ERC-721"),
    ("approve(address,uint256)", "ERC-20/ERC-721"),
    ("allowance(address,address)", "ERC-20"),
    ("name()", "ERC-20 metadata"),
    ("symbol()", "ERC-20 metadata"),
    ("decimals()", "ERC-20 metadata"),
    ("increaseAllowance(address,uint256)", "ERC-20 extension"),
    ("decreaseAllowance(address,uint256)", "ERC-20 extension"),
    (
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "ERC-2612",
    ),
    ("nonces(address)", "ERC-2612"),
    ("DOMAIN_SEPARATOR()", "ERC-2612"),
    ("eip712Domain()", "ERC-5267"),
    ("mint(address,uint256)", "mintable"),
    ("burn(uint256)", "burnable"),
    ("burnFrom(address,uint256)", "burnable"),
    ("deposit()", "WETH"),
    ("withdraw(uint256)", "WETH"),
    ("ownerOf(uint256)", "ERC-721"),
    ("safeTransferFrom(address,address,uint256)", "ERC-721"),
    ("safeTransferFrom(address,address,uint256,bytes)", "ERC-721"),
    ("setApprovalForAll(address,bool)", "ERC-721/ERC-1155"),
    ("getApproved(uint256)", "ERC-721"),
    ("isApprovedForAll(address,address)", "ERC-721/ERC-1155"),
    ("tokenURI(uint256)", "ERC-721 metadata"),
    ("tokenByIndex(uint256)", "ERC-721 enumerable"),
    ("tokenOfOwnerByIndex(address,uint256)", "ERC-721 enumerable"),
    (
        "onERC721Received(address,address,uint256,bytes)",
        "ERC-721 receiver",
    ),
    ("balanceOf(address,uint256)", "ERC-1155"),
    ("balanceOfBatch(address[],uint256[])", "ERC-1155"),
    (
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        "ERC-1155",
    ),
    (
        "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
        "ERC-1155",
    ),
    ("uri(uint256)", "ERC-1155 metadata"),
    (
        "onERC1155Received(address,address,uint256,uint256,bytes)",
        "ERC-1155 receiver",
    ),
    (
        "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
        "ERC-1155 receiver",
    ),
    ("supportsInterface(bytes4)", "ERC-165"),
    ("asset()", "ERC-4626"),
    ("totalAssets()", "ERC-4626"),
    ("convertToShares(uint256)", "ERC-4626"),
    ("convertToAssets(uint256)", "ERC-4626"),
    ("maxDeposit(address)", "ERC-4626"),
    ("previewDeposit(uint256)", "ERC-4626"),
    ("deposit(uint256,address)", "ERC-4626"),
    ("maxMint(address)", "ERC-4626"),
    ("previewMint(uint256)", "ERC-4626"),
    ("mint(uint256,address)", "ERC-4626"),
    ("maxWithdraw(address)", "ERC-4626"),
    ("previewWithdraw(uint256)", "ERC-4626"),
    ("withdraw(uint256,address,address)", "ERC-4626"),
    ("maxRedeem(address)", "ERC-4626"),
    ("previewRedeem(uint256)", "ERC-4626"),
    ("redeem(uint256,address,address)", "ERC-4626"),
    ("owner()", "Ownable"),
    ("transferOwnership(address)", "Ownable"),
    ("renounceOwnership()", "Ownable"),
    ("pendingOwner()", "Ownable2Step"),
    ("acceptOwnership()", "Ownable2Step"),
    ("hasRole(bytes32,address)", "AccessControl"),
    ("getRoleAdmin(bytes32)", "AccessControl"),
    ("grantRole(bytes32,address)", "AccessControl"),
    ("revokeRole(bytes32,address)", "AccessControl"),
    ("renounceRole(bytes32,address)", "AccessControl"),
    ("DEFAULT_ADMIN_ROLE()", "AccessControl"),
    ("getRoleMember(bytes32,uint256)", "AccessControlEnumerable"),
    ("getRoleMemberCount(bytes32)", "AccessControlEnumerable"),
    ("paused()", "Pausable"),
    ("pause()", "Pausable"),
    ("unpause()", "Pausable"),
    ("implementation()", "proxy"),
    ("upgradeTo(address)", "EIP-1967 proxy"),
    ("upgradeToAndCall(address,bytes)", "EIP-1967 proxy"),
    ("changeAdmin(address)", "EIP-1967 proxy"),
    ("admin()", "EIP-1967 proxy"),
    ("proxiableUUID()", "ERC-1822"),
    ("beacon()", "beacon proxy"),
    ("initialize()", "initializable"),
    ("multicall(bytes[])", "multicall"),
    ("execute(address,uint256,bytes)", "account"),
    ("isValidSignature(bytes32,bytes)", "ERC-1271"),
    ("royaltyInfo(uint256,uint256)", "ERC-2981"),
    ("flashLoan(address,address,uint256,bytes)", "ERC-3156"),
    ("maxFlashLoan(address)", "ERC-3156"),
    ("flashFee(address,uint256)", "ERC-3156"),
];

const EVENTS: &[&str] = &[
    "Transfer(address,address,uint256)",
    "Approval(address,address,uint256)",
    "ApprovalForAll(address,address,bool)",
    "TransferSingle(address,address,address,uint256,uint256)",
    "TransferBatch(address,address,address,uint256[],uint256[])",
    "URI(string,uint256)",
    "OwnershipTransferred(address,address)",
    "OwnershipTransferStarted(address,address)",
    "RoleGranted(bytes32,address,address)",
    "RoleRevoked(bytes32,address,address)",
    "RoleAdminChanged(bytes32,bytes32,bytes32)",
    "Upgraded(address)",
    "AdminChanged(address,address)",
    "BeaconUpgraded(address)",
    "Deposit(address,address,uint256,uint256)",
    "Withdraw(address,address,address,uint256,uint256)",
    "Deposit(address,uint256)",
    "Withdrawal(address,uint256)",
    "Paused(address)",
    "Unpaused(address)",
    "Initialized(uint8)",
    "Initialized(uint64)",
    "EIP712DomainChanged()",
];

const ERRORS: &[&str] = &[
    "Error(string)",
    "Panic(uint256)",
    "ERC20InsufficientBalance(address,uint256,uint256)",
    "ERC20InvalidSender(address)",
    "ERC20InvalidReceiver(address)",
    "ERC20InsufficientAllowance(address,uint256,uint256)",
    "ERC20InvalidApprover(address)",
    "ERC20InvalidSpender(address)",
    "ERC721InvalidOwner(address)",
    "ERC721NonexistentToken(uint256)",
    "ERC721IncorrectOwner(address,uint256,address)",
    "ERC721InvalidSender(address)",
    "ERC721InvalidReceiver(address)",
    "ERC721InsufficientApproval(address,uint256)",
    "ERC721InvalidApprover(address)",
    "ERC721InvalidOperator(address)",
    "ERC1155InsufficientBalance(address,uint256,uint256,uint256)",
    "ERC1155InvalidSender(address)",
    "ERC1155InvalidReceiver(address)",
    "ERC1155MissingApprovalForAll(address,address)",
    "ERC1155InvalidApprover(address)",
    "ERC1155InvalidOperator(address)",
    "ERC1155InvalidArrayLength(uint256,uint256)",
    "OwnableUnauthorizedAccount(address)",
    "OwnableInvalidOwner(address)",
    "AccessControlUnauthorizedAccount(address,bytes32)",
    "AccessControlBadConfirmation()",
    "ReentrancyGuardReentrantCall()",
    "EnforcedPause()",
    "ExpectedPause()",
    "AddressEmptyCode(address)",
    "FailedInnerCall()",
    "FailedCall()",
    "SafeERC20FailedOperation(address)",
    "InvalidInitialization()",
    "NotInitializing()",
    "ERC1967InvalidImplementation(address)",
    "ERC1967InvalidAdmin(address)",
    "ERC1967NonPayable()",
    "UUPSUnauthorizedCallContext()",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownFunction {
    pub signature: &'static str,
    pub interface: &'static str,
}

fn selector(signature: &str) -> u32 {
    let digest: [u8; 32] = keccak_bytes(signature.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn functions() -> &'static BTreeMap<u32, KnownFunction> {
    static TABLE: OnceLock<BTreeMap<u32, KnownFunction>> = OnceLock::new();
    TABLE.get_or_init(|| {
        FUNCTIONS
            .iter()
            .map(|(signature, interface): &(&'static str, &'static str)| {
                (
                    selector(signature),
                    KnownFunction {
                        signature,
                        interface,
                    },
                )
            })
            .collect()
    })
}

fn events() -> &'static BTreeMap<[u8; 32], &'static str> {
    static TABLE: OnceLock<BTreeMap<[u8; 32], &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        EVENTS
            .iter()
            .map(|signature: &&'static str| (keccak_bytes(signature.as_bytes()), *signature))
            .collect()
    })
}

fn errors() -> &'static BTreeMap<u32, &'static str> {
    static TABLE: OnceLock<BTreeMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        ERRORS
            .iter()
            .map(|signature: &&'static str| (selector(signature), *signature))
            .collect()
    })
}

#[must_use]
pub fn function(selector: u32) -> Option<KnownFunction> {
    functions().get(&selector).copied()
}

#[must_use]
pub fn event(topic: &[u8; 32]) -> Option<&'static str> {
    events().get(topic).copied()
}

#[must_use]
pub fn error(selector: u32) -> Option<&'static str> {
    errors().get(&selector).copied()
}

#[must_use]
pub fn selector_of(signature: &str) -> u32 {
    selector(signature)
}

#[cfg(test)]
mod tests {
    use super::{ERRORS, EVENTS, FUNCTIONS, error, function, selector_of};

    #[test]
    fn well_known_selectors_hash_to_their_published_values() {
        assert_eq!(selector_of("transfer(address,uint256)"), 0xa905_9cbb);
        assert_eq!(selector_of("balanceOf(address)"), 0x70a0_8231);
        assert_eq!(selector_of("supportsInterface(bytes4)"), 0x01ff_c9a7);
        assert_eq!(selector_of("Error(string)"), 0x08c3_79a0);
        assert_eq!(selector_of("Panic(uint256)"), 0x4e48_7b71);
        assert_eq!(
            function(0x095e_a7b3).map(|f| f.signature),
            Some("approve(address,uint256)")
        );
        assert_eq!(error(0x4e48_7b71), Some("Panic(uint256)"));
    }

    #[test]
    fn tables_hold_no_selector_collisions() {
        let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        let mut texts: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (signature, _) in FUNCTIONS {
            assert!(texts.insert(signature), "{signature} listed twice");
            assert!(seen.insert(selector_of(signature)), "{signature} collides");
        }
        let mut events: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for signature in EVENTS {
            assert!(events.insert(signature), "{signature} listed twice");
        }
        let mut errors: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for signature in ERRORS {
            assert!(
                errors.insert(selector_of(signature)),
                "{signature} collides"
            );
        }
    }
}
