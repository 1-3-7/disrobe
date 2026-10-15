# pragma version 0.4.3

event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    value: uint256

event Flagged:
    who: indexed(address)
    flag: bool

balanceOf: public(HashMap[address, uint256])
totalSupply: public(uint256)
owner: public(address)
label: public(String[32])
flags: HashMap[address, bool]


@deploy
def __init__():
    self.owner = msg.sender


@external
def transfer(receiver: address, amount: uint256) -> bool:
    assert self.balanceOf[msg.sender] >= amount, "ledger: balance"
    self.balanceOf[msg.sender] -= amount
    self.balanceOf[receiver] += amount
    log Transfer(sender=msg.sender, receiver=receiver, value=amount)
    return True


@external
@payable
def deposit():
    self.balanceOf[msg.sender] += msg.value
    self.totalSupply += msg.value


@external
@view
def peek(who: address) -> uint256:
    return self.balanceOf[who]


@external
@pure
def combine(a: uint8, b: int128, c: bytes4) -> int256:
    return convert(a, int256) + convert(b, int256) + convert(convert(c, uint32), int256)


@external
def setFlag(flag: bool, note: Bytes[64]) -> uint256:
    self.flags[msg.sender] = flag
    log Flagged(who=msg.sender, flag=flag)
    return len(note)


@external
@pure
def total(values: DynArray[uint256, 8]) -> uint256:
    acc: uint256 = 0
    for v: uint256 in values:
        acc += v
    return acc


@external
def setLabel(text: String[32]):
    assert msg.sender == self.owner, "ledger: owner"
    self.label = text


@external
@pure
def wide(a: uint16, b: uint64, c: uint128, d: int8, e: bytes32) -> uint256:
    return convert(a, uint256) + convert(b, uint256) + convert(c, uint256)
