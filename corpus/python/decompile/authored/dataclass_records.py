import dataclasses
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Address:
    street: str
    city: str
    postcode: str = ""


@dataclass(frozen=True)
class Point:
    x: float = 0.0
    y: float = 0.0

    def distance(self, other: "Point") -> float:
        return ((self.x - other.x) ** 2 + (self.y - other.y) ** 2) ** 0.5


@dataclass(order=True)
class Employee:
    sort_key: tuple = field(init=False, repr=False)
    name: str
    salary: int
    tags: List[str] = field(default_factory=list)
    manager: Optional["Employee"] = None
    address: Optional[Address] = None

    def __post_init__(self):
        self.sort_key = (-self.salary, self.name)

    def raise_salary(self, percent):
        self.salary = int(self.salary * (1 + percent / 100))
        self.__post_init__()
        return self.salary


def team_payroll(team):
    return sum(member.salary for member in team)


def chain_of_command(employee):
    chain = []
    current = employee
    while current is not None:
        chain.append(current.name)
        current = current.manager
    return chain


def relocate(employee, city):
    if employee.address is None:
        employee.address = Address("unknown", city)
    else:
        employee.address = dataclasses.replace(employee.address, city=city)
    return dataclasses.asdict(employee.address)


def as_rows(team):
    return [dataclasses.astuple(member)[1:3] for member in sorted(team)]
