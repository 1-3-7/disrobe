from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterator


WAREHOUSE_ID: str = "WH-BOSTON-42"
LOW_STOCK_THRESHOLD: int = 5
UNIT_TAX_RATE: float = 0.0875


@dataclass
class Item:
    sku: str
    name: str
    quantity: int
    unit_price: float
    tags: list[str] = field(default_factory=list)

    def total_value(self) -> float:
        return self.quantity * self.unit_price

    def is_low_stock(self) -> bool:
        return self.quantity < LOW_STOCK_THRESHOLD

    def discounted_price(self, pct: float) -> float:
        if not 0.0 <= pct <= 1.0:
            raise ValueError(f"discount must be in [0, 1], got {pct}")
        return self.unit_price * (1.0 - pct)


class Inventory:
    def __init__(self, warehouse_id: str = WAREHOUSE_ID) -> None:
        self._warehouse_id: str = warehouse_id
        self._items: dict[str, Item] = {}

    def add(self, item: Item) -> None:
        if item.sku in self._items:
            self._items[item.sku].quantity += item.quantity
        else:
            self._items[item.sku] = item

    def remove(self, sku: str, qty: int) -> bool:
        item: Item | None = self._items.get(sku)
        if item is None or item.quantity < qty:
            return False
        item.quantity -= qty
        if item.quantity == 0:
            del self._items[sku]
        return True

    def low_stock_report(self) -> list[str]:
        return [
            f"{item.sku}: {item.quantity} units remaining"
            for item in self._items.values()
            if item.is_low_stock()
        ]

    def total_value(self) -> float:
        return sum(item.total_value() for item in self._items.values())

    def taxed_value(self) -> float:
        return self.total_value() * (1.0 + UNIT_TAX_RATE)

    def search_by_tag(self, tag: str) -> Iterator[Item]:
        return (item for item in self._items.values() if tag in item.tags)

    def reorder_candidates(self, budget: float) -> list[Item]:
        affordable: list[Item] = [
            item for item in self._items.values()
            if item.is_low_stock() and item.unit_price <= budget
        ]
        affordable.sort(key=lambda i: i.unit_price)
        return affordable

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Inventory(warehouse={self._warehouse_id!r}, items={len(self)})"


def summarize(inv: Inventory) -> dict[str, object]:
    total: float = inv.total_value()
    taxed: float = inv.taxed_value()
    return {
        "warehouse": inv._warehouse_id,
        "item_count": len(inv),
        "gross_value": round(total, 2),
        "taxed_value": round(taxed, 2),
        "value_per_item": round(total / len(inv), 2) if len(inv) else 0.0,
        "sqrt_items": round(math.sqrt(len(inv)), 4),
    }
