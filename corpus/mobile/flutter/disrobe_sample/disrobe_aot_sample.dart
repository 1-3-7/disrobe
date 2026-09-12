import 'dart:io';
import 'dart:math';

class InventoryItem {
  final String skuLabel;
  final int quantityOnHand;
  final double unitPriceUsd;

  const InventoryItem(this.skuLabel, this.quantityOnHand, this.unitPriceUsd);

  double extendedValue() => quantityOnHand * unitPriceUsd;

  bool get isBackordered => quantityOnHand <= 0;

  InventoryItem withRestock(int incomingUnits) =>
      InventoryItem(skuLabel, quantityOnHand + incomingUnits, unitPriceUsd);
}

class WarehouseLedger {
  final List<InventoryItem> trackedItems;

  WarehouseLedger(this.trackedItems);

  double totalCarryingValue() {
    double running = 0.0;
    for (final InventoryItem entry in trackedItems) {
      running += entry.extendedValue();
    }
    return running;
  }

  int countBackordered() =>
      trackedItems.where((InventoryItem e) => e.isBackordered).length;

  InventoryItem? mostValuable() {
    if (trackedItems.isEmpty) {
      return null;
    }
    InventoryItem best = trackedItems.first;
    for (final InventoryItem candidate in trackedItems) {
      if (candidate.extendedValue() > best.extendedValue()) {
        best = candidate;
      }
    }
    return best;
  }
}

int fibonacciStep(int depth) {
  if (depth < 2) {
    return depth;
  }
  return fibonacciStep(depth - 1) + fibonacciStep(depth - 2);
}

String classifyMagnitude(double value) {
  if (value > 10000.0) {
    return 'enterprise-tier';
  }
  if (value > 1000.0) {
    return 'mid-market-tier';
  }
  return 'starter-tier';
}

void main(List<String> commandLineArgs) {
  final Random deterministicRng = Random(20260613);
  final List<InventoryItem> seeded = <InventoryItem>[
    InventoryItem('widget-alpha', 42, 19.95),
    InventoryItem('gadget-bravo', 0, 149.50),
    InventoryItem('sprocket-charlie', 7, 2400.00),
    InventoryItem('flange-delta', 130, 4.25),
  ];
  final WarehouseLedger ledger = WarehouseLedger(seeded);

  final double carrying = ledger.totalCarryingValue();
  final int backordered = ledger.countBackordered();
  final InventoryItem? top = ledger.mostValuable();
  final int fib = fibonacciStep(12 + deterministicRng.nextInt(3));

  stdout.writeln('total carrying value: ${carrying.toStringAsFixed(2)}');
  stdout.writeln('backordered lines: $backordered');
  stdout.writeln('most valuable sku: ${top?.skuLabel ?? "none"}');
  stdout.writeln('magnitude class: ${classifyMagnitude(carrying)}');
  stdout.writeln('fibonacci probe: $fib');
}
