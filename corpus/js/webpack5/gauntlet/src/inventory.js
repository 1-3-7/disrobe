export const STORE_NAME = "disrobe-webpack-gauntlet";

export class Warehouse {
  constructor(label) {
    this.label = label;
    this.stock = new Map();
  }

  restock(sku, quantity) {
    const current = this.stock.get(sku) || 0;
    this.stock.set(sku, current + quantity);
    return this.stock.get(sku);
  }

  available(sku) {
    return this.stock.get(sku) || 0;
  }

  summary() {
    let lines = [];
    for (const [sku, quantity] of this.stock) {
      lines.push(`${sku}=${quantity}`);
    }
    return `${this.label}: ${lines.join(",")}`;
  }
}
