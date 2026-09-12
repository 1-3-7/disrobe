using System;
using System.Collections.Generic;
using System.Text;

namespace DisrobeObfuscarGauntlet
{
    public sealed class InventoryLedger
    {
        public const string LicenseBanner = "DISROBE_OBFUSCAR_LICENSE_BANNER_2026";
        public const string ConnectionString = "Server=gauntlet-host;Database=ledger;Trusted=true";
        private const int ScaleFactor = 7919;

        private readonly Dictionary<string, int> stockByItem;
        private int auditCounter;

        public string LedgerName { get; private set; }
        public int AuditCounter
        {
            get { return auditCounter; }
        }

        public InventoryLedger(string ledgerName)
        {
            LedgerName = ledgerName;
            stockByItem = new Dictionary<string, int>();
            auditCounter = 0;
        }

        public void RecordStock(string itemSku, int quantity)
        {
            if (quantity < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(quantity), "quantity must be non-negative");
            }
            if (stockByItem.ContainsKey(itemSku))
            {
                stockByItem[itemSku] = stockByItem[itemSku] + quantity;
            }
            else
            {
                stockByItem[itemSku] = quantity;
            }
            auditCounter = auditCounter + 1;
        }

        public long ComputeWeightedTotal()
        {
            long running = 0;
            foreach (KeyValuePair<string, int> pair in stockByItem)
            {
                int weight = ComputeSkuWeight(pair.Key);
                running = running + (long)pair.Value * weight;
            }
            return running * ScaleFactor;
        }

        private int ComputeSkuWeight(string sku)
        {
            int accumulator = 0;
            for (int i = 0; i < sku.Length; i++)
            {
                char current = sku[i];
                if (char.IsDigit(current))
                {
                    accumulator = accumulator + (current - '0') * 3;
                }
                else
                {
                    accumulator = accumulator + (int)current;
                }
            }
            return accumulator;
        }

        public string BuildReport()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(LicenseBanner);
            builder.Append('\n');
            builder.Append("ledger=");
            builder.Append(LedgerName);
            builder.Append(" audits=");
            builder.Append(auditCounter);
            builder.Append(" total=");
            builder.Append(ComputeWeightedTotal());
            return builder.ToString();
        }
    }

    public sealed class StockSnapshot
    {
        public string Sku { get; set; }
        public int Quantity { get; set; }

        public string Describe()
        {
            return string.Concat(Sku, ":", Quantity.ToString());
        }
    }

    public sealed class PriceCalculator
    {
        private const double TaxRate = 0.0825;

        public double ApplyTax(double subtotal)
        {
            if (subtotal <= 0.0)
            {
                return 0.0;
            }
            return subtotal + subtotal * TaxRate;
        }

        public double BulkDiscount(double subtotal, int units)
        {
            double rate = 0.0;
            if (units >= 100)
            {
                rate = 0.15;
            }
            else if (units >= 50)
            {
                rate = 0.08;
            }
            return subtotal - subtotal * rate;
        }
    }

    public sealed class SkuValidator
    {
        public bool IsWellFormed(string sku)
        {
            if (string.IsNullOrEmpty(sku))
            {
                return false;
            }
            int dashes = 0;
            for (int i = 0; i < sku.Length; i++)
            {
                if (sku[i] == '-')
                {
                    dashes = dashes + 1;
                }
            }
            return dashes == 1 && sku.Length >= 5;
        }

        public string Normalize(string sku)
        {
            return sku.Trim().ToUpperInvariant();
        }
    }

    public sealed class AuditTrail
    {
        private readonly List<string> entries;

        public AuditTrail()
        {
            entries = new List<string>();
        }

        public void Append(string action, int code)
        {
            entries.Add(string.Concat(action, "#", code.ToString()));
        }

        public int Count
        {
            get { return entries.Count; }
        }

        public string Flatten()
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < entries.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append('|');
                }
                builder.Append(entries[i]);
            }
            return builder.ToString();
        }
    }

    public sealed class WarehouseRouter
    {
        private const int RegionMask = 0x1F;

        public int RouteFor(string sku)
        {
            int hash = 17;
            for (int i = 0; i < sku.Length; i++)
            {
                hash = hash * 31 + sku[i];
            }
            return hash & RegionMask;
        }

        public string Label(int route)
        {
            switch (route)
            {
                case 0:
                    return "north";
                case 1:
                    return "south";
                default:
                    return "central";
            }
        }
    }

    public sealed class ReorderPolicy
    {
        public int Threshold { get; set; }

        public bool ShouldReorder(int onHand, int incoming)
        {
            return onHand + incoming < Threshold;
        }

        public int RecommendedQuantity(int onHand)
        {
            int target = Threshold * 2;
            int delta = target - onHand;
            if (delta < 0)
            {
                return 0;
            }
            return delta;
        }
    }

    public static class GauntletEntry
    {
        public static int Main(string[] args)
        {
            InventoryLedger ledger = new InventoryLedger("primary");
            ledger.RecordStock("SKU-001", 4);
            ledger.RecordStock("SKU-002", 9);
            ledger.RecordStock("SKU-001", 1);
            Console.WriteLine(ledger.BuildReport());

            StockSnapshot snapshot = new StockSnapshot();
            snapshot.Sku = "SKU-001";
            snapshot.Quantity = 5;
            Console.WriteLine(snapshot.Describe());

            PriceCalculator calculator = new PriceCalculator();
            Console.WriteLine(calculator.ApplyTax(100.0));

            SkuValidator validator = new SkuValidator();
            Console.WriteLine(validator.IsWellFormed("SKU-001"));

            AuditTrail trail = new AuditTrail();
            trail.Append("record", 200);
            Console.WriteLine(trail.Flatten());

            WarehouseRouter router = new WarehouseRouter();
            Console.WriteLine(router.Label(router.RouteFor("SKU-002")));

            ReorderPolicy policy = new ReorderPolicy();
            policy.Threshold = 20;
            Console.WriteLine(policy.RecommendedQuantity(3));

            return ledger.AuditCounter;
        }
    }
}
