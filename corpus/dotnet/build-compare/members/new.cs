[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Shop
{
    public class Cart
    {
        private int items;
        public decimal Total;

        public string Owner { get; set; }

        public string Note { get; set; }

        public event System.EventHandler Emptied;

        public void Add(int quantity)
        {
            items += quantity;
        }

        public void Remove(int quantity)
        {
            items -= quantity;
            if (items == 0)
            {
                Emptied?.Invoke(this, System.EventArgs.Empty);
            }
        }

        public int Count()
        {
            return items;
        }

        public sealed class Line
        {
            public int Sku;
        }
    }

    public class Voucher
    {
        public string Code = "NONE";
    }

    public interface IPricing
    {
        decimal Price(int sku);

        decimal Discount(int sku);
    }
}
