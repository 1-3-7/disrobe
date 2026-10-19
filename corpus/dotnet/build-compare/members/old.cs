[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Shop
{
    public class Cart
    {
        private int count;
        public decimal Total;

        public string Owner { get; set; }

        public event System.EventHandler Changed;

        public void Add(int quantity)
        {
            count += quantity;
            Changed?.Invoke(this, System.EventArgs.Empty);
        }

        public void Clear()
        {
            count = 0;
        }

        public int Count()
        {
            return count;
        }
    }

    public class Coupon
    {
        public string Code = "NONE";
    }

    public interface IPricing
    {
        decimal Price(int sku);
    }
}
