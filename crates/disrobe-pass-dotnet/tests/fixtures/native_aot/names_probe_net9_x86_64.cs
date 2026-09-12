using System;
using System.Globalization;

namespace DisrobeAotProbe;

public interface IGauge
{
    int Read();
}

public sealed class Widget
{
    public string Serial { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public override string ToString() =>
        string.Concat(this.Serial, "/", this.Label);
}

public sealed class Thermometer : IGauge
{
    private readonly int calibration;

    public Thermometer(int calibration) => this.calibration = calibration;

    public int Read() => 21 + this.calibration;

    public override string ToString() =>
        this.Read().ToString(CultureInfo.InvariantCulture);
}

public static class Program
{
    public static void Main()
    {
        Widget widget = new Widget { Serial = "SN-1", Label = "intake" };
        Console.WriteLine(widget.ToString());
        Console.WriteLine(widget.Serial);
        Console.WriteLine(widget.Label);

        IGauge gauge = new Thermometer(4);
        Console.WriteLine(gauge.Read().ToString(CultureInfo.InvariantCulture));
        Console.WriteLine(gauge.ToString());

        Console.WriteLine(typeof(Widget).Name);
        Console.WriteLine(typeof(IGauge).Name);
        Console.WriteLine(typeof(Thermometer).Name);
        Console.WriteLine(typeof(Program).Namespace);
    }
}
