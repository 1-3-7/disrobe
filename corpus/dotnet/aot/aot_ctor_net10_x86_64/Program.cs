using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Tidewater.Moorings
{
    internal enum Tide : int
    {
        Slack = 0,
        Flood = 3,
        Ebb = 7,
    }

    internal sealed class Berth
    {
        private readonly bool _lit;
        private readonly byte _lane;
        private readonly sbyte _drift;
        private readonly short _draft;
        private readonly ushort _beam;
        private readonly char _code;
        private readonly int _depth;
        private readonly uint _flags;
        private readonly long _tonnage;
        private readonly long _displacement;
        private readonly ulong _serial;
        private readonly float _heading;
        private readonly double _latitude;
        private readonly Tide _tide;
        private readonly string _name;
        private readonly int _fender0;
        private readonly int _fender1;
        private readonly int _fender2;
        private readonly int _fender3;
        private readonly int _fender4;
        private readonly int _fender5;
        private readonly int _fender6;
        private readonly int _fender7;
        private readonly int _fender8;
        private readonly int _fender9;
        private readonly int _fender10;
        private readonly int _fender11;
        private readonly int _fender12;
        private readonly int _fender13;
        private readonly int _fender14;
        private readonly int _fender15;
        private readonly int _fender16;
        private readonly int _fender17;
        private readonly int _fender18;
        private readonly int _fender19;
        private readonly int _fender20;
        private readonly int _fender21;
        private readonly int _fender22;
        private readonly int _fender23;
        private readonly long _bollard0;
        private readonly long _bollard1;
        private readonly long _bollard2;
        private readonly long _bollard3;
        private readonly short _cleat0;
        private readonly short _cleat1;
        private readonly byte _light0;
        private readonly byte _light1;
        private readonly int _tail;
        private readonly long _mark;

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal Berth()
        {
            _lit = true;
            _lane = 200;
            _drift = -5;
            _draft = -1234;
            _beam = 40000;
            _code = 'K';
            _depth = 123456789;
            _flags = 0xC0FFEE11;
            _tonnage = -77;
            _displacement = 0x7FFFFFFF;
            _serial = 0x1122334455667788;
            _heading = 182.5f;
            _latitude = 51.4779;
            _tide = Tide.Ebb;
            _name = "north pier";
            _fender0 = 1000;
            _fender1 = 1001;
            _fender2 = 1002;
            _fender3 = 1003;
            _fender4 = 1004;
            _fender5 = 1005;
            _fender6 = 1006;
            _fender7 = 1007;
            _fender8 = 1008;
            _fender9 = 1009;
            _fender10 = 1010;
            _fender11 = 1011;
            _fender12 = 1012;
            _fender13 = 1013;
            _fender14 = 1014;
            _fender15 = 1015;
            _fender16 = 1016;
            _fender17 = 1017;
            _fender18 = 1018;
            _fender19 = 1019;
            _fender20 = 1020;
            _fender21 = 1021;
            _fender22 = 1022;
            _fender23 = 1023;
            _bollard0 = 2000;
            _bollard1 = -2001;
            _bollard2 = 0x100000000;
            _bollard3 = 2003;
            _cleat0 = 300;
            _cleat1 = -301;
            _light0 = 7;
            _light1 = 255;
            _tail = -1;
            _mark = 4096;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal long Checksum()
        {
            long total = 0;
            total += _lit ? 1 : 0;
            total += _lane + _drift + _draft + _beam + _code + _depth + _flags;
            total += _tonnage + _displacement + (long)_serial + (long)_heading + (long)_latitude + (long)_tide;
            total += _name.Length;
            total += _fender0 + _fender1 + _fender2 + _fender3 + _fender4 + _fender5 + _fender6 + _fender7;
            total += _fender8 + _fender9 + _fender10 + _fender11 + _fender12 + _fender13 + _fender14 + _fender15;
            total += _fender16 + _fender17 + _fender18 + _fender19 + _fender20 + _fender21 + _fender22 + _fender23;
            total += _bollard0 + _bollard1 + _bollard2 + _bollard3 + _cleat0 + _cleat1 + _light0 + _light1;
            total += _tail + _mark;
            return total;
        }
    }

    internal sealed class Buoy
    {
        private readonly int _colour;
        private readonly byte _flashes;
        private readonly long _period;

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal Buoy()
        {
            _colour = 0x00FF7F;
            _flashes = 3;
            _period = 90;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal long Checksum() => _colour + _flashes + _period;
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            Berth berth = new Berth();
            Buoy buoy = new Buoy();
            long total = berth.Checksum() + buoy.Checksum() + args.Length;
            foreach (FieldInfo field in typeof(Berth).GetFields(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                total += field.Name.Length;
                object? value = field.GetValue(berth);
                total += value is null ? 0 : value.GetHashCode() & 0xFF;
            }
            foreach (FieldInfo field in typeof(Buoy).GetFields(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                total += field.Name.Length;
                object? value = field.GetValue(buoy);
                total += value is null ? 0 : value.GetHashCode() & 0xFF;
            }
            foreach (ConstructorInfo constructor in typeof(Berth).GetConstructors(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                total += constructor.ToString()!.Length;
            }
            foreach (ConstructorInfo constructor in typeof(Buoy).GetConstructors(
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                total += constructor.ToString()!.Length;
            }
            Console.WriteLine(total.ToString(CultureInfo.InvariantCulture));
            return total == 0 ? 1 : 0;
        }
    }
}
