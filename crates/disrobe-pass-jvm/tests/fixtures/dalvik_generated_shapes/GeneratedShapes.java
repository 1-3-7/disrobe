import java.util.ArrayList;
import java.util.List;

public final class GeneratedShapes {
    public static void loopWithElseIfChain()
    {
        List<Integer> t = new ArrayList<>();
        int a = 5;
        int b = 6;
        int c = 2;
        int d = 4;
        int e = 8;
        int n1 = 0;
        while (n1 < 3 && (!(12 <= (6 / 7)) || n1 == 0))
        {
            n1++;
            a = (((b / 1) / 3) % 1000);
            if (!((e - b) <= (13 % 5)))
            {
                e = ((c <= ((e * e) % 97)) ? (c - a) : e);
            }
            else if ((c - b) != d)
            {
                if (b <= ((e * 6) % 97))
                {
                    t.add((a % 7));
                    a = (12 % 1000);
                    t.add((d - d));
                }
            }
            else
            {
                Sink.emit(((d + d) + ((c * 10) % 97)));
            }
            Sink.emit((((a - e) <= d) ? (0 % 4) : ((a * a) % 97)));
            e = Sink.f(((b * a) % 97), 4);
        }
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void doWhileAroundGuardedWhile()
    {
        List<Integer> t = new ArrayList<>();
        int a = 7;
        int b = 9;
        int c = 8;
        int d = 5;
        int e = 9;
        c = (((b + d) - (11 + d)) % 1000);
        int n1 = 0;
        do
        {
            n1++;
            Sink.emit(b);
            if ((b + a) != (a / 3))
            {
                int n2 = 0;
                while (n2 < 1 && ((10 <= (e + a)) && e > 1 || n2 == 0))
                {
                    n2++;
                    t.add((d - b));
                    t.add(b);
                    a = (((e - b) + (c + 1)) % 1000);
                }
                Sink.emit((((d * 10) % 97) - 5));
                e = Math.max((12 % 3), (c - 4));
            }
            t.add(c);
        } while (n1 < 4 && ((b == 7) && c > 2 || n1 == 1));
        Sink.emit(Math.max((e / 2), ((c * d) % 97)));
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void tryFinallyAroundDoWhile()
    {
        List<Integer> t = new ArrayList<>();
        int a = 4;
        int b = 7;
        int c = 1;
        int d = 5;
        int e = 8;
        b *= e;
        b %= 1000;
        try
        {
            d = d / (((3 - 9) + a) % 3);
            t.add((9 / 3));
            int n1 = 0;
            do
            {
                n1++;
                t.add(((15 * d) % 97));
            } while (n1 < 3 && (!((d / 3) == (b % 7)) || n1 == 1));
        }
        catch (ArithmeticException error)
        {
            Sink.emit("zero");
        }
        finally
        {
            Sink.emit(e);
        }
        Sink.emit(e);
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void tryInsideCountedLoop()
    {
        List<Integer> t = new ArrayList<>();
        int a = 9;
        int b = 7;
        int c = 0;
        int d = 4;
        int e = 0;
        for (int i1 = 3; i1 <= 5; i1++)
        {
            d = (d + i1) % 1000;
            Sink.emit(((9 % 4) / 3));
            Sink.emit((d % 7));
            try
            {
                a = b / (((e % 10) + d) % 3);
                if (((a % 7) == e) && e > 6)
                {
                    t.add(((b * 3) % 97));
                    c = ((0 + (6 / 1)) % 1000);
                    Sink.emit(((!((c / 2) > ((12 * 12) % 97))) ? (d / 5) : (12 % 5)));
                }
                try
                {
                    c = b / (((b + e) + c) % 3);
                    b = ((((3 + 18) * ((0 * 4) % 97)) % 97) % 1000);
                    t.add((e + 19));
                }
                catch (ArithmeticException error)
                {
                    Sink.emit("zero");
                }
                finally
                {
                    Sink.emit(e);
                }
            }
            catch (ArithmeticException error)
            {
                Sink.emit("zero");
            }
            for (int i2 = 3; i2 <= 4; i2++)
            {
                c = (a + i2) % 1000;
                e = (((c < (16 - e)) || d == 8) ? (e - d) : (11 / 3));
                for (int i3 = 3; i3 <= 5; i3++)
                {
                    c = (c + i3) % 1000;
                    t.add(13);
                    e = (((d / 7) / 4) % 1000);
                    d -= 16;
                    d %= 1000;
                    t.add(16);
                    if ((7 != a) || d == 3) break;
                }
                if (!((e - c) <= (a - b))) continue;
                Sink.emit(c);
            }
        }
        t.add((c + 0));
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void valueAssignedInsideTry()
    {
        List<Integer> t = new ArrayList<>();
        int a = 0;
        int b = 1;
        int c = 4;
        int d = 5;
        int e = 4;
        switch ((((b + c)) % 4 + 4) % 4)
        {
            case 0:
                {
                    b = ((((17 - a) != e) || a == 7) ? (d - 1) : (11 / 3));
                    break;
                }
            case 1:
            case 2:
                {
                    try
                    {
                        d = b / (((13 / 7) + e) % 3);
                        int n1 = 0;
                        while (n1 < 4 && (((e / 2) == ((a * d) % 97)) && c > 4 || n1 == 0))
                        {
                            n1++;
                            t.add(a);
                            b -= 14;
                            b %= 1000;
                            d -= (c + d);
                            d %= 1000;
                            if ((c == c) && b > 1) break;
                        }
                        Sink.emit((((7 / 1) - e) % 1000));
                    }
                    catch (ArithmeticException error)
                    {
                        Sink.emit("zero");
                    }
                    a = ((c != (e % 8)) ? 8 : (a / 6));
                    c = ((((9 + 19) * (a - 12)) % 97) % 1000);
                    break;
                }
            default:
                {
                    a *= (d % 4);
                    a %= 1000;
                    if (t.contains((3 + a)))
                    {
                        t.add((d / 4));
                        t.add((d / 4));
                        c = ((t.contains((e % 2))) ? (11 / 2) : (15 + d));
                    }
                    else
                    {
                        if ((a - a) < (4 / 4))
                        {
                            Sink.emit((((12 % 3) != 7) ? ((d * c) % 97) : (b + b)));
                            t.add(e);
                        }
                    }
                    if (t.contains((16 + d)))
                    {
                        Sink.emit((e % 1000));
                        int n2 = 0;
                        do
                        {
                            n2++;
                            t.add(6);
                            if (t.contains(c)) break;
                        } while (n2 < 5 && (t.contains((c / 2)) || n2 == 1));
                        c *= ((c * a) % 97);
                        c %= 1000;
                    }
                    b = ((t.contains(b)) ? (b + 5) : 16);
                    break;
                }
        }
        int n3 = 0;
        while (n3 < 5 && ((a + 2) >= 0 || n3 == 0))
        {
            n3++;
            if (!(c == (e + c)))
            {
                switch ((((b + c)) % 4 + 4) % 4)
                {
                    case 0:
                        {
                            Sink.emit((((d % 9) / 4) % 1000));
                            d *= (e % 4);
                            d %= 1000;
                            t.add(d);
                            b = Sink.f((d % 5), 2);
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            a -= ((d * 8) % 97);
                            a %= 1000;
                            a *= 11;
                            a %= 1000;
                            break;
                        }
                }
                t.add((10 + 14));
            }
            Sink.emit(((6 / 7) % 1000));
            Sink.emit((((10 % 7) / 4) % 1000));
        }
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void splitHandlersBesideFinally()
    {
        List<Integer> t = new ArrayList<>();
        int a = 8;
        int b = 2;
        int c = 1;
        int d = 4;
        int e = 2;
        d = ((((b / 2) * ((e * e) % 97)) % 97) % 1000);
        int n1 = 0;
        while (n1 < 1 && (((e / 2) < 19) || c == 2 || n1 == 0))
        {
            n1++;
            t.add(12);
            if (!((e - c) > (a / 7)))
            {
                switch (((e) % 4 + 4) % 4)
                {
                    case 0:
                        {
                            b = (d % 1000);
                            d += (e + 3);
                            d %= 1000;
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            Sink.emit((((b >= 4) && c > 2) ? b : (13 / 2)));
                            Sink.emit((d % 1000));
                            Sink.emit(Math.max(9, ((b * d) % 97)));
                            Sink.emit(Sink.f(((1 * 3) % 97), 2));
                            break;
                        }
                }
            }
            else if (((a / 5) == (7 / 2)) || a == 0)
            {
                switch ((((c % 9)) % 4 + 4) % 4)
                {
                    case 0:
                        {
                            t.add(b);
                            b = (d % 1000);
                            Sink.emit(((a - a) % 1000));
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            c -= (d / 5);
                            c %= 1000;
                            e = Sink.f(((1 * a) % 97), 2);
                            t.add((d - b));
                            t.add((c % 9));
                            break;
                        }
                }
            }
            else
            {
                if ((d + 8) != (d / 3))
                {
                    b = (a % 1000);
                    Sink.emit(((((b * 8) % 97) <= a) ? (b % 8) : b));
                    t.add((e / 3));
                    d = Sink.f(c, 2);
                }
                else
                {
                    t.add(c);
                    t.add(((a * 4) % 97));
                }
                Sink.emit(Sink.f((2 + c), 2));
                if (b < (b / 1))
                {
                    Sink.emit(Math.max((0 / 7), ((d * c) % 97)));
                    c = (t.size() > 3 ? t.get(3) : (19 / 4));
                    d -= ((8 * c) % 97);
                    d %= 1000;
                }
                else
                {
                    e += d;
                    e %= 1000;
                }
            }
            if ((e == 14) && d > 3)
            {
                d += (c % 4);
                d %= 1000;
                Sink.emit(0);
                try
                {
                    d = e / ((((b * 8) % 97) + b) % 3);
                    e = Sink.f(((e * 5) % 97), 2);
                    c = ((((d + e) >= 6) && d > 8) ? (9 / 5) : (0 % 3));
                }
                catch (ArithmeticException error)
                {
                    Sink.emit("zero");
                }
                finally
                {
                    Sink.emit(a);
                }
                if (!(11 < (5 % 4)))
                {
                    c = Math.max(5, ((13 * d) % 97));
                    b = (((3 + d) % 3) % 1000);
                }
                else if ((b > (e + a)) && c > 9)
                {
                    b += ((d * c) % 97);
                    b %= 1000;
                    t.add((8 - 10));
                    Sink.emit(Math.max(d, (b + 15)));
                    a *= d;
                    a %= 1000;
                }
            }
            else
            {
                try
                {
                    e = 7 / ((b + c) % 3);
                    t.add((4 % 9));
                    t.add((e - 7));
                    e *= 13;
                    e %= 1000;
                    b = Math.max(10, a);
                }
                catch (ArithmeticException error)
                {
                    Sink.emit("zero");
                }
                finally
                {
                    Sink.emit(d);
                }
            }
            c = (t.size() > 1 ? t.get(1) : b);
            if ((a + d) != (d - d)) break;
        }
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void liveAcrossCoveredFixupBlock()
    {
        List<Integer> t = new ArrayList<>();
        int a = 1;
        int b = 1;
        int c = 7;
        int d = 9;
        int e = 5;
        try
        {
            b = d / ((14 + e) % 3);
            t.add((12 + 14));
            t.add(b);
            for (int i1 = 2; i1 <= 4; i1++)
            {
                d = (b + i1) % 1000;
                switch ((((c + 13)) % 4 + 4) % 4)
                {
                    case 0:
                        {
                            Sink.emit((t.size() > 0 ? t.get(0) : 15));
                            t.add((e / 6));
                            d -= (9 % 9);
                            d %= 1000;
                            break;
                        }
                    case 1:
                    case 2:
                        {
                            d = (t.size() > 1 ? t.get(1) : d);
                            break;
                        }
                }
                a -= a;
                a %= 1000;
                t.add((c % 5));
                int n2 = 0;
                while (n2 < 2 && (!((c - b) != (6 + b)) || n2 == 0))
                {
                    n2++;
                    t.add((1 + d));
                    t.add(((6 * a) % 97));
                    t.add((e % 10));
                }
            }
            Sink.emit(((c % 5) / 3));
        }
        catch (ArithmeticException error)
        {
            Sink.emit("zero");
        }
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }

    public static void tryAroundOnlyLiteralRemainders()
    {
        List<Integer> t = new ArrayList<>();
        int a = 6;
        int b = 0;
        int c = 4;
        int d = 2;
        int e = 2;
        switch ((((4 - d)) % 4 + 4) % 4)
        {
            case 0:
                {
                    if ((8 - c) >= ((17 * a) % 97))
                    {
                        e += (c % 7);
                        e %= 1000;
                        switch ((((19 - a)) % 4 + 4) % 4)
                        {
                            case 0:
                                {
                                    e = Math.max((e - 8), (c / 5));
                                    break;
                                }
                            case 1:
                            case 2:
                                {
                                    Sink.emit(Sink.f((e % 5), 4));
                                    e += (c / 5);
                                    e %= 1000;
                                    break;
                                }
                        }
                    }
                    else
                    {
                        switch ((((c + 7)) % 4 + 4) % 4)
                        {
                            case 0:
                                {
                                    b -= 15;
                                    b %= 1000;
                                    Sink.emit(((17 == (e + a)) ? (e / 3) : (12 + a)));
                                    break;
                                }
                            case 1:
                            case 2:
                                {
                                    Sink.emit(((t.contains((16 / 6))) ? (e / 5) : (a / 4)));
                                    Sink.emit((((c % 9) % 8) % 1000));
                                    a -= ((3 * 18) % 97);
                                    a %= 1000;
                                    a = Math.max((b / 1), (e / 6));
                                    break;
                                }
                            default:
                                {
                                    Sink.emit((t.size() > 1 ? t.get(1) : (c / 7)));
                                    break;
                                }
                        }
                        t.add((a + d));
                        Sink.emit((c % 7));
                        for (int i1 = 0; i1 <= 2; i1++)
                        {
                            e = (e + i1) % 1000;
                            c = (e % 1000);
                        }
                    }
                    break;
                }
            case 1:
            case 2:
                {
                    d = (((b - b) + (b / 3)) % 1000);
                    break;
                }
            default:
                {
                    switch (((((10 * 6) % 97)) % 4 + 4) % 4)
                    {
                        case 0:
                            {
                                t.add(((c * e) % 97));
                                for (int i2 = 1; i2 <= 1; i2++)
                                {
                                    e = (c + i2) % 1000;
                                    t.add((c / 7));
                                }
                                for (int i3 = 3; i3 <= 6; i3++)
                                {
                                    b = (c + i3) % 1000;
                                    b -= (9 + e);
                                    b %= 1000;
                                    t.add(a);
                                    a *= c;
                                    a %= 1000;
                                    e = ((c / 2) % 1000);
                                }
                                Sink.emit(11);
                                break;
                            }
                        case 1:
                        case 2:
                            {
                                for (int i4 = 3; i4 <= 5; i4++)
                                {
                                    a = (e + i4) % 1000;
                                    c = (((19 + a) % 4) % 1000);
                                    b = (((12 / 5) - (e / 7)) % 1000);
                                    e -= e;
                                    e %= 1000;
                                    if ((8 - d) == (d % 4)) break;
                                }
                                int n5 = 0;
                                while (n5 < 3 && (((2 + c) > (e % 5)) || d == 7 || n5 == 0))
                                {
                                    n5++;
                                    d = (t.size() > 1 ? t.get(1) : c);
                                    b = ((((c / 6) >= (d / 5)) && a > 1) ? 6 : a);
                                    if (t.contains(((d * c) % 97))) break;
                                }
                                break;
                            }
                    }
                    if (((d + d) == (e / 4)) || e == 1)
                    {
                        e = Sink.f((d - b), 4);
                        int n6 = 0;
                        while (n6 < 3 && ((c + a) > c || n6 == 0))
                        {
                            n6++;
                            t.add((e - 2));
                            c = ((!(18 == b)) ? (c + e) : (b % 7));
                            t.add((2 + c));
                        }
                        t.add((5 % 2));
                        Sink.emit(((b / 5) / 7));
                    }
                    else if ((c >= a) && a > 3)
                    {
                        Sink.emit(b);
                        int n7 = 0;
                        while (n7 < 5 && (e > 10 || n7 == 0))
                        {
                            n7++;
                            Sink.emit((((b - 7) / 2) % 1000));
                            c = (3 % 1000);
                        }
                        if (t.contains((2 - c)))
                        {
                            e = (t.size() > 0 ? t.get(0) : (5 / 2));
                            Sink.emit(((((8 * c) % 97) / 4) % 1000));
                        }
                        else
                        {
                            c = (((9 / 4) % 9) % 1000);
                        }
                        for (int i8 = 2; i8 <= 6; i8++)
                        {
                            e = (c + i8) % 1000;
                            a = (((6 * ((c * 0) % 97)) % 97) % 1000);
                            Sink.emit((t.size() > 1 ? t.get(1) : (e % 6)));
                            Sink.emit(((((4 + d) < ((14 * a) % 97)) && b > 5) ? (3 - a) : (b / 6)));
                            if ((2 - 13) < c) continue;
                            Sink.emit(b);
                        }
                    }
                    Sink.emit((((e + a) >= (a / 4)) ? (d % 5) : (13 - b)));
                    e -= (1 + 12);
                    e %= 1000;
                    break;
                }
        }
        for (int i9 = 0; i9 <= 1; i9++)
        {
            c = (a + i9) % 1000;
            Sink.emit(Math.max(((d * b) % 97), ((16 * e) % 97)));
            if (((a % 6) < 6) || a == 5) break;
        }
        if (t.contains(((b * 10) % 97)))
        {
            try
            {
                a = d / (((16 / 5) + a) % 3);
                for (int i10 = 1; i10 <= 4; i10++)
                {
                    c = (b + i10) % 1000;
                    a *= ((a * 18) % 97);
                    a %= 1000;
                    a = ((((0 % 10) * (19 / 7)) % 97) % 1000);
                    t.add(6);
                    d = (((e % 8) / 5) % 1000);
                    if (!((a / 4) < 15)) break;
                }
            }
            catch (ArithmeticException error)
            {
                Sink.emit("zero");
            }
            Sink.emit(e);
            e -= e;
            e %= 1000;
        }
        else
        {
            t.add(d);
            Sink.emit((a % 1000));
            e += (3 - d);
            e %= 1000;
        }
        Sink.emit(a);
        Sink.emit(b);
        Sink.emit(c);
        Sink.emit(d);
        Sink.emit(e);
        Sink.emit(t);
    }
}
