using System;

namespace Sample;

public class Branches
{
    public int RefNotNullGuard(int[] items)
    {
        int result = 7;
        if (items != null)
        {
            result = items.Length;
        }
        return result;
    }

    public int RefNullGuard(int[] items)
    {
        int result = 7;
        if (items == null)
        {
            result = 0;
        }
        return result;
    }

    public int IntNonZeroGuard(int n)
    {
        int result = 1;
        if (n != 0)
        {
            result = n;
        }
        return result;
    }

    public int IntZeroGuard(int n)
    {
        int result = 1;
        if (n == 0)
        {
            result = 5;
        }
        return result;
    }

    public int LengthGuard(int[] data)
    {
        int result = 3;
        if (data.Length != 0)
        {
            result = data.Length;
        }
        return result;
    }

    public bool RefIsNull(int[] items)
    {
        if (items == null)
        {
            return true;
        }
        return false;
    }

    public bool HasLength(int[] data)
    {
        if (data.Length != 0)
        {
            return true;
        }
        return false;
    }
}
