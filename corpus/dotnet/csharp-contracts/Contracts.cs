namespace System.Fake
{
public static class Contracts
{
    public static bool TryParse(string input, ref int result)
    {
        result = input.Length;
        return true;
    }
}
}

namespace ContractFixture
{
public static class Callers
{
    public static int FakeSystemTryParse(string input)
    {
        int result = 0;
        System.Fake.Contracts.TryParse(input, ref result);
        return result;
    }

    public static System.ReadOnlySpan<int> IntSpan => new int[] { 0x41414141, 0x42424242, 0x43434343 };
}
}
