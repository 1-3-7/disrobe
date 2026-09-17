using System;
using System.Text;

namespace GauntletSample
{
    public static class Algorithms
    {
        public static uint Fnv1a(string input)
        {
            uint hash = 2166136261u;
            foreach (char c in input)
            {
                hash ^= (byte)c;
                hash *= 16777619u;
            }
            return hash;
        }

        public static int Gcd(int a, int b)
        {
            while (b != 0)
            {
                int t = b;
                b = a % b;
                a = t;
            }
            return a < 0 ? -a : a;
        }

        public static int Collatz(int n)
        {
            int steps = 0;
            while (n != 1)
            {
                if (n % 2 == 0)
                    n /= 2;
                else
                    n = 3 * n + 1;
                steps++;
            }
            return steps;
        }
    }

    public sealed class StringVault
    {
        private readonly string _connectionString = "Server=gauntlet-db;Database=disrobe_test;";
        private readonly string _apiKey = "DISROBE_GAUNTLET_API_KEY_7749";
        private readonly string _secretToken = "DISROBE_SECRET_TOKEN_ALPHA";
        private readonly string _buildLabel = "gauntlet-build-v1";

        public string GetConnectionString() => _connectionString;
        public string GetApiKey() => _apiKey;
        public string GetSecretToken() => _secretToken;
        public string GetBuildLabel() => _buildLabel;
    }

    public sealed class TextProcessor
    {
        private readonly string _prefix;

        public TextProcessor(string prefix)
        {
            _prefix = prefix;
        }

        public string Process(string input)
        {
            if (input == null || input.Length == 0)
                return _prefix + ":empty";

            var sb = new StringBuilder();
            sb.Append(_prefix);
            sb.Append(':');
            bool inWord = false;
            int wordCount = 0;
            foreach (char c in input)
            {
                if (char.IsLetterOrDigit(c))
                {
                    if (!inWord) { wordCount++; inWord = true; }
                    sb.Append(char.ToUpper(c));
                }
                else
                {
                    inWord = false;
                    sb.Append(c);
                }
            }
            sb.Append(':');
            sb.Append(wordCount);
            return sb.ToString();
        }
    }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            StringVault vault = new StringVault();
            Console.WriteLine(vault.GetConnectionString());
            Console.WriteLine(vault.GetApiKey());
            Console.WriteLine(vault.GetSecretToken());
            Console.WriteLine(vault.GetBuildLabel());

            Console.WriteLine(Algorithms.Fnv1a("hello world"));
            Console.WriteLine(Algorithms.Gcd(48, 36));
            Console.WriteLine(Algorithms.Collatz(27));

            TextProcessor proc = new TextProcessor("result");
            Console.WriteLine(proc.Process("the quick brown fox"));
            Console.WriteLine(proc.Process(""));
            return 0;
        }
    }
}
