using IronPython.Runtime;

namespace GreetModule
{
    public static class Greeter
    {
        public static string Greet()
        {
            return "hi from ironpython";
        }

        public static int Classify(PythonList items)
        {
            int total = items.Count;
            if (total > 10)
            {
                return 1;
            }
            return 0;
        }
    }
}
