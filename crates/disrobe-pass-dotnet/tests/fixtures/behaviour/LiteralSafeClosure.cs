using System;

namespace Behaviour
{
    public static class LiteralSafeClosure
    {
        public static void Run()
        {
            int local0 = 7;
            string field = "field";
            Func<string> render = () =>
            {
                int local1 = local0 + 1;
                return "local0 this.field <Run>b__0" + ':' + 'l' + ':' + field + ':' + local1;
            };
            Console.WriteLine(render());
        }
    }
}
