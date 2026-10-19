[assembly: System.Runtime.Versioning.TargetFramework(".NETCoreApp,Version=v9.0", FrameworkDisplayName = ".NET 9.0")]

namespace Platform
{
    using System;
    using System.Runtime.InteropServices;

    public static class Native
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr window, string text, string caption, uint type);

        [DllImport("kernel32.dll", EntryPoint = "Sleep")]
        public static extern void Pause(uint milliseconds);

        [DllImport("kernel32.dll")]
        public static extern int GetCurrentProcessId();
    }
}
