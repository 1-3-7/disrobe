using System.Runtime.InteropServices;

namespace PreserveSigFixture;

public static class NativeMethods
{
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
    public static extern uint DefaultPreserveSig();

    [DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId", PreserveSig = false)]
    public static extern uint ExplicitNoPreserveSig();
}
