using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Disrobe.Samples.Interop
{
    public static class Kernel
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32", EntryPoint = "GetModuleHandleA", CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        public static extern IntPtr ModuleHandle(string name);

        [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern int MessageBox(IntPtr window, string text, string caption, uint type);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "printf")]
        public static extern int Print(string format, int value);

        [DllImport("ntdll.dll", EntryPoint = "#1", PreserveSig = false)]
        public static extern void OrdinalOne();

        [DllImport("advapi32.dll", CallingConvention = CallingConvention.ThisCall, BestFitMapping = true, ThrowOnUnmappableChar = false)]
        public static extern int ThisCallStub(IntPtr self);

        [DllImport("libc", CallingConvention = CallingConvention.FastCall)]
        public static extern int getpid();
    }

    internal sealed class Nested
    {
        internal static class Native
        {
            [DllImport("ws2_32.dll", SetLastError = true)]
            internal static extern int WSAGetLastError();
        }
    }

    public static partial class Generated
    {
        [LibraryImport("kernel32.dll", SetLastError = true)]
        public static partial uint GetCurrentProcessId();

        [LibraryImport("kernel32.dll", EntryPoint = "GetEnvironmentVariableW", StringMarshalling = StringMarshalling.Utf16)]
        public static partial uint ReadEnvironment(string name, IntPtr buffer, uint size);

        [LibraryImport("libz", EntryPoint = "zlibVersion")]
        public static partial IntPtr ZlibVersion();

        [LibraryImport("libexample", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int Greet(string who);
    }

    public static class Exports
    {
        [UnmanagedCallersOnly(EntryPoint = "disrobe_add")]
        public static int Add(int a, int b) => a + b;

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        public static int Twice(int value) => value * 2;

        [UnmanagedCallersOnly(EntryPoint = "disrobe_stdcall", CallConvs = new[] { typeof(CallConvStdcall), typeof(CallConvSuppressGCTransition) })]
        public static void Tick() { }
    }

    [ComImport]
    [Guid("00000000-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IUnknownLike
    {
        void Ignored();
    }

    [ComImport]
    [Guid("6D5140C1-7436-11CE-8034-00AA006009FA")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IServiceProviderLike
    {
        [PreserveSig]
        int QueryService(ref Guid service, ref Guid riid, out IntPtr result);
    }

    [ComImport]
    [Guid("13709620-C279-11CE-A49E-444553540000")]
    public class ShellApplication
    {
    }
}
