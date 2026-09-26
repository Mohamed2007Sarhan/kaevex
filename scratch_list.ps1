$code = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public class WinList {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    public static void Run() {
        EnumWindows((hWnd, lParam) => {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            try {
                var p = System.Diagnostics.Process.GetProcessById((int)pid);
                if (p.ProcessName.ToLower().Contains("kaevex")) {
                    StringBuilder t = new StringBuilder(256);
                    GetWindowText(hWnd, t, 256);
                    StringBuilder c = new StringBuilder(256);
                    GetClassName(hWnd, c, 256);
                    Console.WriteLine("PID: {0} | Name: {1} | Class: {2} | Title: {3}", pid, p.ProcessName, c.ToString(), t.ToString());
                }
            } catch {}
            return true;
        }, IntPtr.Zero);
    }
}
'@

Add-Type -TypeDefinition $code
[WinList]::Run()
