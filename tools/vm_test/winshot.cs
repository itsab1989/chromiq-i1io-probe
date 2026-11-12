// Photographs ONE window (found by a part of its title) with PrintWindow,
// at full resolution (DPI aware), so a picture shows only that window.
//   winshot.exe "<title part>" <out.png>
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;

public static class WinShot {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);

    public static int Main(string[] args) {
        try { return Run(args); }
        catch (Exception e) { System.IO.File.WriteAllText(args[1] + ".err", e.ToString()); return 3; }
    }

    static int Run(string[] args) {
        SetProcessDPIAware();
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, l) => {
            if (!IsWindowVisible(h)) return true;
            var sb = new StringBuilder(512);
            GetWindowTextW(h, sb, 512);
            if (sb.ToString().Contains(args[0])) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        if (found == IntPtr.Zero) return 2;
        RECT r;
        GetWindowRect(found, out r);
        using (var bmp = new Bitmap(r.R - r.L, r.B - r.T))
        using (var g = Graphics.FromImage(bmp)) {
            IntPtr dc = g.GetHdc();
            PrintWindow(found, dc, 2);
            g.ReleaseHdc(dc);
            bmp.Save(args[1], ImageFormat.Png);
        }
        return 0;
    }
}
