// Reads another process's console screen, or types into its console input,
// for the VM test. Built as a WINDOWS (not console) program, so it has no
// console of its own and never prints anything into the window it attaches
// to. (A PowerShell helper did: after FreeConsole its host wrote "invalid
// handle" errors into the tool's window.)
//   conhelper.exe read <pid> <outfile>
//   conhelper.exe type <pid> <text>      ("\n" in text = Enter)
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class ConHelper {
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
    [StructLayout(LayoutKind.Sequential)] struct COORD { public short X; public short Y; }
    [StructLayout(LayoutKind.Sequential)] struct RECT16 { public short L, T, R, B; }
    [StructLayout(LayoutKind.Sequential)] struct CSBI { public COORD Size; public COORD Cursor; public short Attr; public RECT16 Win; public COORD Max; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CSBI i);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ReadConsoleOutputCharacterW(IntPtr h, StringBuilder b, uint n, COORD at, out uint read);
    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)] struct KEYREC {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public int KeyDown;
        [FieldOffset(8)] public ushort Repeat;
        [FieldOffset(10)] public ushort VKey;
        [FieldOffset(12)] public ushort VScan;
        [FieldOffset(14)] public char Ch;
        [FieldOffset(16)] public uint Ctrl;
    }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool WriteConsoleInputW(IntPtr h, KEYREC[] r, uint n, out uint w);

    public static int Main(string[] args) {
        int pid = int.Parse(args[1]);
        if (!AttachConsole(pid)) return 2;
        if (args[0] == "read") {
            IntPtr h = CreateFileW("CONOUT$", 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            CSBI info;
            if (!GetConsoleScreenBufferInfo(h, out info)) return 3;
            var sb = new StringBuilder();
            sb.AppendLine("COLUMNS " + info.Size.X + " CURSOR " + info.Cursor.X + "," + info.Cursor.Y);
            for (short y = 0; y <= info.Cursor.Y; y++) {
                var line = new StringBuilder(info.Size.X + 1);
                uint read;
                COORD at; at.X = 0; at.Y = y;
                ReadConsoleOutputCharacterW(h, line, (uint)info.Size.X, at, out read);
                string text = line.ToString();
                if (text.Length > (int)read) text = text.Substring(0, (int)read);
                sb.AppendLine(text.TrimEnd());
            }
            File.WriteAllText(args[2], sb.ToString(), new UTF8Encoding(false));
            return 0;
        }
        if (args[0] == "type") {
            IntPtr h = CreateFileW("CONIN$", 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            string text = args[2].Replace("\\n", "\r").Replace("^C", "\x03");
            var recs = new KEYREC[text.Length * 2];
            for (int i = 0; i < text.Length; i++) {
                for (int d = 0; d < 2; d++) {
                    var r = new KEYREC();
                    r.EventType = 1; r.KeyDown = d == 0 ? 1 : 0; r.Repeat = 1; r.Ch = text[i];
                    if (text[i] == '\r') { r.VKey = 0x0D; r.VScan = 0x1C; }
                    if (text[i] == '\x03') { r.VKey = 0x43; r.VScan = 0x2E; r.Ctrl = 0x0008; }
                    recs[i * 2 + d] = r;
                }
            }
            uint w;
            return WriteConsoleInputW(h, recs, (uint)recs.Length, out w) ? 0 : 4;
        }
        return 1;
    }
}
