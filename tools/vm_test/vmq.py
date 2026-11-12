"""Host-side client for vm_server.py: queue a PowerShell script, wait for its
result. Standard library only.

    import vmq
    q = vmq.Queue("/path/to/session")
    print(q.ps("Get-Date"))
"""

import json
import os
import time

# PowerShell helpers every command gets in front of it. Win32 calls for
# finding a console window and sending it keys, and a screenshot that is
# uploaded back to the host.
PRELUDE = r'''
$base = '__BASE__'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
if (-not ('VmT.W' -as [type])) {
Add-Type -Namespace VmT -Name W -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h);
[DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int n);
[DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow();
[DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(System.IntPtr h, System.Text.StringBuilder s, int n);
'@
}
function Shot([string]$name) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    Invoke-WebRequest -Uri "$base/u/$name" -Method Put -UseBasicParsing -Body $ms.ToArray() | Out-Null
    $g.Dispose(); $bmp.Dispose()
    "shot $name"
}
function Upload([string]$path, [string]$name) {
    Invoke-WebRequest -Uri "$base/u/$name" -Method Put -UseBasicParsing -InFile $path | Out-Null
    "uploaded $name"
}
function Fetch([string]$name, [string]$dest) {
    Invoke-WebRequest -Uri "$base/f/$name" -UseBasicParsing -OutFile $dest
    "fetched $name"
}
function Activate([string]$title) {
    $sh = New-Object -ComObject WScript.Shell
    for ($i = 0; $i -lt 20; $i++) { if ($sh.AppActivate($title)) { return $true }; Start-Sleep -Milliseconds 300 }
    return $false
}
function Keys([string]$title, [string]$keys) {
    if (-not (Activate $title)) { return "NO WINDOW $title" }
    Start-Sleep -Milliseconds 400
    [System.Windows.Forms.SendKeys]::SendWait($keys)
    "sent"
}
'''


class Queue:
    def __init__(self, root: str, base: str = "http://192.168.248.1:8765"):
        self.root = root
        self.base = base
        self.n = 0
        for d in ("files", "queue", "results"):
            os.makedirs(os.path.join(root, d), exist_ok=True)

    def runner_alive(self, within: float = 10.0) -> bool:
        try:
            with open(os.path.join(self.root, "heartbeat")) as fh:
                return time.time() - float(fh.read()) < within
        except (OSError, ValueError):
            return False

    def ps(self, script: str, timeout: float = 120.0, name: str = "cmd") -> str:
        self.n += 1
        cid = f"{int(time.time()*1000)}-{self.n:03d}-{name}"
        body = {"id": cid, "ps": PRELUDE.replace("__BASE__", self.base) + "\n" + script}
        tmp = os.path.join(self.root, "queue", cid + ".part")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        os.replace(tmp, os.path.join(self.root, "queue", cid + ".json"))
        result = os.path.join(self.root, "results", cid + ".json")
        end = time.time() + timeout
        while time.time() < end:
            if os.path.exists(result):
                with open(result, encoding="utf-8-sig") as fh:
                    data = json.load(fh)
                return data.get("output") or ""
            time.sleep(0.5)
        raise TimeoutError(f"no answer to {cid} within {timeout:.0f} s")

    def result_path(self, name: str) -> str:
        return os.path.join(self.root, "results", name)
