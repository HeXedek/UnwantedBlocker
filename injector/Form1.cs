using System;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace WinFormsApp13
{

    /// <summary>
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    ///     FANUM TAX IS THE EXECUTABLE FOR THE CONTROLLER IDK WHY I NAMED IT LIKE THAT
    ///     MAIN.DLL IS THE INJECT DLL
    ///     STARTASNONADMIN.EXE - IS YOU KNOW
    ///     THEY NEED TO BE BUILD FIRST AND PUT HERE IN ORDER FOR IT TO BUILD
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    /// 
    /// </summary>
    /// THE CODE STARTS FROM HERE

    public partial class Form1 : Form
    {
        bool injected = false;

        public Form1()
        {
            InitializeComponent();
        }

        private const UInt32 StdOutputHandle = 0xFFFFFFF5;
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(UInt32 nStdHandle);
        [DllImport("kernel32.dll")]
        private static extern void SetStdHandle(UInt32 nStdHandle, IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32")]
        static extern bool AllocConsole();


        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;


        private System.Windows.Forms.Timer injectionTimer; 
        private bool isTimerRunning = false; 

        private void StartInjectionTimer()
        {
            if (!isTimerRunning)
            {
                // Initialize the timer
                injectionTimer = new System.Windows.Forms.Timer();
                injectionTimer.Interval = 700; 
                injectionTimer.Tick += InjectionTimer_Tick;
                injectionTimer.Start();
                isTimerRunning = true;
                Console.WriteLine("Injection timer started.");
            }
            else
            {
                Console.WriteLine("Timer is already running.");
            }
        }

        private void StopInjectionTimer()
        {
            if (isTimerRunning)
            {
                injectionTimer.Stop();
                injectionTimer.Dispose();
                isTimerRunning = false;
                Console.WriteLine("Injection timer stopped.");
            }
            else
            {
                Console.WriteLine("Timer is not running.");
            }
        }

        private void InjectionTimer_Tick(object sender, EventArgs e)
        {

            string[] processesToInject = { "cmd", "pwsh", "powershell", "explorer" };

            foreach (var processName in processesToInject)
            {
                var processes = Process.GetProcessesByName(processName);
                foreach (var process in processes)
                {
                    if (CheckProcessById(process.Id)) 
                    {
                        Console.WriteLine($"Process {processName} with PID {process.Id} already has the DLL injected.");
                    }
                    else
                    {
                        InjectDll(process.Id, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar\\main.dll");
                    }

                }
            }
        }



        private async void Form1_Load(object sender, EventArgs e)
        {
            button1.Left = (this.ClientSize.Width - button1.Width) / 2;
            button2.Left = (this.ClientSize.Width - button2.Width) / 2;
            label1.Left = (this.ClientSize.Width - label1.Width) / 2;
            Inject.Left = (this.ClientSize.Width - Inject.Width) / 2;
            if (Process.GetProcessesByName("ProcessName").Length > 0)
            {
                disableinject();
                injected = true;
            }
            if (Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar"))
            {
                button2.Enabled = false;
                button2.Visible = false;
                label1.Visible = false;
                button1.Enabled = true;
            }
            await PutTaskDelay();


        }


        void disableinject()
        {
            injected = true;
            button1.Text = "Uninject (kills controller)";
        }


        void enableinject()
        {
            injected = false;
            button1.Text = "inject";
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);


        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("user32.dll", SetLastError = true)] 
        private static extern IntPtr GetShellWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        void start(string path)
        {
            string unelevatedAppPath = path;

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{unelevatedAppPath}\"",
                UseShellExecute = true
            };

            Process.Start(psi);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool WaitNamedPipe(string name, uint timeout);
        private async void button1_Click(object sender, EventArgs e)
        {
            if (!injected)
            {
                asadmin(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar\\frontendmaybe.exe");
                await delay2(200);
                start(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar\\startasnonadmin.exe");
                await delay2(1000);
                StartInjectionTimer();
                disableinject();
                this.Visible = true;
                label1.Text = injected.ToString();
                injected = true;
            }
            else
            {
                StopInjectionTimer();
                foreach (var process in Process.GetProcessesByName("frontendmaybe"))
                {
                    process.Kill();
                }
                enableinject();
                label1.Text = injected.ToString();
                injected = false;
            }

        }


        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        const int LIST_MODULES_ALL = 0x03;
        const int PROCESS_VM_READ = 0x0010;


        const int PROCESS_QUERY_INFORMATION = 0x0400;

        static bool CheckProcessById(int targetProcessId)
        {
            IntPtr hProcess = IntPtr.Zero;

            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, targetProcessId);
                if (hProcess == IntPtr.Zero)
                {
                    int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    Console.WriteLine($"Error: Failed to open process with ID {targetProcessId}. Win32 Error Code: {error}");
                    return false;
                }

                IntPtr[] modules = new IntPtr[1024]; 
                int bytesNeeded;

                if (EnumProcessModulesEx(hProcess, modules, modules.Length * IntPtr.Size, out bytesNeeded, LIST_MODULES_ALL))
                {
                    int count = bytesNeeded / IntPtr.Size;
                    StringBuilder moduleName = new StringBuilder(1024);

                    for (int i = 0; i < count; i++)
                    {
                        moduleName.Clear();

                        if (GetModuleFileNameEx(hProcess, modules[i], moduleName, moduleName.Capacity) > 0)
                        {
                            string currentModuleName = moduleName.ToString();
                            string fileName = System.IO.Path.GetFileName(currentModuleName);

                            // Case-insensitive comparison of the filename
                            if (string.Equals(fileName, "main.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine($"Detected module: {currentModuleName}");
                                return true; 
                            }
                        }
                        else
                        {
                            int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                            Console.WriteLine($"Warning: GetModuleFileNameEx failed for module handle {modules[i]}. Win32 Error Code: {error}");
                        }
                    }
                }
                else
                {
                    int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    Console.WriteLine($"Error: EnumProcessModulesEx failed for process ID {targetProcessId}. Win32 Error Code: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {

                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                return false;
            }
            finally
            {

                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
            return false;
        }


        static void InjectDll(int processId, string dllPath)
        {

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process. Error code: " + Marshal.GetLastWin32Error());
                return;
            }


            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (allocMemAddress == IntPtr.Zero)
            {
                Console.WriteLine("Failed to allocate memory in the target process. Error code: " + Marshal.GetLastWin32Error());
                return;
            }


            byte[] dllPathBytes = System.Text.Encoding.Default.GetBytes(dllPath);

            uint bytesWritten;
            bool writeMemorySuccess = WriteProcessMemory(hProcess, allocMemAddress, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten);
            if (!writeMemorySuccess)
            {
                Console.WriteLine("Failed to write memory to target process. Error code: " + Marshal.GetLastWin32Error());
                return;
            }

            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to get the address of LoadLibraryA. Error code: " + Marshal.GetLastWin32Error());
                return;
            }

            IntPtr hThread;
            hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, out IntPtr threadId);

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("Failed to create remote thread in target process. Error code: " + Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine("DLL injected successfully!");


            WaitForSingleObject(hThread, 0xFFFFFFFF);

            // Clean up
            CloseHandle(hThread);
            CloseHandle(hProcess);
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        async Task PutTaskDelay()
        {
            await Task.Delay(200);
            UseImmersiveDarkMode(this.Handle, true);
        }

        async Task delay2(int delay)
        {
            await Task.Delay(delay);
        }

        private static bool UseImmersiveDarkMode(IntPtr handle, bool enabled)
        {
            if (IsWindows10OrGreater(17763))
            {
                var attribute = DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1;
                if (IsWindows10OrGreater(18985))
                {
                    attribute = DWMWA_USE_IMMERSIVE_DARK_MODE;
                }

                int useImmersiveDarkMode = enabled ? 1 : 0;
                return DwmSetWindowAttribute(handle, (int)attribute, ref useImmersiveDarkMode, sizeof(int)) == 0;
            }

            return false;
        }

        private static bool IsWindows10OrGreater(int build = -1)
        {
            return Environment.OSVersion.Version.Major >= 10 && Environment.OSVersion.Version.Build >= build;
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            await delay2(200);
            Console.WriteLine("[ShitBlocker] Allocated Console");
            Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar");
            Console.WriteLine("[ShitBlocker] Created Directory");
            Directory.SetCurrentDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar");
            Console.WriteLine("[ShitBlocker] Set current directory to directory i just created");
            Console.WriteLine("[ShitBlocker] Extracting WinFormsApp13.fanumtax.exe to " + Directory.GetCurrentDirectory());
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinFormsApp13.fanumtax.exe"))
            {
                using (var file = new FileStream("frontendmaybe.exe", FileMode.Create, FileAccess.Write))
                {
                    resource.CopyTo(file);
                }
            }
            Console.WriteLine("[ShitBlocker] Extracted");
            Console.WriteLine("[ShitBlocker] Extracting WinFormsApp13.main.dll to " + Directory.GetCurrentDirectory());
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinFormsApp13.main.dll"))
            {
                using (var file = new FileStream("main.dll", FileMode.Create, FileAccess.Write))
                {
                    resource.CopyTo(file);
                }
            }
            using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("WinFormsApp13.startasnonadmin.exe"))
            {
                using (var file = new FileStream("startasnonadmin.exe", FileMode.Create, FileAccess.Write))
                {
                    resource.CopyTo(file);
                }
            }
            Console.WriteLine("[ShitBlocker] Extracted");
            button2.Enabled = false;
            button2.Visible = false;
            label1.Visible = false;
            button1.Enabled = true;
            Console.WriteLine("[ShitBlocker] we just hided controls so your bitchass wont extract it again and crash ts shit");
        }


        static void asadmin(string sex)
        {
            // Start a process to execute the command
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = sex,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            Process process = Process.Start(startInfo);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if(injected)
            {
                Inject.Text = "cant close when injected";
                Inject.Left = (this.ClientSize.Width - Inject.Width) / 2;
                e.Cancel = true;
            }

        }
    }
}

