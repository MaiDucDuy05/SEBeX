using System; // I'm sure a lot you know abt it, it's for Exception, DateTime etc.
using System.Collections; // IList, path, file
using System.Collections.Generic;
using System.IO; // .FirstOrDefault() (which is going to be used to search through lists of assemblies)
using System.Linq; // Select and FirstOrDefault for the search logic
using System.Reflection; // Assembly, Type, MethodInfo / PropertyInfo and BindingFlags
using System.Runtime.CompilerServices; // MethodImplOptions.NoInlining
using System.Runtime.InteropServices; // DllImport
using System.Threading; // Thread
using System.Diagnostics; // Process
using HarmonyLib; // To 'connect' our code into the browser's process... You need to download HarmonyLib. For more info see https://harmony.pardeike.net/articles/intro.html

// NOTE: I will ONLY include references for functions that might be unfamiliar or somewhat complex for deep undestanding it's up to you to make research in it
// See https://learn.microsoft.com/en-us/dotnet/api/ 

namespace seb_patcher
{
    public class Entrypoint
    {
        // If you can remember, nativ loader jumps here after setting everything up
        public static int Run(string arg)
        {
            try
            {
                // Redirects the program's search for missing dlls (like harmony) to our folder so the browser doesn't crash when it can't find them in its own directory
                // https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.currentdomain?view=net-9.0#system-appdomain-currentdomain
                AppDomain.CurrentDomain.AssemblyResolve += current_domain_asm_resolve;

                // Jump into the main logic (you can just add all the functionality here and not jump at all but it would be 'clean' this way)
                return run_internal(arg);
            }
            catch { return -1; }
        }

        // It searches for 0Harmony.dll if it's not in the main(current) folder
        private static Assembly current_domain_asm_resolve(object sender, ResolveEventArgs args)
        {
            try
            {
                // This gets the name of the missing dll our program is looking for
                string assemblyName = new AssemblyName(args.Name).Name;

                // And if the missing dll is harmony then...
                if (assemblyName == "0Harmony")
                {
                    // It finds the folder where this current dll is placed
                    string baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? @"C:\KioskInject";
                    // And then combine that folder path with the harmony filename
                    string dllPath = Path.Combine(baseDir, "0Harmony.dll");

                    // Finally, if the file is there then load it into memory 'manually'
                    // NOTE: Assembly methods:
                    //- Assembly.Load https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.load?view=net-9.0
                    //- Assembly.LoadFrom
                    //- Assembly.GetExecutingAssembly
                    if (File.Exists(dllPath)) return Assembly.LoadFrom(dllPath);
                }
            }
            catch { }
            return null;
        }

        //  the resolve event is ready

        // It makes it that it won't load the stuff inside this function until it tell it to run it to prevents crashing on startup
        // If that was too complicated for you to understand just think that we use 'NoInlining' so the JIT (just in time) compiler doesn't try to load harmony before calling run_internal
        // This is because the computer is TOO FAST that it tries to load everything at once and fails cause it hasn't seen the "directions" yet so Noinlining forces the computer to slow down and wait until the very last sec to look for harmony
        [MethodImpl(MethodImplOptions.NoInlining)]

        // THE MAIN LOGIC
        private static int run_internal(string arg)
        {
            try
            {
                // It gives this specific patch a unique ID... it's like a package name but for a harmony so that it prevernts our patches from getting mixed up with other patches
                var harmony = new Harmony("com.kioskpatcher.override");


                // ############################################################## PATCH 1: Kiosk Mode #############################################################
                // First we got to find the assembly that controls the "lockdown" part
                Assembly settingsAsm = find_asm("SafeExamBrowser.Settings");
                // And then find the class that holds security settings
                Type securitySettingsType = settingsAsm?.GetType("SafeExamBrowser.Settings.Security.SecuritySettings");
                // It then find the "getter" method for kiosk mode (in simple term it gets which mode we are in)
                MethodInfo kioskModeGetter = securitySettingsType?.GetProperty("KioskMode", BindingFlags.Public | BindingFlags.Instance)?.GetGetMethod();

                if (kioskModeGetter != null)
                {
                    // This finds our replacement function or in other word postfix which will allow us to mod the method
                    var kioskPostfix = typeof(kiosk_mode_mod).GetMethod(nameof(kiosk_mode_mod.Postfix));
                    // This makes that wheneever seb asks for kiosk mode run our code AFTER the original one
                    harmony.Patch(kioskModeGetter, postfix: new HarmonyMethod(kioskPostfix));
                }

                // ############################################################ PATCH 2: Whitelisted Apps #######################################################
                // It's almost the same as the patch 1
                Assembly configAsm = find_asm("SafeExamBrowser.Configuration");
                Type dataProcessorType = configAsm?.GetType("SafeExamBrowser.Configuration.ConfigurationData.DataProcessor");
                MethodInfo processMethod = dataProcessorType?.GetMethod("Process", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

                if (processMethod != null)
                {
                    // It finds the functions after it got loaded and ran... if we used a prefix, the whitelist wouldn't exist yet and there would be nothing for us to modify since the browser hasn't loaded the data from the disk
                    var whitelistPostfix = typeof(inject_whitelist_app).GetMethod(nameof(inject_whitelist_app.Postfix));
                    harmony.Patch(processMethod, postfix: new HarmonyMethod(whitelistPostfix));
                }

                // NOTE 1: Prefix is used when we want to prevent the original code from running or in other word change the "input" variables before the method starts
                // NOTE 2: Postfix used to modify the result after the original code has finished its work


                // ############################################################# PATCH 3: Clipboard Policy ########################################################
                // We don't need to find the assembly here cause we already located the 'configuration' dll in the previous patch other than that everything is the same
                Type securityMapperType = configAsm?.GetType("SafeExamBrowser.Configuration.ConfigurationData.DataMapping.SecurityDataMapper");
                MethodInfo mapClipboard = securityMapperType?.GetMethod("MapClipboardPolicy", BindingFlags.Instance | BindingFlags.NonPublic);

                if (mapClipboard != null)
                {
                    var clipPrefix = typeof(clipboard_policy_mod).GetMethod(nameof(clipboard_policy_mod.Prefix));
                    harmony.Patch(mapClipboard, prefix: new HarmonyMethod(clipPrefix));
                }

                // ############################################################# PATCH 4: VM Detection Policy #######################################################
                // No need to assign securityMapperType again, for the same reason I told you earlier
                MethodInfo mapVM = securityMapperType?.GetMethod("MapVirtualMachinePolicy", BindingFlags.Instance | BindingFlags.NonPublic);

                if (mapVM != null)
                {
                    var vmPrefix = typeof(vm_policy_mod).GetMethod(nameof(vm_policy_mod.Prefix));
                    harmony.Patch(mapVM, prefix: new HarmonyMethod(vmPrefix));
                }

                Assembly uiSharedAsm = find_asm("SafeExamBrowser.UserInterface.Shared");
                Type windowGuardType = uiSharedAsm?.GetType("SafeExamBrowser.UserInterface.Shared.WindowGuard");
                MethodInfo activateMethod = windowGuardType?.GetMethod("Activate", BindingFlags.Public | BindingFlags.Instance);
                MethodInfo guardMethod = windowGuardType?.GetMethod("Guard", BindingFlags.NonPublic | BindingFlags.Instance);
                MethodInfo triageMethod = windowGuardType?.GetMethod("Triage", BindingFlags.NonPublic | BindingFlags.Instance);

                if (activateMethod != null)
                {
                    var skipPrefix = typeof(window_protection_mod).GetMethod(nameof(window_protection_mod.Prefix));
                    harmony.Patch(activateMethod, prefix: new HarmonyMethod(skipPrefix));
                }
                if (guardMethod != null)
                {
                    var skipPrefix = typeof(window_protection_mod).GetMethod(nameof(window_protection_mod.Prefix));
                    harmony.Patch(guardMethod, prefix: new HarmonyMethod(skipPrefix));
                }
                if (triageMethod != null)
                {
                    var skipPrefix = typeof(window_protection_mod).GetMethod(nameof(window_protection_mod.Prefix));
                    harmony.Patch(triageMethod, prefix: new HarmonyMethod(skipPrefix));
                }

                Type securitySettingsType2 = settingsAsm?.GetType("SafeExamBrowser.Settings.Security.SecuritySettings");
                MethodInfo allowWindowCaptureGetter = securitySettingsType2?.GetProperty("AllowWindowCapture", BindingFlags.Public | BindingFlags.Instance)?.GetGetMethod();

                if (allowWindowCaptureGetter != null)
                {
                    var allowCapturePostfix = typeof(allow_window_capture_mod).GetMethod(nameof(allow_window_capture_mod.Postfix));
                    harmony.Patch(allowWindowCaptureGetter, postfix: new HarmonyMethod(allowCapturePostfix));
                }

                new Thread(() =>
{
    Thread.Sleep(1000); // Chờ SEB init xong
    try
    {
        Assembly uiSharedAsm2 = find_asm("SafeExamBrowser.UserInterface.Shared");
        Type windowGuardType2 = uiSharedAsm2?.GetType("SafeExamBrowser.UserInterface.Shared.WindowGuard");

        // Tìm instance WindowGuard đang chạy trong SEB
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            foreach (var type in asm.GetTypes())
            {
                var fields = type.GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                foreach (var field in fields)
                {
                    if (field.FieldType == windowGuardType2)
                    {
                        // Lấy instance và gọi Deactivate
                        object instance = field.GetValue(null) ?? field.GetValue(Activator.CreateInstance(type));
                        if (instance != null)
                        {
                            var deactivate = windowGuardType2.GetMethod("Deactivate", BindingFlags.Public | BindingFlags.Instance);
                            deactivate?.Invoke(instance, null);
                        }
                    }
                }
            }
        }
    }
    catch { }
})
{ IsBackground = true }.Start();

                // Chỉ chạy key hook ở tiến trình chính để tránh mở 2 cửa sổ Edge
                if (Process.GetCurrentProcess().ProcessName.Equals("SafeExamBrowser", StringComparison.OrdinalIgnoreCase))
                {
                    start_key_hook();
                }
                
                // Start SEB screen capture prevention (cần chạy ở mọi process để bypass Affinity)
                start_screen_capture();

                return 0;
            }
            catch { return -1; }
        }

        // This function checks if dlls already loaded in the process and load them if they are missing
        private static Assembly find_asm(string name)
        {
            // It look at all the dlls already loaded in the browser
            Assembly found = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == name);
            if (found != null) return found;
            // If our dll is already there, we use it instead of loading a second copy
            try { return Assembly.Load(name); } catch { return null; }
        }

        // Windows function which 1. lets us check if a key is pressed, 2. force our ms edge window to stay on top of seb
        [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int vKey);
        [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
        [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
        [DllImport("user32.dll", SetLastError = true)] private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);
        [DllImport("user32.dll")] private static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint dwAffinity);


        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern bool BringWindowToTop(IntPtr hWnd);
        [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr hWnd);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;

        private static IntPtr edgeHandle = IntPtr.Zero;
        private static bool edgeVisible = false;
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        private static void start_key_hook()
        {
            new Thread(() =>
            {
                bool isLaunchPressed = false;
                bool isTogglePressed = false;
                int topMostTimer = 0;

                while (true)
                {
                    try
                    {
                        // --- Ctrl + Shift: mở Edge (chỉ 1 lần) ---
                        bool launchPressed = (GetAsyncKeyState(0xA2) & 0x8000) != 0 &&
                                            ((GetAsyncKeyState(0xA0) & 0x8000) != 0 ||
                                            (GetAsyncKeyState(0xA1) & 0x8000) != 0);

                        if (launchPressed && !isLaunchPressed)
                        {
                            isLaunchPressed = true;

                            // Chỉ mở nếu chưa có hoặc process đã chết
                            if (edgeHandle == IntPtr.Zero || !IsWindow(edgeHandle))
                            {
                                var p = Process.Start("msedge.exe");
                                Thread.Sleep(1500); // Chờ Edge khởi động

                                // Tìm handle cửa sổ của process vừa mở
                                foreach (var ep in Process.GetProcessesByName("msedge"))
                                {
                                    if (ep.MainWindowHandle != IntPtr.Zero)
                                    {
                                        edgeHandle = ep.MainWindowHandle;
                                        edgeVisible = true;
                                        break;
                                    }
                                }
                            }
                        }
                        else if (!launchPressed) isLaunchPressed = false;

                        // --- Ctrl + Z: toggle ẩn/hiện ---
                        bool togglePressed = (GetAsyncKeyState(0x11) & 0x8000) != 0 &&
                                            (GetAsyncKeyState(0x5A) & 0x8000) != 0;

                        if (togglePressed && !isTogglePressed)
                        {
                            isTogglePressed = true;

                            if (edgeHandle != IntPtr.Zero && IsWindow(edgeHandle))
                            {
                                edgeVisible = !edgeVisible;
                                if (edgeVisible)
                                {
                                    ShowWindow(edgeHandle, SW_SHOW);
                                    BringWindowToTop(edgeHandle);
                                    SetForegroundWindow(edgeHandle);
                                }
                                else
                                {
                                    ShowWindow(edgeHandle, SW_HIDE);
                                }
                            }
                        }
                        else if (!togglePressed) isTogglePressed = false;

                        // --- TopMost mỗi ~500ms ---
                        topMostTimer++;
                        if (topMostTimer >= 10)
                        {
                            topMostTimer = 0;
                            if (edgeVisible && edgeHandle != IntPtr.Zero && IsWindow(edgeHandle))
                                SetWindowPos(edgeHandle, new IntPtr(-1), 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0040);
                        }
                    }
                    catch { }
                    Thread.Sleep(50);
                }
            })
            { IsBackground = true }.Start();
        }

        [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

        private static void start_screen_capture()
        {
            new Thread(() =>
            {
                var loggedHwnds = new HashSet<IntPtr>();
                while (true)
                {
                    try
                    {
                        var sebPids = Process.GetProcessesByName("SafeExamBrowser")
                                            .Concat(Process.GetProcessesByName("SafeExamBrowser.Client"))
                                            .Select(p => (uint)p.Id)
                                            .ToHashSet();

                        EnumWindows((hWnd, _) =>
                        {
                            if (!IsWindowVisible(hWnd)) return true;
                            GetWindowThreadProcessId(hWnd, out uint pid);
                            if (sebPids.Contains(pid))
                            {
                                uint currentAffinity = 0;
                                bool getSuccess = GetWindowDisplayAffinity(hWnd, out currentAffinity);
                                
                                if (!loggedHwnds.Contains(hWnd))
                                {
                                    try { File.AppendAllText(@"C:\Users\Public\affinity_log.txt", $"[New Window] hWnd: {hWnd}, PID: {pid}, getSuccess: {getSuccess}, currentAffinity: {currentAffinity}\n"); } catch {}
                                    loggedHwnds.Add(hWnd);
                                }

                                if (currentAffinity != 0)
                                {
                                    bool setSuccess = SetWindowDisplayAffinity(hWnd, 0);
                                    if (!setSuccess)
                                    {
                                        int err = Marshal.GetLastWin32Error();
                                        try { File.AppendAllText(@"C:\Users\Public\affinity_log.txt", $"[Fail Set] hWnd: {hWnd}, PID: {pid}. Error code: {err}\n"); } catch {}
                                    }
                                }

                                int uncloak = 0;
                                DwmSetWindowAttribute(hWnd, 14, ref uncloak, sizeof(int));
                                DwmSetWindowAttribute(hWnd, 13, ref uncloak, sizeof(int));
                            }
                            return true;
                        }, IntPtr.Zero);
                    }
                    catch { }
                    Thread.Sleep(100);
                }
            })
            { IsBackground = true }.Start();
        }
    }

    // @@@@ LOGIC FOR PATCH 1 @@@@
    public static class kiosk_mode_mod
    {
        // This runs AFTER the 'real/original' kiosk mode getter
        public static void Postfix(ref object __result)
        {
            try
            {
                // If the current mode is '0' (none mode), we skip patching it, cause why bother if it's already in our favor
                if (__result != null && Convert.ToInt32(__result) == 0) return;

                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    // This searches for kiosk mode "enum" (the list of modes)
                    var type = asm.GetType("SafeExamBrowser.Settings.Security.KioskMode");
                    // If we find it, set the result to '2' which is DisableExplorerShell
                    if (type != null) { __result = Enum.ToObject(type, 2); return; }
                }
            }
            catch { }
        }
    }

    // @@@@ LOGIC FOR PATCH 2 @@@@
    public static class inject_whitelist_app
    {
        // These runs after seb finishes loading its allowed app list
        public static void Postfix(object settings)
        {
            if (settings == null) return; // If the browser failed to load its own config...
            // NOTE: we can’t just type settings.Applications cause that data is "private" or "protected" so we do GetProperty("Applications") which finds the secret folder "Applications" inside the browser's memory
            // In short it get the 'Applications' settings object using reflection
            var appSettings = settings.GetType().GetProperty("Applications")?.GetValue(settings);
            if (appSettings == null) return;

            // This CLEAR the blacklisted applications so it first find the 'blacklist' property and clean it up
            if (appSettings.GetType().GetProperty("Blacklist")?.GetValue(appSettings) is IList blacklist) blacklist.Clear();

            // It adds microsoft edge to whitelisted app but first it need to find the 'whitelist' list
            var whitelist = appSettings.GetType().GetProperty("Whitelist")?.GetValue(appSettings) as IList;
            // This finds 'WhitelistApplication' type
            // The things is inorder to add edge to the whitelist, we can't just add the word "edge"... if you read the doc you would know that we have to add an object that the browser understands (let's just say a WhitelistApplication object)
            Type wlAppType = AppDomain.CurrentDomain.GetAssemblies().Select(a => a.GetType("SafeExamBrowser.Settings.Applications.WhitelistApplication")).FirstOrDefault(t => t != null);

            if (whitelist != null && wlAppType != null) // It checks if it founds both the whitelist (which is the list itself) and the blueprint(type) but if either is missing, you know what's going to happen
            {

                object edge = Activator.CreateInstance(wlAppType); // It creates a new empty application entry
                // Then fill in the details for edge
                entry_setup(edge, "ExecutableName", "msedge.exe");
                entry_setup(edge, "OriginalName", "msedge.exe");
                entry_setup(edge, "AllowRunning", true);
                entry_setup(edge, "DisplayName", "microsoft edge");
                // Finally, SHOVE it into the list so the browser thinks it's supposed to be there
                whitelist.Add(edge);
            }
        }
        // This allows us to "force write" values to an object's hidden properties by just name
        private static void entry_setup(object o, string name, object v) => o.GetType().GetProperty(name)?.SetValue(o, v);
    }

    // @@@@ LOGIC FOR PATCH 3 @@@@
    public static class clipboard_policy_mod
    {
        // It runs before the clipboard check
        public static bool Prefix(object[] __args)
        {
            try
            {
                // These forces the internal 'ClipboardPolicy' variable to '0' which means 'allow'
                var sec = __args[0].GetType().GetProperty("Security")?.GetValue(__args[0]);
                var prop = sec?.GetType().GetProperty("ClipboardPolicy");
                if (prop != null) prop.SetValue(sec, Enum.ToObject(prop.PropertyType, 0));
                return false; // As always this skips the real logic
            }
            catch { return true; }
        }
    }

    // @@@@ LOGIC FOR PATCH 5 @@@@
    public static class vm_policy_mod
    {
        // This runs before the vm check
        public static bool Prefix(object[] __args)
        {
            try
            {
                // Sets 'VirtualMachinePolicy' variable to 0 which is again means 'allow'
                var sec = __args[0].GetType().GetProperty("Security")?.GetValue(__args[0]);
                var prop = sec?.GetType().GetProperty("VirtualMachinePolicy");
                if (prop != null) prop.SetValue(sec, Enum.ToObject(prop.PropertyType, 0));
                return false;
            }
            catch { return true; }
        }
    }

// @@@@ LOGIC FOR PATCH 6: Window Guard @@@@
public static class window_protection_mod
{
    public static bool Prefix()
    {
        return false; // Bỏ qua Activate, Guard, Triage hoàn toàn
    }
}

// @@@@ LOGIC FOR PATCH 7: Allow Window Capture @@@@
public static class allow_window_capture_mod
{
    public static void Postfix(ref object __result)
    {
        __result = true; // Luôn cho phép window capture
    }
}
}