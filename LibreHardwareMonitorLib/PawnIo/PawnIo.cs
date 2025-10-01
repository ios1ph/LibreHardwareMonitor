using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

using Microsoft.Win32;

namespace LibreHardwareMonitor.PawnIo;

public unsafe class PawnIo
{
    private const string ServiceName = "PawnIO";

    private static readonly string TempDir = Path.Combine(Path.GetTempPath(), "PawnIO_Temp");
    private static readonly string TempDllPath = Path.Combine(TempDir, "PawnIOLib.dll"); // нейтральное имя!
    private static readonly string TempSysPath = Path.Combine(TempDir, "PawnIO.sys");    // нейтральное имя!

    // Больше НЕТ жёстких констант с именами ресурсов — вычисляем динамически.
    // Базовый префикс пространства ресурсов (оставьте под свой проект).
    private const string ResPrefix = nameof(LibreHardwareMonitor) + ".Resources.PawnIO.";

    /// <summary>
    /// Главный сценарий: распаковать нужные DLL+SYS в %TEMP% (под нейтральными именами),
    /// загрузить DLL, создать и запустить kernel-сервис.
    /// </summary>
    public static bool Open()
    {
        try
        {
            // Если уже установлен глобально — пробуем подцепиться к установленной DLL.
            if (IsInstalled)
            {
                TryLoadLibrary(); // сам разрулит, как достать корректную DLL
                try { pawnio_version(out uint _); return true; } catch { /* попробуем временную установку ниже */ }
            }

            Directory.CreateDirectory(TempDir);

            // --- Выбираем ресурсы по архитектуре ОС ---
            var (resDll, resSys) = GetResourceNamesForOs();

            // --- Распаковываем в нейтральные имена (важно для DllImport("PawnIOLib")) ---
            ExtractIfMissing(resDll, TempDllPath);
            ExtractIfMissing(resSys, TempSysPath);

            // Подгружаем DLL, чтобы DllImport начал её резолвить
            try { Kernel32.LoadLibrary(TempDllPath); } catch { /* ignore */ }

            // Создаём службу, если её нет
            if (!ServiceExists(ServiceName))
            {
                RunCmd($@"sc create {ServiceName} type= kernel start= demand binPath= ""{TempSysPath}"" DisplayName= ""PawnIO""");
                Thread.Sleep(400);
            }

            // Стартуем службу, если не запущена
            if (!ServiceRunning(ServiceName))
            {
                RunCmd($@"sc start {ServiceName}");
                Thread.Sleep(700);
            }

            // Проверяем доступность
            pawnio_version(out uint _);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void Close2()
    {
        try
        {
            string imagePath = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + ServiceName, "ImagePath", null) as string;
            string norm(string p) => string.IsNullOrWhiteSpace(p) ? "" : Path.GetFullPath(p.Trim().Trim('"'));

            if (!string.IsNullOrEmpty(imagePath) &&
                string.Equals(norm(imagePath), norm(TempSysPath), StringComparison.OrdinalIgnoreCase))
            {
                RunCmd($@"sc stop {ServiceName}");
                Thread.Sleep(300);
                RunCmd($@"sc delete {ServiceName}");
                Thread.Sleep(300);
            }
        }
        catch { /* ignore */ }

        TryDeleteFile(TempDllPath);
        TryDeleteFile(TempSysPath);
        TryDeleteEmptyDir(TempDir);
    }

    // ===== Новое: выбор архитектуры и ресурсов =====

    private static (string resDll, string resSys) GetResourceNamesForOs()
    {
        string tag = GetArchTag(); // "amd" или "arm"
        string resDll = ResPrefix + $"PawnIOLib{tag}.dll";
        string resSys = ResPrefix + $"PawnIO{tag}.sys";
        return (resDll, resSys);
    }

    /// <summary>
    /// Возвращает "amd" для X64 и "arm" для ARM64. Бросает на неподдерживаемых.
    /// </summary>
    private static string GetArchTag()
    {
        // ВАЖНО: драйвер должен совпадать с архитектурой ОС, не процесса.
        var osArch = RuntimeInformation.OSArchitecture;
        return osArch switch
        {
            Architecture.X64 => "amd",
            Architecture.Arm64 => "arm",
            // Если нужно, можно добавить X86/Arm (но kernel-драйверы для них вам скорее всего не нужны)
            _ => throw new PlatformNotSupportedException($"PawnIO: неподдерживаемая архитектура ОС: {osArch}")
        };
    }

    // ===== Существующая утилитарка (без изменений, за исключением TryLoadLibrary) =====

    private static void ExtractIfMissing(string resourceName, string targetPath)
    {
        if (File.Exists(targetPath)) return;

        using Stream s =
            Assembly.GetEntryAssembly()?.GetManifestResourceStream(resourceName)
            ?? Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);

        if (s == null)
            throw new FileNotFoundException("Resource not found: " + resourceName);

        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);

        using var fs = File.Open(targetPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        s.CopyTo(fs);
        File.SetAttributes(targetPath, FileAttributes.Temporary);
    }

    private static void RunCmd(string cmd)
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { /* ignore */ }
    }

    private static bool ServiceExists(string serviceName)
    {
        try
        {
            return ServiceController.GetServices()
                .Any(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static bool ServiceRunning(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
        }
        catch
        {
            MoveFileEx(path, null, 0x00000004); // MOVEFILE_DELAY_UNTIL_REBOOT
        }
    }

    private static void TryDeleteEmptyDir(string dir)
    {
        try
        {
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir, false);
        }
        catch { /* ignore */ }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

    // ===== Инсталляция / резолв DLL =====

    public static string InstallPath
    {
        get
        {
            if ((Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO", "InstallLocation", null) ??
                 Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\PawnIO", "Install_Dir", null) ??
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + Path.DirectorySeparatorChar + "PawnIO") is string { Length: > 0 } path)
            {
                if (Directory.Exists(path))
                    return path;
            }
            return null;
        }
    }

    public static bool IsInstalled => !string.IsNullOrEmpty(InstallPath);

    private static void TryLoadLibrary()
    {
        // 1) Если уже доступна — выходим
        try { pawnio_version(out uint _); return; } catch { /* not loaded */ }

        try
        {
            // 2) Путь установленной версии
            if (IsInstalled)
            {
                var baseDir = InstallPath;
                var neutral = Path.Combine(baseDir, "PawnIOLib.dll");
                if (File.Exists(neutral))
                {
                    Kernel32.LoadLibrary(neutral);
                    return;
                }

                // 3) Если в установке лежат только архитектурные имена — возьмём правильную и скопируем в TEMP под нейтральным именем.
                var tag = GetArchTag();
                var archDll = Path.Combine(baseDir, $"PawnIOLib_{tag}.dll");
                if (File.Exists(archDll))
                {
                    Directory.CreateDirectory(TempDir);
                    File.Copy(archDll, TempDllPath, overwrite: true);
                    Kernel32.LoadLibrary(TempDllPath);
                    return;
                }
            }
        }
        catch { /* ignore */ }

        // 4) Последний шанс — возможно, мы уже распаковали в TEMP в Open()
        try { if (File.Exists(TempDllPath)) Kernel32.LoadLibrary(TempDllPath); } catch { /* ignore */ }
    }

    // ===== P/Invoke в PawnIOLib (имя должно оставаться нейтральным!) =====

    [DllImport("PawnIOLib", ExactSpelling = true, PreserveSig = false)]
    private static extern void pawnio_version(out uint version);

    [DllImport("PawnIOLib", ExactSpelling = true, PreserveSig = false)]
    private static extern void pawnio_open(out IntPtr handle);

    [DllImport("PawnIOLib", ExactSpelling = true, PreserveSig = false)]
    private static extern void pawnio_load(IntPtr handle, byte* blob, IntPtr size);

    [DllImport("PawnIOLib", ExactSpelling = true, PreserveSig = false)]
    private static extern void pawnio_close(IntPtr handle);

    [DllImport("PawnIOLib", ExactSpelling = true, PreserveSig = false)]
    private static extern void pawnio_execute(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPStr)] string name,
        long[] inArray,
        IntPtr inSize,
        long[] outArray,
        IntPtr outSize,
        out IntPtr returnSize);

    [DllImport("PawnIOLib", ExactSpelling = true, EntryPoint = "pawnio_execute")]
    private static extern int pawnio_execute_hr(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPStr)] string name,
        long[] inArray,
        IntPtr inSize,
        long[] outArray,
        IntPtr outSize,
        out IntPtr returnSize);

    // ===== Остальной код класса без изменений =====
    private IntPtr _handle;

    public bool IsLoaded => _handle != IntPtr.Zero;

    public static Version Version()
    {
        try
        {
            TryLoadLibrary();
            pawnio_version(out uint version);
            return new Version((int)((version >> 16) & 0xFF),
                               (int)((version >> 8) & 0xFF),
                               (int)(version & 0xFF),
                               0);
        }
        catch { return new Version(); }
    }

    public void Close()
    {
        if (_handle != IntPtr.Zero)
            pawnio_close(_handle);
    }

    public static PawnIo LoadModuleFromResource(Assembly assembly, string resourceName)
    {
        var pawnIO = new PawnIo();

        using Stream s = assembly.GetManifestResourceStream(resourceName);

        if (s is UnmanagedMemoryStream ums)
        {
            TryLoadLibrary();

            try
            {
                pawnio_open(out IntPtr handle);
                pawnio_load(handle, ums.PositionPointer, (IntPtr)ums.Length);
                pawnIO._handle = handle;
            }
            catch { /* PawnIO not available */ }
        }

        return pawnIO;
    }

    public long[] Execute(string name, long[] input, int outLength)
    {
        long[] result = new long[outLength];

        if (_handle == IntPtr.Zero)
            return result;

        pawnio_execute(_handle, name, input, (IntPtr)input.Length, result, (IntPtr)result.Length, out nint returnLength);

        Array.Resize(ref result, (int)returnLength);
        return result;
    }

    public int ExecuteHr(string name, long[] inBuffer, uint inSize, long[] outBuffer, uint outSize, out uint returnSize)
    {
        if (inBuffer.Length < inSize) throw new ArgumentOutOfRangeException(nameof(inSize));
        if (outBuffer.Length < outSize) throw new ArgumentOutOfRangeException(nameof(outSize));

        if (_handle == IntPtr.Zero) { returnSize = 0; return 0; }

        int ret = pawnio_execute_hr(_handle, name, inBuffer, (IntPtr)inSize, outBuffer, (IntPtr)outSize, out IntPtr retSize);
        returnSize = (uint)retSize;
        return ret;
    }
}

// Простая оболочка над kernel32.LoadLibrary
internal static class Kernel32
{
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
}
