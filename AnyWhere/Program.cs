using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;

class Program
{
    static List<string> initialProcesses = new List<string>();
    static List<string> AppArgs = new List<string>();

    public static string filePath;
    static void Main()
    {
        //StartBootstrapper();
        //StartBootstrapperCrashHandler();
        //StartCod();
        //StartCodCrashHandler();

        // Get the application's current directory
        string currentDirectory = AppDomain.CurrentDomain.BaseDirectory;
        filePath = Path.Combine(currentDirectory, "output.txt");

        try
        {
            // Create or open the file for writing
            using (StreamWriter writer = File.CreateText(filePath))
            {
                writer.WriteLine("Application started.");
            }

            // Get the initial list of running processes
            GetInitialProcesses();

            // Create a folder for new apps if it doesn't exist
            string newAppsDirectory = Path.Combine(currentDirectory, "New Apps");
            Directory.CreateDirectory(newAppsDirectory);

            // Start an infinite loop
            while (true)
            {
                List<string> currentProcesses = GetCurrentProcesses();
                List<string> closedProcesses = initialProcesses.Except(currentProcesses).ToList();

                foreach (string processName in closedProcesses)
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine($"Program Closed: {processName}" + "\n");
                    Console.ResetColor();

                    using (StreamWriter writer = File.AppendText(filePath))
                    {
                        writer.WriteLine($"App Closed: {processName}");
                    }
                }

                //initialProcesses = currentProcesses;

                foreach (string processName in currentProcesses)
                {
                    if (!initialProcesses.Contains(processName))
                    {
                        string appLocation = GetAppLocation(processName);
                        if (appLocation != null)
                        {
                            List<string> commandLines = GetCommandLines(processName);
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"New App Found: {processName} | App Location: {appLocation}");
                            Console.ResetColor();

                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"New App Found: {processName} | App Location: {appLocation}");
                            }

                            if (commandLines.Count > 0)
                            {
                                //Console.WriteLine("Command Lines/Arguments:");
                                foreach (string commandLine in commandLines)
                                {
                                    if (!AppArgs.Contains(commandLine))
                                    {
                                        Console.ForegroundColor = ConsoleColor.Red;
                                        Console.WriteLine(commandLine + "\n");
                                        Console.ResetColor();
                                        using (StreamWriter writer = File.AppendText(filePath))
                                        {
                                            writer.WriteLine(commandLine);
                                        }
                                        AppArgs.Add(commandLine); // Add the command-line argument to the list
                                    }
                                }
                            }
                            else
                            {
                                //Console.WriteLine("No command lines/arguments found.");

                                using (StreamWriter writer = File.AppendText(filePath))
                                {
                                    writer.WriteLine("No command lines/arguments found.");
                                }
                            }

                            string destinationPath = Path.Combine(newAppsDirectory, Path.GetFileName(appLocation));

                            try
                            {
                                if (!File.Exists(destinationPath))
                                {
                                    File.Copy(appLocation, destinationPath);
                                    initialProcesses.Add(processName);
                                }
                                else
                                {
                                    //Console.WriteLine($"File already exists at {destinationPath}. Skipped copying.");

                                    using (StreamWriter writer = File.AppendText(filePath))
                                    {
                                        writer.WriteLine($"File already exists at {destinationPath}. Skipped copying.");
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                //Console.WriteLine($"Error copying file: {ex.Message}");
                                using (StreamWriter writer = File.AppendText(filePath))
                                {
                                    writer.WriteLine($"Error copying file: {ex.Message}");
                                }
                            }
                        }
                        else
                        {
                            //Console.WriteLine($"App Location for {processName} is not accessible. Skipping.");
                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"App Location for {processName} is not accessible. Skipping.");
                            }
                        }

                        initialProcesses.Add(processName);

                    }
                }

                initialProcesses = currentProcesses;
                System.Threading.Thread.Sleep(0); // Sleep for 5 seconds
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unhandled Exception: {ex}");
            using (StreamWriter writer = File.AppendText(filePath))
            {
                writer.WriteLine($"Unhandled Exception: {ex}");
            }
        }

        Console.WriteLine("Press Any Key To Exit!");
        Console.ReadLine();
    }


    static List<string> GetCommandLines(string processName)
    {
        List<string> commandLines = new List<string>();
        Process[] processes = Process.GetProcessesByName(processName);

        foreach (Process process in processes)
        {
            try
            {
                commandLines.Add(process.StartInfo.Arguments);
            }
            catch (Win32Exception ex)
            {
                Console.WriteLine($"Error getting command line for process {processName}: {ex.Message}");
                using (StreamWriter writer = File.AppendText(filePath))
                {
                    writer.WriteLine($"Error getting command line for process {processName}: {ex.Message}");
                }
            }
        }

        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE Name = '{processName}.exe'"))
        {
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    commandLines.Add(obj["CommandLine"].ToString());
                }
                catch (Win32Exception ex)
                {
                    Console.WriteLine($"Error getting command line for process {processName}: {ex.Message}");
                    using (StreamWriter writer = File.AppendText(filePath))
                    {
                        writer.WriteLine($"Error getting command line for process {processName}: {ex.Message}");
                    }
                }
            }
        }

        return commandLines;
    }

    static void StartApplication(string commandLine)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C {commandLine}",
                RedirectStandardOutput = false,
                UseShellExecute = true,
                CreateNoWindow = true
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static void GetInitialProcesses()
    {
        foreach (Process process in Process.GetProcesses())
        {
            initialProcesses.Add(process.ProcessName);
        }
    }

    static List<string> GetCurrentProcesses()
    {
        List<string> currentProcesses = new List<string>();

        foreach (Process process in Process.GetProcesses())
        {
            currentProcesses.Add(process.ProcessName);
        }

        return currentProcesses;
    }

    static string GetAppLocation(string processName)
    {
        try
        {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length > 0)
            {
                return processes[0].MainModule.FileName;
            }
        }
        catch (Exception)
        {
            // Handle exceptions if the process is inaccessible
        }

        return "N/A";
    }

    static void StartDxdiag()
    {
        string appLocation = @"C:\WINDOWS\SYSTEM32\dxdiag.exe";
        string arguments = @"/dontskip /whql:off /t ""C:\Users\Mercy\AppData\Local\Temp\Activision\bootstrapper\20231023-231633755\dxdiag_onboot.txt""";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process dxdiagProcess = new Process() { StartInfo = startInfo };
        dxdiagProcess.Start();
        dxdiagProcess.WaitForExit();
    }

    static void StartMoUsoCoreWorker()
    {
        string appLocation = @"C:\Windows\System32\mousocoreworker.exe";
        string arguments = @"-Embedding";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process mousoCoreWorkerProcess = new Process() { StartInfo = startInfo };
        mousoCoreWorkerProcess.Start();
        mousoCoreWorkerProcess.WaitForExit();
    }

    static void StartBootstrapper()
    {
        string appLocation = @"C:\Program Files (x86)\Call of Duty\_retail_\bootstrapper.exe";
        string arguments = @"cod.exe -uid auks";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process bootstrapperProcess = new Process() { StartInfo = startInfo };
        bootstrapperProcess.Start();
        bootstrapperProcess.WaitForExit();
    }

    static void StartBootstrapperCrashHandler()
    {
        string appLocation = @"C:\Program Files (x86)\Call of Duty\_retail_\bootstrappercrashhandler.exe";
        string arguments = @"--project ""bootstrapper"" --engine_pid 24800 --engine_build ""public_ship"" --engine_exec_name ""bootstrapper.exe"" --engine_changelist 1 --exception_info_addr 140695177063952 --shared_mutex_name ""namedMutex-20231023-231633755"" --folder_crashreport ""C:\Users\Mercy\AppData\Local\Activision\bootstrapper\crash_reports"" --folder_temp ""C:\Users\Mercy\AppData\Local\Temp\Activision\bootstrapper\20231023-231633755"" --fullpath_datafile ""C:\Users\Mercy\AppData\Local\Temp\Activision\bootstrapper\20231023-231633755\datafile.json"" --fullpath_bnet_launcher ""C:\Program Files (x86)\Call of Duty\_retail_\\"" --used_version_lib ""0.24.1"" --used_version_app ""0.21.4"" --time_code ""20231023-231633755"" --throttle_dev 1.000000 --throttle_prod 0.020000 --titleid_dev 6031 --titleid_prod 6031 --first_party ""bnet"" --first_party_project ""auks"" --opt-allow_crash_upload --opt-allow_dump_generation --opt-packaged_build";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process bootstrapperCrashHandlerProcess = new Process() { StartInfo = startInfo };
        bootstrapperCrashHandlerProcess.Start();
        bootstrapperCrashHandlerProcess.WaitForExit();
    }

    static void StartCod()
    {
        string appLocation = @"C:\Program Files (x86)\Call of Duty\_retail_\cod.exe";
        string arguments = @"-uid auks hdeyguxs3zaumvlgvybm2vyc";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process codProcess = new Process() { StartInfo = startInfo };
        codProcess.Start();
        codProcess.WaitForExit();
    }

    static void StartCodCrashHandler()
    {
        string appLocation = @"C:\Program Files (x86)\Call of Duty\_retail_\codCrashHandler.exe";
        string arguments = @"hdeyguxs3zaumvlgvybm2vyc --project ""iw9"" --engine_pid 24580 --engine_build ""public_ship"" --engine_exec_name ""cod.exe"" --engine_changelist 16245188 --exception_info_addr 140701575390144 --shared_mutex_name ""namedMutex-20231023-231649180"" --folder_crashreport ""C:\Users\Mercy\AppData\Local\Activision\Call of Duty\crash_reports"" --folder_temp ""C:\Users\Mercy\AppData\Local\Temp\Activision\Call of Duty\20231023-231649180"" --fullpath_datafile ""C:\Users\Mercy\AppData\Local\Temp\Activision\Call of Duty\20231023-231649180\datafile.json"" --fullpath_bnet_launcher ""C:\Program Files (x86)\Call of Duty\_retail_\cod Launcher.exe"" --used_version_lib ""0.26.0"" --used_version_app ""0.22.0"" --time_code ""20231023-231649180"" --throttle_dev 1.000000 --throttle_prod 0.020000 --titleid_dev 5886 --titleid_prod 7000 --first_party ""bnet"" --first_party_project ""AUKS"" --opt-allow_crash_upload --opt-allow_dump_generation --opt-allow_popup_display --opt-packaged_build --opt-enable_save_dlog_events_feature";

        ProcessStartInfo startInfo = new ProcessStartInfo(appLocation)
        {
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        Process codCrashHandlerProcess = new Process() { StartInfo = startInfo };
        codCrashHandlerProcess.Start();
        codCrashHandlerProcess.WaitForExit();
    }
}
