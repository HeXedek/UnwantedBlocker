using System.Diagnostics;

namespace ConsoleApp15
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Process.Start("conhost.exe",Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\ShitBlockar\\frontendmaybe.exe");

        }
    }
}
