using Spectre.Console;
using System;
using System.Linq;

namespace RedOps.Utils
{
    public static class UIHelper
    {
        private static readonly string LogoString = 
            "  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ███████╗\n" +
            "  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝\n" +
            "  ██████╔╝█████╗  ██║  ██║██║   ██║██████╔╝███████╗\n" +
            "  ██╔══██╗██╔══╝  ██║  ██║██║   ██║██╔═══╝ ╚════██║\n" +
            "  ██║  ██║███████╗██████╔╝╚██████╔╝██║     ███████║\n" +
            "  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝";

        public static void DisplayHeader(string title)
        {
            AnsiConsole.Clear();
            
            // Center the ASCII logo
            var logoLines = LogoString.Split('\n');
            var consoleWidth = AnsiConsole.Profile.Width;
            // Calculate the maximum width of a logo line without markup for centering purposes
            var maxLogoLineWidth = logoLines.Select(line => Markup.Remove(line).Length).Max();

            foreach (var line in logoLines)
            {
                var plainLineLength = Markup.Remove(line).Length;
                var paddingLength = (consoleWidth - plainLineLength) / 2;
                string padding = new string(' ', paddingLength > 0 ? paddingLength : 0);
                AnsiConsole.MarkupLine(padding + "[red]" + Markup.Remove(line) + "[/]"); // Apply color after padding
            }
            
            AnsiConsole.WriteLine(); // Add a blank line after the logo
            AnsiConsole.Write(new Rule($"[bold white on red]{title}[/]").Centered());
            AnsiConsole.WriteLine();
            AnsiConsole.WriteLine(); // Add some space before menu items
        }
    }
}
