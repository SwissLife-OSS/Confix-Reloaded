using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Json;

namespace Confix.Tool;

public static class ConsoleExtensions
{
    public static void Error(this IAnsiConsole console, string message)
    {
        console.MarkupLine($"[red]{message.EscapeMarkup()}[/]");
    }

    public static void Success(this IAnsiConsole console, string message)
    {
        console.MarkupLine($"[green]{message.EscapeMarkup()}[/]");
    }
    
    /// <summary>
    /// Writes a json object to the console
    /// </summary>
    /// <param name="console">
    /// The console to write to
    /// </param>
    /// <param name="data">
    /// The data to write
    /// </param>
    public static void WriteJson(this IAnsiConsole console, object? data)
    {
        var serializedData =
            JsonSerializer.Serialize(data, new JsonSerializerOptions() { WriteIndented = true });

        var jsonText = new JsonText(serializedData);

        console.Write(jsonText);
    }
}