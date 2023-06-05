namespace Confix.Tool.Commands.Logging;

public static class StringExtensions
{
    public static string AsHighlighted(this string value)
    {
        return $"[bold blue]{value}[/]";
    }
}
