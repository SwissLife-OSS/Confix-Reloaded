namespace Confix.Tool.Commands.Logging;

public interface IConsoleLogger
{
    void Log(ref ILoggerMessage message);
}
