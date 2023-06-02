using Spectre.Console;

namespace Confix.Tool.Common.Pipelines;

public class MiddlewareContext : IMiddlewareContext
{
    public IFeatureCollection Features { get; } = new FeatureCollection();

    /// <inheritdoc />
    public IDictionary<string, object> ContextData { get; } = new Dictionary<string, object>();

    public required CancellationToken CancellationToken { get; init; }

    /// <inheritdoc />
    public required IExecutionContext Execution { get; init; }
    
    /// <inheritdoc />
    public required IAnsiConsole Console { get; init; }

    /// <inheritdoc />
    public required IParameterCollection Parameter { get; init; }

    public int ExitCode { get; set; } = ExitCodes.Error;
}