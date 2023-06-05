using System.CommandLine.Builder;
using Confix.Tool.Entities.Component;
using ConfiX.Variables;
using Microsoft.Extensions.DependencyInjection;

namespace Confix.Tool.Middlewares;

public static class MiddlewareCommandLineBuilderExtensions
{
    public static CommandLineBuilder RegisterMiddlewares(this CommandLineBuilder builder)
    {
        builder
            .AddSingleton<ExecuteComponentOutput>()
            .AddSingleton<LoadConfigurationMiddleware>()
            .RegisterComponentInputs()
            .RegisterVariableMiddleware();

        return builder;
    }
}
