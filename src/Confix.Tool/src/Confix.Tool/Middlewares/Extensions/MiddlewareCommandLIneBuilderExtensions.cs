using System.CommandLine.Builder;
using Confix.Tool.Entities.Components;
using Confix.Tool.Entities.Components.DotNet;
using Confix.Tool.Middlewares.Encryption;
using Confix.Tool.Middlewares.JsonSchemas;
using Confix.Tool.Middlewares.Project;
using Microsoft.Extensions.DependencyInjection;

namespace Confix.Tool.Middlewares;

public static class MiddlewareCommandLineBuilderExtensions
{
    public static CommandLineBuilder RegisterMiddlewares(this CommandLineBuilder builder)
    {
        builder
            .AddTransient<LoadConfigurationMiddleware>()
            .AddTransient<EnvironmentMiddleware>()
            .RegisterProjectMiddlewares()
            .RegisterComponentInputs()
            .RegisterConfigurationFiles()
            .RegisterComponentProviders()
            .RegisterConfigurationAdapters()
            .RegisterJsonSchemaCollectionMiddleware()
            .RegisterVariableMiddleware()
            .RegisterEncryptionMiddleware();

        return builder;
    }
}
