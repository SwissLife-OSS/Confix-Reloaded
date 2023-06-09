using Confix.Tool.Abstractions;
using Confix.Tool.Commands.Logging;
using Confix.Tool.Common.Pipelines;
using Confix.Tool.Entities.Components;
using Confix.Tool.Entities.Components.DotNet;
using Confix.Tool.Middlewares.JsonSchemas;
using Confix.Tool.Schema;

namespace Confix.Tool.Middlewares.Project;

public class ReloadProjectMiddleware : IMiddleware
{
    private readonly IProjectComposer _projectComposer;

    private readonly ISchemaStore _schemaStore;

    public ReloadProjectMiddleware(IProjectComposer projectComposer, ISchemaStore schemaStore)
    {
        _projectComposer = projectComposer;
        _schemaStore = schemaStore;
    }

    /// <inheritdoc />
    public async Task InvokeAsync(IMiddlewareContext context, MiddlewareDelegate next)
    {
        context.SetStatus("Reloading the schema of the project...");

        var cancellationToken = context.CancellationToken;

        var jsonSchemas = context.Features.Get<JsonSchemaFeature>();
        var configuration = context.Features.Get<ConfigurationFeature>();
        var files = context.Features.Get<ConfigurationFileFeature>().Files;

        configuration.EnsureProjectScope();

        var project = configuration.EnsureProject();
        var solution = configuration.EnsureSolution();

        var componentProvider =
            context.Features.Get<ComponentProviderExecutorFeature>().Executor;

        var providerContext =
            new ComponentProviderContext(context.Logger, cancellationToken, project, solution);

        context.SetStatus("Loading components...");
        await componentProvider.ExecuteAsync(providerContext);
        var components = providerContext.Components;
        context.Logger.LogComponentsLoaded(components);

        context.SetStatus("Loading variables...");
        var variableResolver = context.Features.Get<VariableResolverFeature>().Resolver;
        var variables = await variableResolver.ListVariables(cancellationToken);

        context.SetStatus("Composing the schema...");
        var jsonSchema = _projectComposer.Compose(components, variables);
        context.Logger.LogSchemaCompositionCompleted(project);

        var schemaFile = await _schemaStore
            .StoreAsync(solution, project, jsonSchema, cancellationToken);

        var jsonSchemaDefinition = new JsonSchemaDefinition()
        {
            Project = project,
            Solution = solution.Directory!,
            FileMatch = files.Select(x => x.InputFile.RelativeTo(solution.Directory!)).ToList(),
            SchemaFile = schemaFile,
            RelativePathToProject =
                Path.GetRelativePath(solution.Directory!.FullName, project.Directory!.FullName)
        };

        jsonSchemas.Schemas.Add(jsonSchemaDefinition);
    }
}

file static class Log
{
    public static void LogComponentsLoaded(
        this IConsoleLogger console,
        ICollection<Component> components)
    {
        console.Success($"Loaded {components.Count} components");
        foreach (var component in components)
        {
            console.Information($"-  @{component.Provider}/{component.ComponentName}");
        }
    }

    public static void LogSchemaCompositionCompleted(
        this IConsoleLogger console,
        ProjectDefinition project)
    {
        console.Success($"Schema composition completed for project {project.Name}");
    }
}
