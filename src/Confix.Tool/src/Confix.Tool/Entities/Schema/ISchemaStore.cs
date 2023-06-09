using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Nodes;
using Confix.Tool.Abstractions;
using Json.Schema;

namespace Confix.Tool.Entities.Components.DotNet;

public interface ISchemaStore
{
    Task<FileInfo> StoreAsync(
        SolutionDefinition solution,
        ProjectDefinition project,
        JsonSchema schema,
        CancellationToken cancellationToken);

    bool TryLoad(
        SolutionDefinition solution,
        ProjectDefinition project,
        [NotNullWhen(true)] out JsonSchema? schema);
}
