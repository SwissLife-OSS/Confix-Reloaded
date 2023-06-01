using System.Text.Json.Nodes;

namespace ConfiX.Variables;

public class LocalVariableProvider : IVariableProvider
{
    public static readonly string PropertyType = "local";
    public LocalVariableProvider(JsonNode configuration)
    {
        _filePath = ((string?)configuration["path"]) ?? throw new ArgumentException("Missing path parameter");
    }

    private readonly string _filePath;

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string> ResolveAsync(string path, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IReadOnlyDictionary<string, string>> ResolveManyAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string> SetAsync(string path, string value, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}

/*
confix variables reload: This command reloads the variables for a project from the providers. Useful for updating your local environment with newly created variables.

confix variables set <variable> <value>: This command sets the value for a specified variable.

confix variables get <variable>: This command retrieves the current value of a specified variable.
*/