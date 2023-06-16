using System.Text.Json.Nodes;

namespace ConfiX.Variables;

public sealed class GitVariableProvider : IVariableProvider
{
    private readonly GitVariableProviderConfiguration _configuration;
    private readonly LocalVariableProvider _localVariableProvider;

    public GitVariableProvider(JsonNode configuration)
        : this(GitVariableProviderConfiguration.Parse(configuration))
    { }

    public GitVariableProvider(GitVariableProviderConfiguration configuration)
    {
        _configuration = configuration;
        _localVariableProvider = new LocalVariableProvider(new LocalVariableProviderConfiguration
        {
            FilePath = Path.Combine(configuration.CloneDirectory, configuration.FilePath)
        });
    }

    public async Task<IReadOnlyList<string>> ListAsync(CancellationToken cancellationToken)
    {
        await EnsureCloned(cancellationToken);
        return await _localVariableProvider.ListAsync(cancellationToken);
    }

    public async Task<JsonNode> ResolveAsync(string path, CancellationToken cancellationToken)
    {
        await EnsureCloned(cancellationToken);
        return await _localVariableProvider.ResolveAsync(path, cancellationToken);
    }

    public async Task<IReadOnlyDictionary<string, JsonNode>> ResolveManyAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken)
    {
        await EnsureCloned(cancellationToken);
        return await _localVariableProvider.ResolveManyAsync(paths, cancellationToken);
    }

    public async Task<string> SetAsync(string path, JsonNode value, CancellationToken cancellationToken)
    {
        await EnsureCloned(cancellationToken);
        return await _localVariableProvider.SetAsync(path, value, cancellationToken);
    }

    private async Task EnsureCloned(CancellationToken cancellationToken)
    {
        GitCloneConfiguration configuration = new(
            _configuration.RepositoryUrl,
            _configuration.CloneDirectory,
            _configuration.Branch,
            _configuration.Depth,
            _configuration.Arguments
        );

        await GitHelpers.Clone(configuration, cancellationToken);
        // TODO: maybe pull/fetch if the repo is already cloned in that location
    }
}
