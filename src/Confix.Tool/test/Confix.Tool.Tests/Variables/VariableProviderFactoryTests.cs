using System.Text.Json.Nodes;
using ConfiX.Variables;
using FluentAssertions;

namespace Confix.Tool.Tests;

public class VariableProviderFactoryTests
{
    [Fact]
    public void CreateProvider_KnownProviderType_CreatesProvider()
    {
        // Arrange
        string providerType = "test";
        var factory = new VariableProviderFactory(
            new Dictionary<string, Func<JsonNode, IVariableProvider>>()
            {
                { providerType, (c) => new LocalVariableProvider(c) },
            });

        VariableProviderConfiguration configuration = new()
        {
            Name = "irrelevant",
            Type = providerType,
            Configuration = JsonNode.Parse("""
            {
                "path": "/path/to/file.json"
            }
            """)!
        };
        // Act
        var provider = factory.CreateProvider(configuration);

        // Assert
        provider.Should().NotBeNull();
        provider.Should().BeOfType<LocalVariableProvider>();
    }

    [Fact]
    public void CreateProvider_UnknownProviderType_ExitException()
    {
        // Arrange
        var factory = new VariableProviderFactory(
             new Dictionary<string, Func<JsonNode, IVariableProvider>>()
             {
                { "NOT-the-one-we-are-looking-for", (c) => new LocalVariableProvider(c) },
             });

        VariableProviderConfiguration configuration = new()
        {
            Name = "irrelevant",
            Type = "the-one-we-are-looking-for",
            Configuration = JsonNode.Parse("""
            {
                "path": "/path/to/file.json"
            }
            """)!
        };

        // Act & Assert
        Assert.Throws<ExitException>(() => factory.CreateProvider(configuration));
    }
}
