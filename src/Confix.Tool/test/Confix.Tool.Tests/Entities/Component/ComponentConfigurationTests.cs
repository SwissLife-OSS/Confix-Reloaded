using System.Text.Json.Nodes;
using Confix.Tool.Abstractions;
using Confix.Tool.Schema;

namespace ConfiX.Entities.Component.Configuration;

public class ComponentConfigurationTests : ParserTestBase
{
    [Fact]
    public void Parse_Should_ReturnValidComponentConfiguration_When_ValidJsonNodeProvided()
    {
        ExpectValid(
            """
            {
                "name": "TestComponent",
                "inputs": [
                    {
                        "type": "graphql",
                        "additional": "property"
                    },
                    {
                        "type": "dotnet",
                        "additional2": "property"
                    }
                ],
                "outputs": [
                    {
                        "type": "schema",
                        "additional2": "property"
                    }
                ]
            }
        """);
    }

    [Fact]
    public void Parse_Should_BeValid_WhenEmpty()
    {
        ExpectValid(""" { } """);
    }

    [Fact]
    public void Parse_ShouldBeInvalid_When_InputsIsNotAnArray()
    {
        ExpectInvalid(
            """
            {
                "name": "TestComponent",
                "inputs": {
                    "type": "graphql",
                    "additional": "property"
                },
                "outputs": [
                    {
                        "type": "schema",
                        "additional2": "property"
                    }
                ]
            }
         """);
    }

    [Fact]
    public void Parse_ShouldBeInvalid_When_OutputsIsNotAnArray()
    {
        ExpectInvalid(
            """
            {
                "name": "TestComponent",
                "inputs": [
                    {
                        "type": "graphql",
                        "additional": "property"
                    },
                    {
                        "type": "dotnet",
                        "additional2": "property"
                    }
                ],
                "outputs": {
                    "type": "schema",
                    "additional2": "property"
                }
            }
         """);
    }

    [Fact]
    public void Merge_Should_ReturnOriginalConfiguration_When_OtherConfigurationIsNull()
    {
        // Arrange
        var original = new ComponentConfiguration("TestComponent",
            new List<ComponentInputConfiguration>(),
            new List<ComponentOutputConfiguration>(),
            Array.Empty<FileInfo>());

        // Act
        var merged = original.Merge(null);

        // Assert
        Assert.Same(original, merged);
    }

    [Fact]
    public void Merge_Should_ReturnMergedConfiguration_When_OtherConfigurationIsNotNull()
    {
        // Arrange
        var original = new ComponentConfiguration("TestComponent",
            new List<ComponentInputConfiguration>()
            {
                new("Test", JsonNode.Parse("{}")!)
            },
            new List<ComponentOutputConfiguration>()
            {
                new("Test", JsonNode.Parse("{}")!)
            },
            Array.Empty<FileInfo>());
        var other = new ComponentConfiguration("MergedComponent",
            new List<ComponentInputConfiguration>()
            {
                new("Test2", JsonNode.Parse("{}")!)
            },
            new List<ComponentOutputConfiguration>()
            {
                new("Test2", JsonNode.Parse("{}")!)
            },
            Array.Empty<FileInfo>());

        // Act
        var merged = original.Merge(other);

        // Assert
        Assert.NotSame(original, merged);
        Assert.Equal("MergedComponent", merged.Name);
        Assert.Equal("Test2", Assert.Single(merged.Inputs!).Type);
        Assert.Equal("Test2", Assert.Single(merged.Outputs!).Type);
    }

    [Fact]
    public void LoadFromFiles_Should_ReturnNull_When_ConfixRcFileNotPresent()
    {
        // Arrange
        var configuration = Array.Empty<FileInfo>();

        // Act
        var result = ComponentConfiguration.LoadFromFiles(configuration);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void LoadFromFiles_Should_LoadFromFile()
    {
        // Arrange
        var confixRcPath = Path.Combine(Path.GetTempPath(), FileNames.ConfixComponent);
        var configuration = new List<FileInfo>
        {
            new(confixRcPath)
        };
        File.WriteAllText(
            confixRcPath,
            """
            {
                "name": "TestComponent",
                "inputs": [],
                "outputs": []
            }
            """);

        // Act
        var result = ComponentConfiguration.LoadFromFiles(configuration);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("TestComponent", result.Name);
        Assert.Empty(result.Inputs!);
        Assert.Empty(result.Outputs!);

        // Cleanup
        File.Delete(confixRcPath);
    }

    [Fact]
    public void LoadFromFiles_Should_OnlyLoadComponent()
    {
        // Arrange
        var confixRcPath = Path.Combine(Path.GetTempPath(), FileNames.ConfixProject);
        var configuration = new List<FileInfo>
        {
            new(confixRcPath)
        };
        File.WriteAllText(
            confixRcPath,
            """
            {
                "name": "TestComponent",
                "inputs": [],
                "outputs": []
            }
            """);

        // Act
        var result = ComponentConfiguration.LoadFromFiles(configuration);

        // Assert
        Assert.Null(result);

        // Cleanup
        File.Delete(confixRcPath);
    }

    /// <inheritdoc />
    public override object Parse(JsonNode json)
        => ComponentConfiguration.Parse(json);
}