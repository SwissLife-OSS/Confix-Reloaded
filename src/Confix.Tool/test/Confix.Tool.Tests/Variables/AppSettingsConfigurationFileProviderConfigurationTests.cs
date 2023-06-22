using System.Text.Json.Nodes;
using Confix.ConfigurationFiles;
using FluentAssertions;

namespace Confix.Tool.Tests;

public class AppSettingsConfigurationFileProviderConfigurationTests
{

    [Fact]
    public void Parse_EmptyObject_ThrowsArgumentException()
    {
        // arrange
        var configuration = JsonNode.Parse("{}")!;

        // act
        Action act = () => AppSettingsConfigurationFileProviderConfiguration.Parse(configuration);

        // assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Parse_WithValidConfigurationKey_ReturnsValidObject()
    {
        // arrange
        var configuration = JsonNode.Parse(
            """
                {
                    "useUserSecrets": true
                }
                """
        )!;

        // act
        var result = AppSettingsConfigurationFileProviderConfiguration.Parse(configuration);

        // assert
        result.Should().Be(new AppSettingsConfigurationFileProviderConfiguration(
            true));
    }
}