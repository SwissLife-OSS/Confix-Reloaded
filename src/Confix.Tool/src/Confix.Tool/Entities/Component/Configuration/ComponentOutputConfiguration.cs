using System.Text.Json.Nodes;
using Confix.Utilities.Json;

namespace Confix.Tool.Abstractions;

public sealed class ComponentOutputConfiguration
{
    private static class FieldNames
    {
        public const string Type = "type";
    }

    public ComponentOutputConfiguration(string? type, JsonNode value)
    {
        Type = type;
        Value = value;
    }

    public string? Type { get; }

    public JsonNode Value { get; }

    public static ComponentOutputConfiguration Parse(JsonNode element)
    {
        var obj = element.ExpectObject();
        var type = obj.MaybeProperty(FieldNames.Type)?.ExpectValue<string>();

        return new ComponentOutputConfiguration(type, element);
    }

    public ComponentOutputConfiguration Merge(ComponentOutputConfiguration? other)
    {
        if (other is null)
        {
            return this;
        }

        var type = other.Type ?? Type;
        var value = Value.Merge(other.Value) ?? new JsonObject();

        return new ComponentOutputConfiguration(type, value);
    }
}
