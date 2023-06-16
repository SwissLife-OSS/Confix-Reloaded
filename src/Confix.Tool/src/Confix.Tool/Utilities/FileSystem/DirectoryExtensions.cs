namespace Confix.Tool.Commands.Temp;

public static class DirectoryExtensions
{
    public static FileInfo? FindInPath(
        this DirectoryInfo directory,
        string fileName,
        bool recursive = true)
        => Directory
            .EnumerateFiles(
                directory.FullName,
                fileName,
                recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Select(x => new FileInfo(x))
            .FirstOrDefault();

    public static IEnumerable<FileInfo> FindAllInPath(
        this DirectoryInfo directory,
        string pattern,
        bool recursive = true)
        => Directory
            .EnumerateFiles(
                directory.FullName,
                pattern,
                recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Select(x => new FileInfo(x));

    public static string? FindInTree(this DirectoryInfo directory, string fileName)
    {
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException($"The directory '{directory}' was not found.");
        }

        var currentDirectory = directory.FullName;
        while (true)
        {
            var file = Path.Combine(currentDirectory, fileName);
            if (File.Exists(file))
            {
                return file;
            }

            var parentDirectory = Directory.GetParent(currentDirectory);
            if (parentDirectory is null)
            {
                return null;
            }

            currentDirectory = parentDirectory.FullName;
        }
    }

    public static IEnumerable<FileInfo> FindAllInTree(this DirectoryInfo directory, string fileName)
    {
        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException(
                $"The directory '{directory.FullName}' was not found.");
        }

        var currentDirectory = directory.FullName;
        while (true)
        {
            var file = Path.Combine(currentDirectory, fileName);
            if (File.Exists(file))
            {
                yield return new FileInfo(file);
            }

            var parentDirectory = Directory.GetParent(currentDirectory);
            if (parentDirectory is null)
            {
                yield break;
            }

            currentDirectory = parentDirectory.FullName;
        }
    }
}