
using System.Diagnostics;
using Confix.Tool.Commands.Logging;

namespace ConfiX.Variables;

public static class GitHelpers
{
    public static async Task Clone(
        GitCloneConfiguration configuration,
        CancellationToken cancellationToken)
    {
        List<string> arguments = new()
        {
            "clone"
        };
        if (configuration.Arguments?.Length > 0)
        {
            arguments.AddRange(configuration.Arguments);
        }
        arguments.Add(configuration.RepositoryUrl);
        arguments.Add(configuration.Location);

        using Process process = new()
        {
            StartInfo = new()
            {
                FileName = "git",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                Arguments = string.Join(" ", arguments)
            }
        };

        try
        {
            App.Log.GitCloneStarted(configuration.RepositoryUrl);
            process.Start();

            await process.WaitForExitAsync(cancellationToken);

            string output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            App.Log.GitCloneOutput(output);

            process.EnsureExitCode();
        }
        catch (Exception ex)
        {
            App.Log.GitCloneFailed(ex);
        }
    }
}

public record GitCloneConfiguration(
    string RepositoryUrl,
    string Location,
    string[]? Arguments
);

file static class LogExtensions
{
    public static void EnsureExitCode(this Process process)
    {
        if (process.ExitCode != 0)
        {
            throw new Exception($"Process exited with code {process.ExitCode}");
        }
    }

    public static void GitCloneStarted(this IConsoleLogger log, string repositoryUrl)
    {
        log.Debug($"Cloning {repositoryUrl} ...");
    }

    public static void GitCloneOutput(this IConsoleLogger log, string output)
    {
        log.Debug(output);
    }

    public static void GitCloneFinished(this IConsoleLogger log, int exitCode)
    {
        log.Debug($"Cloning completed with exit code {exitCode}");
    }

    public static void GitCloneFailed(this IConsoleLogger log, Exception ex)
    {
        log.Exception("Git clone failed", ex);
    }
}