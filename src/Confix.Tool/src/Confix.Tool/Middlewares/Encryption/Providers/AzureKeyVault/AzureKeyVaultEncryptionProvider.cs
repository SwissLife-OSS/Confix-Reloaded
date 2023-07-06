using System.Text.Json.Nodes;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Confix.Utilities.Azure;

namespace Confix.Tool.Middlewares.Encryption.Providers.AzureKeyvault;

public sealed class AzureKeyVaultEncryptionProvider : IEncryptionProvider
{
    private const int ChunkSize = 250;
    private readonly CryptographyClient _client;

    public AzureKeyVaultEncryptionProvider(JsonNode configuration)
        : this(AzureKeyVaultEncryptionProviderConfiguration.Parse(configuration))
    {
    }

    public AzureKeyVaultEncryptionProvider(
        AzureKeyVaultEncryptionProviderConfiguration configuration)
        : this(AzureKeyVaultEncryptionProviderDefinition.From(configuration))
    {
    }

    public AzureKeyVaultEncryptionProvider(AzureKeyVaultEncryptionProviderDefinition definition)
        : this(new KeyClient(new Uri(definition.Uri), new DefaultAzureCredential())
            .GetCryptographyClient(definition.KeyName, definition.KeyVersion))
    {
    }

    public AzureKeyVaultEncryptionProvider(CryptographyClient client)
    {
        _client = client;
    }

    public const string Type = "AzureKeyVault";

    public Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken)
        => KeyVaultExtension.HandleKeyVaultException(async () =>
        {
            using var inputStream = new MemoryStream(data);
            using var outputStream = new MemoryStream();

            var totalBytes = inputStream.Length;
            var buffer = new byte[512];
            int bytesRead;
            long totalBytesRead = 0;

            while ((bytesRead =
                await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
            {
                DecryptResult decrypted = await _client.DecryptAsync(EncryptionAlgorithm.RsaOaep256,
                    buffer, cancellationToken);
                await outputStream.WriteAsync(decrypted.Plaintext, 0, decrypted.Plaintext.Length,
                    cancellationToken);

                totalBytesRead += bytesRead;
                Console.WriteLine($"Encrypting... {totalBytesRead}/{totalBytes} bytes");
            }

            return outputStream.ToArray();
        });

    public Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken)
        => KeyVaultExtension.HandleKeyVaultException(async () =>
        {
            using var inputStream = new MemoryStream(data);
            using var outputStream = new MemoryStream();

            var totalBytes = inputStream.Length;
            var buffer = new byte[ChunkSize];
            int bytesRead;
            long totalBytesRead = 0;

            while ((bytesRead =
                await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
            {
                EncryptResult encrypted = await _client.EncryptAsync(EncryptionAlgorithm.RsaOaep256,
                    buffer, cancellationToken);
                await outputStream.WriteAsync(encrypted.Ciphertext, 0, encrypted.Ciphertext.Length,
                    cancellationToken);

                totalBytesRead += bytesRead;
                Console.WriteLine($"Encrypting... {totalBytesRead}/{totalBytes} bytes");
            }

            return outputStream.ToArray();
        });
}