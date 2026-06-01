using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

// ReSharper disable once CheckNamespace — extensions for IServiceCollection / IHealthChecksBuilder
// live in the host's namespace by .NET convention, so they appear without an extra `using`.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// <see cref="IServiceCollection"/> extensions that wire a local
/// <see cref="IContentKeyProvider"/> into a Microsoft.Extensions.DependencyInjection host.
/// </summary>
public static class KeyManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers a singleton <see cref="IContentKeyProvider"/> backed by
    /// <see cref="LocalContentKeyProvider"/>, configured by <paramref name="configure"/>. If
    /// <see cref="KeyManagementOptions.KeyringPath"/> is set, a <see cref="FileKeyringStore"/> is
    /// registered as <see cref="IKeyringStore"/> and the provider is rebuilt from the persisted
    /// ring on first resolution (or created and saved on first run).
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Callback to populate <see cref="KeyManagementOptions"/>.</param>
    /// <returns>The same collection, for chaining.</returns>
    public static IServiceCollection AddPostQuantumKeyManagement(
        this IServiceCollection services,
        Action<KeyManagementOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var snapshot = new KeyManagementOptions();
        configure(snapshot);

        services.AddOptions<KeyManagementOptions>().Configure(configure);

        if (!string.IsNullOrWhiteSpace(snapshot.KeyringPath))
        {
            string path = snapshot.KeyringPath!;
            services.TryAddSingleton<IKeyringStore>(new FileKeyringStore(path));
        }

        return AddProviderCore(services);
    }

    /// <summary>
    /// Registers a singleton <see cref="IContentKeyProvider"/> using already-bound
    /// <see cref="KeyManagementOptions"/> — useful when the options are bound from
    /// <see cref="Microsoft.Extensions.Configuration.IConfiguration"/> elsewhere.
    /// </summary>
    /// <remarks>
    /// When using this overload the keyring store is NOT auto-registered (the options aren't
    /// readable at registration time). Register an <see cref="IKeyringStore"/> yourself if you want
    /// persistence — for example
    /// <c>services.AddSingleton&lt;IKeyringStore&gt;(new FileKeyringStore("keyring.bin"))</c>.
    /// </remarks>
    public static IServiceCollection AddPostQuantumKeyManagement(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<KeyManagementOptions>();
        return AddProviderCore(services);
    }

    private static IServiceCollection AddProviderCore(IServiceCollection services)
    {
        services.TryAddSingleton<IContentKeyProvider>(static sp =>
        {
            KeyManagementOptions options = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
            if (string.IsNullOrEmpty(options.Passphrase))
            {
                throw new InvalidOperationException(
                    "KeyManagementOptions.Passphrase is required. Set it from a secret store or environment variable.");
            }

            IKeyringStore? store = sp.GetService<IKeyringStore>();
            LocalKekOptions kekOptions = options.ToKekOptions();

            if (store is null)
            {
                return LocalContentKeyProvider.Create(options.Passphrase, kekOptions);
            }

            // Block on the store at startup. ASP.NET hosts call this on the startup thread, so a
            // single read is acceptable; later background work can use the async API directly.
            string? token = store.LoadAsync().AsTask().GetAwaiter().GetResult();
            if (token is null)
            {
                LocalContentKeyProvider fresh = LocalContentKeyProvider.Create(options.Passphrase, kekOptions);
                store.SaveAsync(fresh.ExportMetadata().Encode()).AsTask().GetAwaiter().GetResult();
                return fresh;
            }

            LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
            string passphrase = options.Passphrase!;
            PassphraseResolver resolver = _ => passphrase.AsSpan();
            return LocalContentKeyProvider.Import(metadata, resolver);
        });

        return services;
    }
}

/// <summary>
/// <see cref="IHealthChecksBuilder"/> extension that registers <see cref="KeyManagementHealthCheck"/>.
/// </summary>
public static class KeyManagementHealthChecksBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="KeyManagementHealthCheck"/> against the host's
    /// <see cref="IContentKeyProvider"/> singleton.
    /// </summary>
    public static IHealthChecksBuilder AddPostQuantumKeyManagement(
        this IHealthChecksBuilder builder,
        string name = "post-quantum-key-management",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddCheck<KeyManagementHealthCheck>(name, failureStatus, tags ?? []);
    }
}
