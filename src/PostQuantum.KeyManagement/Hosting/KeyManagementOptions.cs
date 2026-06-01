using PostQuantum.KeyManagement.Local;

namespace PostQuantum.KeyManagement;

/// <summary>
/// Configuration for the local key-management provider when registered through
/// <c>AddPostQuantumKeyManagement</c> on an <see cref="Microsoft.Extensions.DependencyInjection.IServiceCollection"/>.
/// </summary>
/// <remarks>
/// <para>
/// Bind from configuration (with the passphrase coming from a secret store / env var, never the
/// repo's appsettings.json):
/// </para>
/// <code>
/// builder.Services.AddPostQuantumKeyManagement(o =&gt;
/// {
///     o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
///         ?? throw new InvalidOperationException("Missing passphrase");
///     o.WorkFactor = KekWorkFactor.Interactive;
///     o.KeyringPath = "keyring.bin";   // optional — persists the multi-KEK ring via FileKeyringStore
/// });
/// </code>
/// </remarks>
public sealed class KeyManagementOptions
{
    /// <summary>
    /// The passphrase used to derive the local KEK. Must be supplied — set it from a secret store
    /// or environment variable, never from a checked-in configuration file.
    /// </summary>
    public string? Passphrase { get; set; }

    /// <summary>
    /// Argon2id work factor used when deriving the local KEK. Defaults to
    /// <see cref="KekWorkFactor.Interactive"/> — RFC 9106 §4 "second recommended" (64 MiB, 3, 4).
    /// </summary>
    public KekWorkFactor WorkFactor { get; set; } = KekWorkFactor.Interactive;

    /// <summary>
    /// Optional path to a keyring file. When set, the host registers a <see cref="FileKeyringStore"/>
    /// at that path and the provider is rebuilt from it on startup (or created and saved on first run).
    /// When null or empty, the provider is created fresh on each startup with a random salt — fine
    /// for ephemeral / test deployments, never for production data.
    /// </summary>
    public string? KeyringPath { get; set; }

    /// <summary>
    /// Map <see cref="WorkFactor"/> onto a <see cref="LocalKekOptions"/> instance.
    /// </summary>
    internal LocalKekOptions ToKekOptions() => WorkFactor switch
    {
        KekWorkFactor.LowMemory => LocalKekOptions.LowMemory,
        KekWorkFactor.Interactive => LocalKekOptions.Interactive,
        KekWorkFactor.Moderate => LocalKekOptions.Moderate,
        KekWorkFactor.Sensitive => LocalKekOptions.Sensitive,
        _ => LocalKekOptions.Interactive,
    };
}

/// <summary>
/// Named work-factor preset selectable from configuration. Maps onto the static
/// <see cref="LocalKekOptions"/> presets.
/// </summary>
public enum KekWorkFactor
{
    /// <summary>OWASP minimum for constrained hosts: 19 MiB / 2 iterations / parallelism 1.</summary>
    LowMemory,

    /// <summary>RFC 9106 §4 "second recommended": 64 MiB / 3 / 4. Default.</summary>
    Interactive,

    /// <summary>256 MiB / 4 / 4. For background and admin operations.</summary>
    Moderate,

    /// <summary>RFC 9106 §4 "first recommended": 2 GiB / 1 / 4. For long-lived master KEKs.</summary>
    Sensitive,
}
