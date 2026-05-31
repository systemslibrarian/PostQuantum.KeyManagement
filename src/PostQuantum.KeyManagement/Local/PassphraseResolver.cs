namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// Supplies the passphrase for a given local KEK during keyring import. The library calls this once
/// per KEK in the imported <see cref="LocalKeyringMetadata"/>, identifying the KEK by its
/// <paramref name="keyId"/> so callers that rotated passphrases can return the matching secret.
/// </summary>
/// <param name="keyId">The identifier of the KEK whose passphrase is being requested.</param>
/// <returns>The passphrase used to derive that KEK.</returns>
public delegate ReadOnlySpan<char> PassphraseResolver(string keyId);
