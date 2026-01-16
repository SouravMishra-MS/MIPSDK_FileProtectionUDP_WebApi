using Microsoft.InformationProtection;
using Microsoft.Extensions.Options;
using MIPSDK_FileOperations_API.Models;

namespace MIPSDK_FileOperations_API.Services
{
    internal class AuthDelegateImpl : IAuthDelegate
    {
        private readonly AuthService _authService;
        private readonly ILogger<AuthDelegateImpl> _logger;
        private readonly string[] _allowedScopes;

        public AuthDelegateImpl(
            AuthService authService,
            ILogger<AuthDelegateImpl> logger,
            IOptions<MipSdkOptions>? mipOptions = null)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _allowedScopes = !string.IsNullOrWhiteSpace(mipOptions?.Value?.Scopes)
                ? mipOptions!.Value.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : Array.Empty<string>();
        }

        // Called by the MIP SDK when it needs a token
        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            _logger.LogInformation(
                "MIP SDK requesting token - Identity: {Identity}, Authority: {Authority}, Resource: {Resource}",
                identity?.Name ?? "N/A",
                authority,
                resource);

            // Same pattern as your console app:
            // Turn a resource like "https://api.aadrm.com" into "https://api.aadrm.com/.default"
            var requestedScope = resource[resource.Length - 1].Equals('/')
                ? $"{resource}.default"
                : $"{resource}/.default";

            if (_allowedScopes.Length > 0 && !_allowedScopes.Contains(requestedScope, StringComparer.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "Requested scope {RequestedScope} is not in configured MipSdk:Scopes. The token request will likely fail. Configured scopes: {ConfiguredScopes}",
                    requestedScope,
                    string.Join(", ", _allowedScopes));
            }

            // For client-credentials, MSAL tokens are minted per-resource.
            // Always request a token for the exact resource the MIP SDK requested.
            string[] scopes = new[] { requestedScope };

            _logger.LogInformation("Requesting token with scopes: {Scopes}", string.Join(", ", scopes));

            // Perform Client Credentials flow for ServicePrincipal Authentication
            var token = _authService
                .AcquireClientCredentialsTokenAsync(scopes)
                .GetAwaiter()
                .GetResult();

            _logger.LogInformation("Successfully acquired access token for MIP SDK");
            return token;
        }
    }
}