using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.InformationProtection;
using MIPSDK_FileOperations_API.Models;

namespace MIPSDK_FileOperations_API.Services
{
    internal class AuthDelegateImpl : IAuthDelegate
    {
        private readonly AuthService _authService;
        private readonly string _userAssertionToken;
        private readonly ILogger<AuthDelegateImpl> _logger;

        // userAssertionToken = incoming API access token (from Authorization: Bearer ...)
        public AuthDelegateImpl(AuthService authService, string userAssertionToken, ILogger<AuthDelegateImpl> logger)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _userAssertionToken = userAssertionToken ?? throw new ArgumentNullException(nameof(userAssertionToken));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
            string[] scopes = new string[]
            {
                resource[resource.Length - 1].Equals('/')
                    ? $"{resource}.default"
                    : $"{resource}/.default"
            };

            _logger.LogInformation("Requesting token with scopes: {Scopes}", string.Join(", ", scopes));

            // For the web API, instead of interactive sign-in we do OBO:
            // use the incoming API token (_userAssertionToken) as the user assertion.
            var token = _authService
                .AcquireOnBehalfOfTokenAsync(_userAssertionToken, scopes)
                .GetAwaiter()
                .GetResult();

            _logger.LogInformation("Successfully acquired OBO token for MIP SDK");
            return token;
        }
    }
}