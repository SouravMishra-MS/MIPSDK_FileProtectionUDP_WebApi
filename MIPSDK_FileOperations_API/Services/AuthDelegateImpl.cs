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

        // userAssertionToken = incoming API access token (from Authorization: Bearer ...)
        public AuthDelegateImpl(AuthService authService, string userAssertionToken)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _userAssertionToken = userAssertionToken ?? throw new ArgumentNullException(nameof(userAssertionToken));
        }

        // Called by the MIP SDK when it needs a token
        public string AcquireToken(Identity identity, string authority, string resource, string claims)
        {
            // Same pattern as your console app:
            // Turn a resource like "https://api.aadrm.com" into "https://api.aadrm.com/.default"
            string[] scopes = new string[]
            {
                resource[resource.Length - 1].Equals('/')
                    ? $"{resource}.default"
                    : $"{resource}/.default"
            };

            // For the web API, instead of interactive sign-in we do OBO:
            // use the incoming API token (_userAssertionToken) as the user assertion.
            return _authService
                .AcquireOnBehalfOfTokenAsync(_userAssertionToken, scopes)
                .GetAwaiter()
                .GetResult();
        }
    }
}
