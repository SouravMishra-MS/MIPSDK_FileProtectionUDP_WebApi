using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using MIPSDK_FileOperations_API.Models;

namespace MIPSDK_FileOperations_API.Services
{
    public class AuthService
    {
        private readonly AzureAdOptions _azureAd;
        private readonly MipSdkOptions _mipOptions;
        private readonly IConfidentialClientApplication _cca;
        private readonly string[] _defaultScopes;

        public AuthService(
            IOptions<AzureAdOptions> azureAdOptions,
            IOptions<MipSdkOptions> mipOptions)
        {
            _azureAd = azureAdOptions.Value;
            _mipOptions = mipOptions.Value;

            var authority = $"{_azureAd.Instance.TrimEnd('/')}/{_azureAd.TenantId}";

            _cca = ConfidentialClientApplicationBuilder
                .Create(_azureAd.ClientId)
                .WithClientSecret(_azureAd.ClientSecret)
                .WithAuthority(authority)
                .Build();

            _defaultScopes = !string.IsNullOrWhiteSpace(_mipOptions.Scopes)
                ? _mipOptions.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : new[] { $"{_azureAd.ClientId}/.default" };
        }

        // OBO equivalent of SignInUserAndGetAccessTokenUsingMSAL
        public async Task<string> AcquireOnBehalfOfTokenAsync(string userAssertion, string[]? scopes = null)
        {
            if (string.IsNullOrWhiteSpace(userAssertion))
                throw new ArgumentException("User assertion (incoming access token) is required.", nameof(userAssertion));

            var assertion = new UserAssertion(userAssertion);
            var effectiveScopes = (scopes is { Length: > 0 }) ? scopes : _defaultScopes;

            var result = await _cca
                .AcquireTokenOnBehalfOf(effectiveScopes, assertion)
                .ExecuteAsync()
                .ConfigureAwait(false);

            return result.AccessToken;
        }
    }
}
