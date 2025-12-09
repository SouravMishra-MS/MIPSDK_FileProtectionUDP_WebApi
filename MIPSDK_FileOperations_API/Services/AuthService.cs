using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using MIPSDK_FileOperations_API.Models;
using System.IdentityModel.Tokens.Jwt;

namespace MIPSDK_FileOperations_API.Services
{
    public class AuthService
    {
        private readonly AzureAdOptions _azureAd;
        private readonly MipSdkOptions _mipOptions;
        private readonly IConfidentialClientApplication _cca;
        private readonly string[] _defaultScopes;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            IOptions<AzureAdOptions> azureAdOptions,
            IOptions<MipSdkOptions> mipOptions,
            ILogger<AuthService> logger)
        {
            _azureAd = azureAdOptions.Value;
            _mipOptions = mipOptions.Value;
            _logger = logger;

            var authority = $"{_azureAd.Instance.TrimEnd('/')}/{_azureAd.TenantId}";

            _cca = ConfidentialClientApplicationBuilder
                .Create(_azureAd.ClientId)
                .WithClientSecret(_azureAd.ClientSecret)
                .WithAuthority(authority)
                .Build();

            _defaultScopes = !string.IsNullOrWhiteSpace(_mipOptions.Scopes)
                ? _mipOptions.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                : new[] { $"{_azureAd.ClientId}/.default" };

            _logger.LogInformation("AuthService initialized with default scopes: {Scopes}", string.Join(", ", _defaultScopes));
        }

        // OBO equivalent of SignInUserAndGetAccessTokenUsingMSAL
        public async Task<string> AcquireOnBehalfOfTokenAsync(string userAssertion, string[]? scopes = null)
        {
            if (string.IsNullOrWhiteSpace(userAssertion))
                throw new ArgumentException("User assertion (incoming access token) is required.", nameof(userAssertion));

            var assertion = new UserAssertion(userAssertion);
            var effectiveScopes = (scopes is { Length: > 0 }) ? scopes : _defaultScopes;

            _logger.LogInformation("Acquiring OBO token for scopes: {Scopes}", string.Join(", ", effectiveScopes));

            var result = await _cca
                .AcquireTokenOnBehalfOf(effectiveScopes, assertion)
                .ExecuteAsync()
                .ConfigureAwait(false);

            // Log token details
            LogTokenDetails(result.AccessToken, "OBO Token");

            return result.AccessToken;
        }

        private void LogTokenDetails(string accessToken, string tokenType)
        {
            try
            {
                var jwtHandler = new JwtSecurityTokenHandler();
                if (jwtHandler.CanReadToken(accessToken))
                {
                    var jwtToken = jwtHandler.ReadJwtToken(accessToken);

                    _logger.LogInformation(
                        "{TokenType} Details - Subject: {Subject}, Audience: {Audience}, Scopes: {Scp}, Expires: {Exp}",
                        tokenType,
                        jwtToken.Subject,
                        string.Join(", ", jwtToken.Audiences),
                        jwtToken.Claims.FirstOrDefault(c => c.Type == "scp")?.Value ?? "N/A",
                        jwtToken.ValidTo.ToString("O"));

                    _logger.LogDebug("{TokenType} (truncated): {Token}...", tokenType, accessToken.Substring(0, Math.Min(50, accessToken.Length)));
                }
                else
                {
                    _logger.LogWarning("Unable to parse {TokenType} as JWT", tokenType);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging token details for {TokenType}", tokenType);
            }
        }
    }
}
