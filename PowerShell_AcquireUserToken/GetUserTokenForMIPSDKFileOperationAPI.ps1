param(
  [Parameter(Mandatory)] [string] $TenantId,       # Directory (tenant) ID
  [Parameter(Mandatory)] [string] $ClientId,       # Client app registration (public client)
  [Parameter(Mandatory)] [string] $ApiAppId,       # Web API app registration (exposes user_impersonation)
  [string] $RedirectUri = "http://localhost:8400/" # Must be configured in the app registration
)

# Scope for API (plus openid/profile for a nicer sign-in experience)
$Scope = "api://$ApiAppId/user_impersonation openid profile"
$AuthBase = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

########################################################################
# PKCE helpers
########################################################################

function New-CodeVerifier {
    # 32 bytes -> base64url -> 43+ chars, which is PKCE-compliant
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $b64 = [Convert]::ToBase64String($bytes)
    # base64url, remove padding
    $b64.Replace('+','-').Replace('/','_').TrimEnd('=')
}

function New-CodeChallenge {
    param(
        [Parameter(Mandatory)][string] $CodeVerifier
    )
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($CodeVerifier)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($bytes)
    $b64 = [Convert]::ToBase64String($hash)
    $b64.Replace('+','-').Replace('/','_').TrimEnd('=')
}

########################################################################
# Local HTTP listener for redirect_uri
########################################################################

function Start-AuthListener {
    param(
        [Parameter(Mandatory)][string] $Prefix  # e.g. "http://localhost:8400/"
    )

    if (-not $Prefix.EndsWith('/')) {
        $Prefix += '/'
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Prefix)
    $listener.Start()
    Write-Host "Listening for redirect on $Prefix ..." -ForegroundColor Cyan
    return $listener
}

function Wait-ForAuthCode {
    param(
        [Parameter(Mandatory)][System.Net.HttpListener] $Listener
    )

    $context = $Listener.GetContext() # blocks until first request
    $request = $context.Request
    $response = $context.Response

    $query = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)

    $error = $query["error"]
    $error_description = $query["error_description"]
    $code = $query["code"]
    $state = $query["state"]

    # Simple HTML response to show in the browser
    $html = @"
<html>
<head><title>Authentication complete</title></head>
<body>
  <h2>You can close this window.</h2>
</body>
</html>
"@
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()
    $response.Close()

    $Listener.Stop()

    if ($error) {
        throw "Authorization failed: $error - $error_description"
    }

    if (-not $code) {
        throw "Authorization code not found in redirect."
    }

    return $code
}

########################################################################
# 1) Build PKCE values and authorization URL
########################################################################

$codeVerifier = New-CodeVerifier
$codeChallenge = New-CodeChallenge -CodeVerifier $codeVerifier

$state = [Guid]::NewGuid().ToString("N")  # Basic CSRF protection

# URL-encode values
function UrlEncode([string] $value) {
    return [System.Uri]::EscapeDataString($value)
}

$authUrl = "$AuthBase/authorize" +
           "?client_id=$(UrlEncode $ClientId)" +
           "&response_type=code" +
           "&redirect_uri=$(UrlEncode $RedirectUri)" +
           "&response_mode=query" +
           "&scope=$(UrlEncode $Scope)" +
           "&code_challenge=$(UrlEncode $codeChallenge)" +
           "&code_challenge_method=S256" +
           "&state=$(UrlEncode $state)"

Write-Host "Opening browser for interactive sign-in..." -ForegroundColor Cyan

########################################################################
# 2) Start listener and launch browser
########################################################################

$listener = Start-AuthListener -Prefix $RedirectUri
Start-Process $authUrl | Out-Null

$authCode = Wait-ForAuthCode -Listener $listener
Write-Host "Received authorization code." -ForegroundColor Green

########################################################################
# 3) Exchange authorization code for access token (with PKCE)
########################################################################

Write-Host "Exchanging authorization code for access token..." -ForegroundColor Cyan

$tokenResponse = Invoke-RestMethod -Method POST -Uri "$AuthBase/token" `
  -ContentType "application/x-www-form-urlencoded" -Body @{
    grant_type    = "authorization_code"
    client_id     = $ClientId
    code          = $authCode
    redirect_uri  = $RedirectUri
    code_verifier = $codeVerifier
    scope         = $Scope
  }

$accessToken = $tokenResponse.access_token
if (-not $accessToken) {
    throw "Failed to acquire access token. Response: $($tokenResponse | ConvertTo-Json -Depth 5)"
}

########################################################################
# 4) Output and store
########################################################################

Write-Host ("Access Token (truncated): {0}..." -f $accessToken.Substring(0,40)) -ForegroundColor Green
$env:API_TEST_TOKEN = $accessToken
Write-Host "Stored token in `$env:API_TEST_TOKEN" -ForegroundColor Cyan
Write-Host "Use this token in MIPSDK_FileOperations_API.http by setting @token = $accessToken" -ForegroundColor Magenta
