# MIP SDK File Operations API

A secure ASP.NET Core 8 Web API for protecting files using the **Microsoft Information Protection (MIP) SDK**. This API implements the **OAuth 2.0 On-Behalf-Of (OBO) flow** to enable users to protect files with custom user-defined permissions (UDP) while maintaining proper authentication and authorization through Azure AD.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Authentication & Authorization](#authentication--authorization)
- [OAuth 2.0 On-Behalf-Of Flow](#oauth-20-on-behalf-of-flow)
- [API Endpoints](#api-endpoints)
- [Setup & Configuration](#setup--configuration)
- [Usage Examples](#usage-examples)
- [Project Structure](#project-structure)
- [Error Handling](#error-handling)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Support & Resources](#support--resources)

## Overview

The MIP SDK File Operations API provides secure file protection capabilities by integrating with Microsoft Information Protection SDK and Azure Active Directory. It allows authenticated users to upload files and apply custom permissions, ensuring that files are protected according to organizational security policies.

### Key Capabilities

- **File Protection**: Apply Microsoft Information Protection labels and permissions to files
- **User-Defined Permissions (UDP)**: Create custom permission sets for specific users
- **Owner Management**: Automatically include the caller as an owner (optional)
- **On-Behalf-Of Authentication**: Users delegate their permissions through the OAuth 2.0 OBO flow
- **Secure Token Handling**: Proper JWT validation and bearer token management
- **Large File Support**: Handles files up to 100 MB

## Features

- ? JWT/Bearer token authentication via Azure AD
- ? Microsoft Information Protection (MIP) SDK integration
- ? User-defined permissions with granular rights (View, Edit, Print, Export, Owner)
- ? RESTful API with multipart/form-data file uploads
- ? Health check endpoint for monitoring
- ? Comprehensive error handling and validation
- ? Async/await pattern for performance
- ? Automatic output folder creation and file management

## Architecture

```
???????????????????????????????????????????????????????????????
?                 Client Application                          ?
?       (Desktop, Web, or Mobile Client)                      ?
???????????????????????????????????????????????????????????????
                         ?
                    (1) Authenticate
                 (2) Get Access Token
                         ?
                         ?
???????????????????????????????????????????????????????????????
?                    Azure AD                                 ?
?              (Identity Provider)                            ?
???????????????????????????????????????????????????????????????
                         ?
                    (3) Return Token
                         ?
                         ?
???????????????????????????????????????????????????????????????
?          MIP SDK File Operations API                        ?
?                                                             ?
?  ???????????????????????????????????????????????????????   ?
?  ?  FileProtectionController                           ?   ?
?  ?  • POST /api/fileprotection/protect                 ?   ?
?  ?  • Authorization: Bearer <token>                    ?   ?
?  ???????????????????????????????????????????????????????   ?
?                     ?                                       ?
?                     ?                                       ?
?  ???????????????????????????????????????????????????????   ?
?  ?  FileProtectionService                              ?   ?
?  ?  • Process file protection request                  ?   ?
?  ?  • Orchestrate MIP SDK operations                   ?   ?
?  ???????????????????????????????????????????????????????   ?
?                     ?                                       ?
?                     ?                                       ?
?  ???????????????????????????????????????????????????????   ?
?  ?  AuthService (OBO Flow Implementation)              ?   ?
?  ?  • Exchange user token for service token            ?   ?
?  ?  • Call AcquireTokenOnBehalfOf                       ?   ?
?  ???????????????????????????????????????????????????????   ?
?                     ?                                       ?
?                     ?                                       ?
?  ???????????????????????????????????????????????????????   ?
?  ?  MIP SDK                                            ?   ?
?  ?  • Create protection handlers                       ?   ?
?  ?  • Apply user-defined permissions                   ?   ?
?  ?  • Protect files with encryption                    ?   ?
?  ???????????????????????????????????????????????????????   ?
?                                                             ?
???????????????????????????????????????????????????????????????
                     ?
                     ?
        ???????????????????????????????
        ?  Protected File Output      ?
        ?  (Server-side storage)      ?
        ???????????????????????????????
```

## Authentication & Authorization

### Azure AD Configuration

The API requires the following Azure AD settings in `appsettings.json`:

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "<your-tenant-id>",
    "ClientId": "<your-client-id>",
    "ClientSecret": "<your-client-secret>",
    "Audience": "api://<your-client-id>",
    "Scopes": "api://<your-client-id>/.default"
  }
}
```

### JWT Token Validation

All protected endpoints validate:
- Bearer token presence and format
- Token signature and expiration
- Token audience matches the configured audience
- User claims (subject, UPN)

### Authorization

The API uses role-based authorization via `[Authorize]` attributes. All file protection endpoints require a valid JWT token.

## OAuth 2.0 On-Behalf-Of Flow

The OBO flow enables the API to:
1. Receive an access token from the client (delegated by the user)
2. Exchange this token for a new token with MIP SDK scopes
3. Use the new token to interact with MIP services on behalf of the user

### Flow Sequence

```
Client              API                 Azure AD           MIP Service
  ?                 ?                     ?                   ?
  ?? User logs in ??????????????????????? ?                   ?
  ?                                       ?                   ?
  ? ???? Returns Access Token ?????????????                   ?
  ?                                       ?                   ?
  ?? POST file + Bearer token ???????????? ?                   ?
  ?                                       ?                   ?
  ?                  ?? Extract Token     ?                   ?
  ?                  ?                     ?                   ?
  ?                  ?? OBO Exchange ??????????????????????? ?
  ?                  ?  (AcquireTokenOnBehalfOf)             ?
  ?                  ?                     ?                   ?
  ?                  ? ?? MIP Token ????????                   ?
  ?                  ?                     ?                   ?
  ?                  ?? Auth Delegate ?????????????????????? ?
  ?                  ?? Load Profile ???????????????????????? ?
  ?                  ?? Create Handler ??????????????????? ?
  ?                  ?? Set Protection ??????????????????? ?
  ?                  ?                                     ?
  ? ?? Protected File Info ????                           ?
  ?                  ?                     ?                   ?
```

### Implementation Details

The `AuthService` class implements the OBO flow:

```csharp
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
```

**Key Points:**
- `userAssertion`: The incoming access token from the client
- `effectiveScopes`: MIP SDK scopes (typically `https://api.azurerms.com/user_impersonation`)
- The new token is passed to MIP SDK authentication delegates
- Token is obtained using the API's own credentials (Client ID + Secret)

## API Endpoints

### 1. Health Check

**Endpoint:** `GET /api/healthcheck/status`

**Description:** Verify that the API is running and healthy.

**Authentication:** Not required

**Response (200 OK):**

```json
{
  "status": "healthy",
  "timestamp": "2025-12-07T10:30:00Z",
  "service": "MIPSDK_FileOperations_API"
}
```

---

### 2. Protect File

**Endpoint:** `POST /api/fileprotection/protect`

**Description:** Upload a file and apply protection with user-defined permissions.

**Authentication:** Required (Bearer token)

**Request Headers:**

```
Authorization: Bearer <JWT_ACCESS_TOKEN>
Content-Type: multipart/form-data
```

**Request Body:**
- `file` (IFormFile): The document to protect (required)
- `protectionDefinition` (JSON string): Protection configuration (required)

**Protection Definition Schema:**

```json
{
  "userPermissions": [
    {
      "email": "user@example.com",
      "rights": ["VIEW"]
    },
    {
      "email": "editor@example.com",
      "rights": ["EDIT", "PRINT"]
    }
  ],
  "includeCallerAsOwner": true,
  "outputFileName": "protected_document.pdf",
  "outputFolderPath": "C:\\ProtectedFiles"
}
```

**User Permissions Details:**
- `email` (string): User's email address
- `rights` (string[]): Array of permissions. Supported values:
  - `"VIEW"` or `"READ"` - View permissions
  - `"EDIT"` - Edit permissions
  - `"PRINT"` - Print permissions
  - `"EXPORT"` or `"SHARE"` - Export permissions
  - `"OWNER"` or `"FULLCONTROL"` - Owner permissions (case-insensitive)

**Protection Definition Properties:**
- `userPermissions` (array): List of users and their rights
- `includeCallerAsOwner` (boolean): If `true`, the API caller is automatically granted Owner rights
- `outputFileName` (string, optional): Custom output filename (auto-generated if omitted)
- `outputFolderPath` (string, required): Server-side folder to store the protected file

**Response (200 OK):**

```json
{
  "outputFileName": "protected_document.pdf",
  "outputFolderPath": "C:\\ProtectedFiles",
  "fullPath": "C:\\ProtectedFiles\\protected_document.pdf",
  "sizeBytes": 15234,
  "createdUtc": "2025-12-07T10:30:00Z",
  "modifiedUtc": "2025-12-07T10:30:05Z",
  "userPermissions": [
    {
      "email": "user@example.com",
      "rights": ["VIEW"]
    },
    {
      "email": "editor@example.com",
      "rights": ["EDIT", "PRINT"]
    }
  ],
  "includeCallerAsOwner": true
}
```

**Error Responses:**

| Status | Error | Reason |
|--------|-------|--------|
| 400 | File is required | No file in request |
| 400 | protectionDefinition (JSON) is required | Missing protection definition |
| 400 | Invalid protectionDefinition JSON: ... | Malformed JSON |
| 400 | OutputFolderPath is required in protectionDefinition | Missing output folder |
| 401 | Authorization header with Bearer token is required | No Bearer token provided |
| 401 | Unauthorized | Invalid or expired token |
| 500 | Internal server error | MIP SDK or service error |

**Request Size Limit:** 100 MB

---

## Setup & Configuration

### Prerequisites

- .NET 8 SDK or runtime
- Azure AD tenant with registered application
- MIP SDK installed and licensed
- Windows environment (MIP SDK requirement)

### Step 1: Register Azure AD Application

1. Go to **Azure Portal** ? **Azure AD** ? **App registrations**
2. Click **New registration**
3. Name: `MIPSDK-FileOperations-API`
4. Supported account types: "Accounts in this organizational directory only"
5. Redirect URI: `https://localhost:7161` (for development)

### Step 2: Configure API Permissions

1. In the app registration, go to **API permissions**
2. Click **Add a permission** ? **APIs my organization uses**
3. Search for and add:
   - **Microsoft Information Protection Sync Service**
     - Permission: `user_impersonation`
   - **Microsoft Graph** (optional for additional features)

### Step 3: Create Client Secret

1. Go to **Certificates & secrets** ? **New client secret**
2. Description: `API secret`
3. Expiration: 24 months (or as per policy)
4. Copy the secret value (you won't see it again)

### Step 4: Configure appsettings.json

Update `appsettings.json` with your Azure AD values:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "<your-tenant-id>",
    "ClientId": "<your-app-client-id>",
    "ClientSecret": "<your-app-secret>",
    "Audience": "api://<your-app-client-id>",
    "Scopes": "api://<your-app-client-id>/.default"
  },
  "MipSdk": {
    "AppId": "<your-app-client-id>",
    "AppName": "MIPSDK_FileOperations_API",
    "AppVersion": "1.0",
    "EnableEml": "false",
    "CachePath": "c:\\mip-cache",
    "Scopes": "https://api.azurerms.com/user_impersonation"
  },
  "AllowedHosts": "*"
}
```

### Step 5: Configure MIP SDK Cache Path

Ensure the cache path directory exists and is writable:

```powershell
mkdir c:\mip-cache
icacls c:\mip-cache /grant $env:USERNAME:F /t
```

### Step 6: Run the API

```bash
dotnet restore
dotnet build
dotnet run
```

The API will start on `https://localhost:7161` (HTTPS by default).

---

## Usage Examples

### Example 1: Health Check with cURL

```bash
curl -k https://localhost:7161/api/healthcheck/status
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-12-07T10:30:00Z",
  "service": "MIPSDK_FileOperations_API"
}
```

### Example 2: Protect File with cURL

```bash
curl -k -X POST \
  https://localhost:7161/api/fileprotection/protect \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -F "file=@C:\path\to\document.pdf" \
  -F 'protectionDefinition={
    "userPermissions": [
      {
        "email": "viewer@example.com",
        "rights": ["VIEW"]
      }
    ],
    "includeCallerAsOwner": true,
    "outputFileName": "protected_document.pdf",
    "outputFolderPath": "C:\\ProtectedFiles"
  }'
```

### Example 3: Using REST Client Extension

See `MIPSDK_FileOperations_API.http` for pre-configured requests:

```http
### Health Check
GET https://localhost:7161/api/healthcheck/status
Accept: application/json

### Protect File
POST https://localhost:7161/api/fileprotection/protect
Authorization: Bearer {{BearerToken}}
Content-Type: multipart/form-data; boundary=----FormBoundary

------FormBoundary
Content-Disposition: form-data; name="file"; filename="document.pdf"
Content-Type: application/pdf

< C:\path\to\document.pdf
------FormBoundary
Content-Disposition: form-data; name="protectionDefinition"
Content-Type: application/json

{
  "userPermissions": [
    {
      "email": "viewer@example.com",
      "rights": ["VIEW"]
    }
  ],
  "includeCallerAsOwner": true,
  "outputFileName": "protected_document.pdf",
  "outputFolderPath": "C:\\ProtectedFiles"
}
------FormBoundary--
```

### Example 4: C# Client Code

```csharp
using System.Net.Http.Headers;
using System.Text.Json;

public class FileProtectionClient
{
    public async Task ProtectFileAsync(string token, string filePath, string outputPath)
    {
        using var client = new HttpClient();

        // Prepare file content
        var fileStream = File.OpenRead(filePath);
        var fileContent = new StreamContent(fileStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");

        // Prepare protection definition
        var protectionDef = new
        {
            userPermissions = new[]
            {
                new { email = "user@example.com", rights = new[] { "VIEW" } }
            },
            includeCallerAsOwner = true,
            outputFileName = Path.GetFileName(filePath),
            outputFolderPath = outputPath
        };

        // Prepare multipart form
        var content = new MultipartFormDataContent();
        content.Add(fileContent, "file", Path.GetFileName(filePath));
        content.Add(
            new StringContent(JsonSerializer.Serialize(protectionDef)),
            "protectionDefinition"
        );

        // Make the request
        client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
        
        var response = await client.PostAsync(
            "https://localhost:7161/api/fileprotection/protect",
            content
        );

        // Handle response
        if (response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Success: {json}");
        }
        else
        {
            var error = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Error: {error}");
        }
    }
}
```

---

## Project Structure

```
MIPSDK_FileOperations_API/
??? Controllers/
?   ??? FileProtectionController.cs       # File protection endpoints
?   ??? HealthCheckController.cs          # Health check endpoint
??? Services/
?   ??? AuthService.cs                    # OAuth 2.0 OBO implementation
?   ??? FileProtectionService.cs          # MIP SDK orchestration
?   ??? AuthDelegateImpl.cs               # Auth delegate for MIP SDK
?   ??? ConsentDelegateImpl.cs            # Consent delegate for MIP SDK
??? Models/
?   ??? AzureAdOptions.cs                # Azure AD configuration
?   ??? MipSdkOptions.cs                 # MIP SDK configuration
?   ??? ProtectionFileRequestDto.cs      # File protection request
?   ??? ProtectionFileResponseDto.cs     # File protection response
?   ??? UserPermissionDto.cs             # User permission definition
??? Program.cs                            # Application startup
??? appsettings.json                     # Configuration file
??? appsettings.Development.json         # Development-specific settings
??? MIPSDK_FileOperations_API.http       # API test requests (REST Client)
??? MIPSDK_FileOperations_API.csproj     # Project file
??? README.md                            # This file
```

### Key Classes

| Class | Purpose |
|-------|---------|
| `FileProtectionController` | Handles HTTP requests for file protection |
| `FileProtectionService` | Orchestrates MIP SDK operations |
| `AuthService` | Implements OAuth 2.0 OBO flow for token exchange |
| `AuthDelegateImpl` | Provides authentication to MIP SDK |
| `ConsentDelegateImpl` | Handles user consent prompts for MIP SDK |
| `ProtectionFileRequestDto` | Request model for file protection |
| `ProtectionFileResponseDto` | Response model with protected file metadata |
| `UserPermissionDto` | Individual user permission definition |

---

## Error Handling

The API implements comprehensive error handling at multiple levels:

### Validation Errors (400 Bad Request)
- Missing file in request
- Invalid or missing protection definition
- Malformed JSON in protection definition
- Missing required configuration values
- Invalid user permissions

### Authentication Errors (401 Unauthorized)
- Missing Bearer token
- Invalid token signature
- Expired token
- Token audience mismatch
- Insufficient token permissions

### Authorization Errors (403 Forbidden)
- User does not have permission to perform the operation

### Server Errors (500 Internal Server Error)
- MIP SDK initialization failure
- File I/O errors
- Permission application failures
- Azure AD token exchange errors
- Unexpected exceptions

### Error Response Format

```json
{
  "type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "traceId": "0HN1GKDRB4G2V:00000001",
  "errors": {
    "file": ["The file field is required."]
  }
}
```

---

## Troubleshooting

### Issue: "MIP SDK not initialized"

**Cause:** MIP SDK has not been properly initialized or configured.

**Solution:**
- Ensure MIP SDK is properly installed on the system
- Verify cache path exists and is writable: `c:\mip-cache`
- Check Windows event logs for MIP initialization errors
- Ensure you have necessary MIP licenses

### Issue: "Invalid token / Unauthorized (401)"

**Cause:** Token is invalid, expired, or has insufficient permissions.

**Solution:**
- Verify token is not expired (check token expiration time)
- Ensure token was issued by your Azure AD tenant
- Verify token audience matches the configured audience in `appsettings.json`
- Check that Bearer token is properly formatted: `Bearer <token>`
- Verify the token has delegated permissions

### Issue: "Access Denied (403) when applying protection"

**Cause:** User email addresses don't exist or API lacks permissions.

**Solution:**
- Verify all user email addresses in protection definition exist in Azure AD
- Ensure API has sufficient MIP SDK permissions in Azure AD
- Check that the tenant has MIP enabled
- Verify API credentials have appropriate scopes

### Issue: "OutputFolderPath does not exist (400)"

**Cause:** Specified output folder path is missing or inaccessible.

**Solution:**
- Ensure the folder path exists on the server
- Verify the API process has read/write permissions to the folder
- Use an absolute path (e.g., `C:\ProtectedFiles`)
- Create the folder manually if needed: `mkdir C:\ProtectedFiles`

### Issue: "File Size Limit Exceeded (413)"

**Cause:** Uploaded file exceeds the 100 MB limit.

**Solution:**
- Current limit is 100 MB (configurable in `FileProtectionController`)
- To increase limit, modify the `[RequestSizeLimit(100_000_000)]` attribute
- Consider increasing Kestrel max request body size in `Program.cs`

```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 500_000_000; // 500 MB
});
```

### Issue: "OBO flow failure - Cannot exchange token"

**Cause:** Azure AD OBO flow configuration is incorrect.

**Solution:**
- Verify `ClientId` and `ClientSecret` in `appsettings.json`
- Ensure API is registered in Azure AD with correct redirect URIs
- Check that `user_impersonation` permission is granted for MIP service
- Verify admin has consented to API permissions

### Enable Debug Logging

Add detailed logging in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Information",
      "Microsoft.Identity": "Debug",
      "MIPSDK_FileOperations_API": "Debug"
    }
  }
}
```

Then run with:

```bash
dotnet run --configuration Debug
```

---

## Security Considerations

1. **Token Management**
   - Tokens are short-lived; implement refresh token handling in clients
   - Never log or expose tokens in error messages
   - Use HTTPS only for token transmission

2. **API Security**
   - Always use HTTPS in production
   - Implement rate limiting to prevent abuse
   - Use CORS policies to restrict cross-origin requests
   - Enable authentication on all protected endpoints

3. **Secret Management**
   - Store client secrets securely in Azure Key Vault (not in source code)
   - Rotate secrets regularly (recommended: every 3-6 months)
   - Use Managed Identity for Azure deployments when possible

4. **Input Validation**
   - All inputs are validated before processing
   - File uploads are scanned for malware (optional)
   - Email addresses are validated before adding permissions

5. **Output Folder Security**
   - Restrict access to output folders using NTFS permissions
   - Use strong file naming conventions to prevent collisions
   - Implement automatic cleanup of old protected files

6. **Audit & Logging**
   - Log all file protection operations for compliance
   - Include user identity, timestamp, and operation details
   - Retain logs according to regulatory requirements

7. **Compliance**
   - Ensure compliance with data protection regulations (GDPR, HIPAA, etc.)
   - Use encryption in transit (HTTPS) and at rest (MIP encryption)
   - Document data retention and deletion policies

---

## Support & Resources

- [Microsoft Information Protection SDK Documentation](https://learn.microsoft.com/en-us/information-protection/develop/)
- [Azure AD Authentication Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [OAuth 2.0 On-Behalf-Of Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [MSAL.NET Documentation](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet)
- [MIP SDK File API](https://learn.microsoft.com/en-us/information-protection/develop/concept-apis-use-cases)
- [ASP.NET Core Security](https://learn.microsoft.com/en-us/aspnet/core/security/)

---

## License

[Add your license information here]

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Changelog

### Version 1.0.0
- Initial release
- File protection with user-defined permissions
- OAuth 2.0 OBO flow implementation
- Health check endpoint

---

## FAQ

**Q: Can I use this API without Azure AD?**  
A: No, the API requires Azure AD for authentication and the OBO flow.

**Q: What file formats are supported?**  
A: MIP SDK supports all file formats. Protection is format-agnostic.

**Q: Is there a file size limit?**  
A: Yes, the default limit is 100 MB. This can be configured in the `FileProtectionController`.

**Q: Can I store protected files in cloud storage (Azure Blob Storage)?**  
A: Yes, modify `FileProtectionService.cs` to use cloud storage instead of local paths.

**Q: How do I revoke permissions from a protected file?**  
A: MIP SDK does not support permission revocation. Users must re-protect files with new permissions.

---

*Last Updated: December 2025*  
*API Version: 1.0.0*  
*Target Framework: .NET 8*
