using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.InformationProtection;
using Microsoft.InformationProtection.File;
using Microsoft.InformationProtection.Protection;
using MIPSDK_FileOperations_API.Models;

namespace MIPSDK_FileOperations_API.Services
{
    public interface IFileProtectionService
    {
        Task<ProtectionFileResponseDto> ProtectWithUserDefinedPermissionsAsync(
            Stream inputStream,
            string originalFileName,
            ProtectionFileRequestDto definition,
            ClaimsPrincipal user,
            CancellationToken cancellationToken);
    }

    public class FileProtectionService : IFileProtectionService
    {
        private readonly MipSdkOptions _mipOptions;
        private readonly AzureAdOptions _azureAdOptions;
        private readonly AuthService _authService;
        private readonly ILogger<FileProtectionService> _logger;
        private readonly ILoggerFactory _loggerFactory;
        private readonly string _defaultOwnerEmail;
        private static bool _mipInitialized;
        private static readonly object _initLock = new();

        public FileProtectionService(
            IOptions<MipSdkOptions> mipOptions,
            IOptions<AzureAdOptions> azureAdOptions,
            AuthService authService,
            ILogger<FileProtectionService> logger,
            ILoggerFactory loggerFactory)
        {
            _mipOptions = mipOptions.Value;
            _azureAdOptions = azureAdOptions.Value;
            _authService = authService;
            _logger = logger;
            _loggerFactory = loggerFactory;
            _defaultOwnerEmail = _mipOptions.DefaultOwnerEmail;
            EnsureMipInitialized();
        }

        private void EnsureMipInitialized()
        {
            if (_mipInitialized) return;

            lock (_initLock)
            {
                if (_mipInitialized) return;

                // Match console app behaviour: initialize File SDK
                MIP.Initialize(MipComponent.File);
                _mipInitialized = true;
                _logger.LogInformation("MIP SDK initialized");
            }
        }

        public async Task<ProtectionFileResponseDto> ProtectWithUserDefinedPermissionsAsync(
            Stream inputStream,
            string originalFileName,
            ProtectionFileRequestDto definition,
            ClaimsPrincipal user,
            CancellationToken cancellationToken)
        {
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable.", nameof(inputStream));

            if (string.IsNullOrWhiteSpace(definition.OutputFolderPath))
                throw new ArgumentException("OutputFolderPath is required in protectionDefinition.", nameof(definition));

            _logger.LogInformation("Starting file protection for: {FileName}", originalFileName);

            var outputFolder = definition.OutputFolderPath;
            Directory.CreateDirectory(outputFolder);

            var appInfo = new ApplicationInfo
            {
                ApplicationId = _mipOptions.AppId,
                ApplicationName = _mipOptions.AppName,
                ApplicationVersion = _mipOptions.AppVersion
            };

            var authDelegate = new AuthDelegateImpl(
                _authService,
                _loggerFactory.CreateLogger<AuthDelegateImpl>(),
                Options.Create(_mipOptions));

            var mipConfig = new MipConfiguration(
                appInfo,
                _mipOptions.CachePath,
                Microsoft.InformationProtection.LogLevel.Trace,
                false,
                CacheStorageType.OnDiskEncrypted);

            var mipContext = MIP.CreateMipContext(mipConfig);

            var fileProfileSettings = new FileProfileSettings(
                mipContext,
                CacheStorageType.OnDiskEncrypted,
                new ConsentDelegateImpl());

            var fileProfile = await MIP.LoadFileProfileAsync(fileProfileSettings)
                                       .ConfigureAwait(false);

            var protectionProfileSettings = new ProtectionProfileSettings(
                mipContext,
                CacheStorageType.InMemory,
                new ConsentDelegateImpl());

            var protectionProfile = await MIP.LoadProtectionProfileAsync(protectionProfileSettings)
                                             .ConfigureAwait(false);

            // ============================================================================
            // Service Principal Identity for file engine
            // ============================================================================
            var servicePrincipalIdentity = $"{_mipOptions.AppId}@{_azureAdOptions.TenantId}";
            var identityId = $"{servicePrincipalIdentity}-webapi";

            _logger.LogInformation("Creating file engine for Service Principal identity: {IdentityId}", identityId);

            var fileEngineSettings = new FileEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Identity(servicePrincipalIdentity)
            };

            var fileEngine = await fileProfile.AddEngineAsync(fileEngineSettings)
                                              .ConfigureAwait(false);

            var protectionEngineSettings = new ProtectionEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Identity(servicePrincipalIdentity)
            };

            var protectionEngine = await protectionProfile.AddEngineAsync(protectionEngineSettings)
                                       .ConfigureAwait(false);

            // Build UDP (UserRights) from definition
            var userRightsList = new List<UserRights>();

            if (definition.UserPermissions != null)
            {
                foreach (var perm in definition.UserPermissions)
                {
                    if (string.IsNullOrWhiteSpace(perm.Email) || perm.Rights == null || perm.Rights.Count == 0)
                    {
                        _logger.LogWarning(
                            "Skipping permission - no valid rights for {Email}",
                            perm.Email);
                        continue;
                    }

                    var rights = MapRights(perm.Rights);
                    if (rights.Count == 0) continue;

                    userRightsList.Add(new UserRights(new List<string> { perm.Email }, rights));
                    _logger.LogInformation(
                        "✅ PROTECTION SET: Email={Email}, Rights={RightsList}",
                        perm.Email,
                        string.Join(",", rights));
                }
            }

            // Always add default owner with full control
            userRightsList.Add(new UserRights(
                new List<string> { _defaultOwnerEmail },
                new List<string> { Rights.Owner }));
            _logger.LogInformation("✅ OWNER SET: Email={Email}, Rights=OWNER", _defaultOwnerEmail);

            if (userRightsList.Count == 0)
                throw new InvalidOperationException("No valid user permissions were provided.");

            _logger.LogInformation("Total permissions: {Count}", userRightsList.Count);

            var tempInputPath = Path.GetTempFileName();
            var tempOutputPath = Path.GetTempFileName();

            try
            {
                await using (var fs = File.Open(tempInputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await inputStream.CopyToAsync(fs, cancellationToken).ConfigureAwait(false);
                }

                _logger.LogInformation("Created handler for temporary file");

                var handler = await fileEngine.CreateFileHandlerAsync(
                        tempInputPath,
                        tempInputPath,
                        false)
                    .ConfigureAwait(false);

                // ============================================================================
                // KEY CHANGE: Use ProtectionDescriptor with PublishingLicenseDescriptor
                // This enables true UDP where users can open files with assigned rights
                // ============================================================================
                
                _logger.LogInformation("=== APPLYING USER-DEFINED PROTECTION ===");
                _logger.LogInformation("Creating protection descriptor with {UserCount} users", userRightsList.Count);
                
                var descriptor = new ProtectionDescriptor(userRightsList);

                _logger.LogInformation("✅ Using ProtectionDescriptor approach (NOT PublishingLicense)");
                _logger.LogInformation("Descriptor type: {Type}", descriptor.GetType().Name);
                _logger.LogInformation("Descriptor content owner: {Owner}", descriptor.ContentId);
                _logger.LogInformation("User rights count: {Count}", descriptor.UserRights.Count);

                foreach (var ur in descriptor.UserRights)
                {
                    _logger.LogInformation(
                        "Descriptor entry: Users={Users} Rights={Rights}",
                        string.Join(";", ur.Users),
                        string.Join(";", ur.Rights));
                }

                handler.SetProtection(descriptor, new ProtectionSettings());

                _logger.LogInformation("Committing protected file with UDP");

                await handler.CommitAsync(tempOutputPath).ConfigureAwait(false);

                var outputFileName = !string.IsNullOrWhiteSpace(definition.OutputFileName)
                    ? definition.OutputFileName
                    : $"{Path.GetFileNameWithoutExtension(originalFileName)}_protected{Path.GetExtension(originalFileName)}";

                var serverFilePath = Path.Combine(outputFolder, outputFileName);
                File.Copy(tempOutputPath, serverFilePath, overwrite: true);

                var fi = new FileInfo(serverFilePath);

                _logger.LogInformation(
                    "✅ FILE PROTECTION COMPLETED - Output: {OutputPath}, Size: {Size} bytes",
                    serverFilePath,
                    fi.Length);

                return new ProtectionFileResponseDto
                {
                    OutputFileName = outputFileName,
                    OutputFolderPath = outputFolder,
                    FullPath = serverFilePath,
                    SizeBytes = fi.Length,
                    CreatedUtc = fi.CreationTimeUtc,
                    ModifiedUtc = fi.LastWriteTimeUtc,
                    UserPermissions = definition.UserPermissions ?? new List<UserPermissionDto>(),
                    IncludeCallerAsOwner = definition.IncludeCallerAsOwner
                };
            }
            finally
            {
                try { if (File.Exists(tempInputPath)) File.Delete(tempInputPath); } catch { }
                try { if (File.Exists(tempOutputPath)) File.Delete(tempOutputPath); } catch { }
            }
        }

        private List<string> MapRights(IEnumerable<string> requested)
        {
            var rights = new List<string>();

            foreach (var token in requested)
            {
                var normalizedToken = token.Trim().ToLowerInvariant();
                _logger.LogInformation("Mapping right: {Token} -> {Normalized}", token, normalizedToken);

                switch (normalizedToken)
                {
                    case "read":
                    case "view":
                        rights.Add(Rights.View);
                        break;
                    case "edit":
                        rights.Add(Rights.Edit);
                        break;
                    case "print":
                        rights.Add(Rights.Print);
                        break;
                    case "fullcontrol":
                    case "full control":
                    case "owner":
                        rights.Add(Rights.Owner);
                        break;
                    case "share":
                    case "export":
                        rights.Add(Rights.Export);
                        break;
                }
            }

            return rights;
        }
    }
}