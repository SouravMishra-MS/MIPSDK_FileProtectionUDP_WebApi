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
            string userAccessToken,
            CancellationToken cancellationToken);
    }

    public class FileProtectionService : IFileProtectionService
    {
        private readonly MipSdkOptions _mipOptions;
        private readonly AuthService _authService;
        private static bool _mipInitialized;
        private static readonly object _initLock = new();

        public FileProtectionService(
            IOptions<MipSdkOptions> mipOptions,
            AuthService authService)
        {
            _mipOptions = mipOptions.Value;
            _authService = authService;
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
            }
        }

        public async Task<ProtectionFileResponseDto> ProtectWithUserDefinedPermissionsAsync(
            Stream inputStream,
            string originalFileName,
            ProtectionFileRequestDto definition,
            ClaimsPrincipal user,
            string userAccessToken,
            CancellationToken cancellationToken)
        {
            if (inputStream == null || !inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable.", nameof(inputStream));

            if (string.IsNullOrWhiteSpace(definition.OutputFolderPath))
                throw new ArgumentException("OutputFolderPath is required in protectionDefinition.", nameof(definition));

            var outputFolder = definition.OutputFolderPath;

            // Ensure output directory exists
            Directory.CreateDirectory(outputFolder);

            var appInfo = new ApplicationInfo
            {
                ApplicationId = _mipOptions.AppId,
                ApplicationName = _mipOptions.AppName,
                ApplicationVersion = _mipOptions.AppVersion
            };

            // Auth delegate that uses OBO via AuthService
            var authDelegate = new AuthDelegateImpl(_authService, userAccessToken);

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

            var upn = user.Identity?.Name ?? "unknown@unknown";
            var identityId = $"{upn}-webapi";

            var fileEngineSettings = new FileEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Identity(identityId)
            };

            var fileEngine = await fileProfile.AddEngineAsync(fileEngineSettings)
                                              .ConfigureAwait(false);

            var protectionEngineSettings = new ProtectionEngineSettings(identityId, authDelegate, string.Empty, "en-us")
            {
                Identity = new Identity(identityId)
            };

            _ = await protectionProfile.AddEngineAsync(protectionEngineSettings)
                                       .ConfigureAwait(false);

            // Build UDP (UserRights) from definition
            var userRightsList = new List<UserRights>();

            if (definition.UserPermissions != null)
            {
                foreach (var perm in definition.UserPermissions)
                {
                    if (string.IsNullOrWhiteSpace(perm.Email) ||
                        perm.Rights == null ||
                        perm.Rights.Count == 0)
                    {
                        continue;
                    }

                    var rights = MapRights(perm.Rights);
                    if (rights.Count == 0) continue;

                    userRightsList.Add(new UserRights(new List<string> { perm.Email }, rights));
                }
            }

            if (definition.IncludeCallerAsOwner)
            {
                var callerEmail = upn;
                userRightsList.Add(new UserRights(
                    new List<string> { callerEmail },
                    new List<string> { Rights.Owner }));
            }

            if (userRightsList.Count == 0)
                throw new InvalidOperationException("No valid user permissions were provided.");

            // Temp files for MIP handler
            var tempInputPath = Path.GetTempFileName();
            var tempOutputPath = Path.GetTempFileName();

            try
            {
                // Write input stream into temp file
                await using (var fs = File.Open(tempInputPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    await inputStream.CopyToAsync(fs, cancellationToken).ConfigureAwait(false);
                }

                // Create handler and set protection
                var handler = await fileEngine.CreateFileHandlerAsync(
                        tempInputPath,
                        tempInputPath,
                        false)
                    .ConfigureAwait(false);

                var descriptor = new ProtectionDescriptor(userRightsList);
                handler.SetProtection(descriptor, new ProtectionSettings());

                await handler.CommitAsync(tempOutputPath).ConfigureAwait(false);

                // Determine final file name
                var outputFileName = !string.IsNullOrWhiteSpace(definition.OutputFileName)
                    ? definition.OutputFileName
                    : $"{Path.GetFileNameWithoutExtension(originalFileName)}_protected{Path.GetExtension(originalFileName)}";

                var serverFilePath = Path.Combine(outputFolder, outputFileName);

                // Move/copy the committed protected file to the final location
                // Overwrite if exists
                File.Copy(tempOutputPath, serverFilePath, overwrite: true);

                var fi = new FileInfo(serverFilePath);

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

        private static List<string> MapRights(IEnumerable<string> requested)
        {
            var rights = new List<string>();

            foreach (var token in requested)
            {
                switch (token.Trim().ToLowerInvariant())
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
