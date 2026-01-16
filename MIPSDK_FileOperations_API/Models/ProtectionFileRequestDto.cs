namespace MIPSDK_FileOperations_API.Models
{
    public class ProtectionFileRequestDto
    {
        // User-defined permissions (UDP)
        public List<UserPermissionDto> UserPermissions { get; set; } = new();

        // When true, the API will add an owner entry for the configured default owner.
        // In client-credentials mode there is no authenticated end-user.
        public bool IncludeCallerAsOwner { get; set; } = false;

        // Name of the protected file (for response and/or save), e.g. "output_filename.pdf"
        public string? OutputFileName { get; set; }

        // Local server folder to save the protected file, e.g. "C:\\ProtectedFiles"
        // Optional. If empty/null, no extra server-side copy is saved.
        public string? OutputFolderPath { get; set; }
    }
}
