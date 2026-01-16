namespace MIPSDK_FileOperations_API.Models
{
    public class ProtectionFileResponseDto
    {
        public string OutputFileName { get; set; } = string.Empty;
        public string OutputFolderPath { get; set; } = string.Empty;
        public string FullPath { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset ModifiedUtc { get; set; }

        // Echo back protection definition bits for convenience
        public List<UserPermissionDto> UserPermissions { get; set; } = new();
        public bool IncludeCallerAsOwner { get; set; }
    }
}
