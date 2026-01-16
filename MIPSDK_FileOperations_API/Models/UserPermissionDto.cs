namespace MIPSDK_FileOperations_API.Models
{
    public class UserPermissionDto
    {
        public string Email { get; set; } = string.Empty;

        // e.g. ["Read", "Edit", "Print", "FullControl", "Share"]
        public List<string> Rights { get; set; } = new();
    }
}
