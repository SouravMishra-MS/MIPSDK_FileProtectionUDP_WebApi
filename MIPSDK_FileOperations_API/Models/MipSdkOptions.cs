namespace MIPSDK_FileOperations_API.Models
{
    public class MipSdkOptions
    {
        public string AppId { get; set; } = string.Empty;
        public string AppName { get; set; } = string.Empty;
        public string AppVersion { get; set; } = string.Empty;
        public string EnableEml { get; set; } = "false";
        public string CachePath { get; set; } = "c:\\mip-cache";
        public string Scopes { get; set; } = string.Empty; // MIP resource scopes
    }
}
