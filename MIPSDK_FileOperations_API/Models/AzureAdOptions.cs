namespace MIPSDK_FileOperations_API.Models
{
    public class AzureAdOptions
    {
        public string Instance { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public string Scopes { get; set; } = string.Empty;
    }
}
