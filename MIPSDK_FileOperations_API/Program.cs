using MIPSDK_FileOperations_API.Models;
using MIPSDK_FileOperations_API.Services;

namespace MIPSDK_FileOperations_API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var configuration = builder.Configuration;

            // Bind configuration into strongly typed option classes
            builder.Services.Configure<AzureAdOptions>(configuration.GetSection("AzureAd"));
            builder.Services.Configure<MipSdkOptions>(configuration.GetSection("MipSdk"));

            // Register application services
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<IFileProtectionService, FileProtectionService>();

            // MVC / Controllers
            builder.Services.AddControllers();

            var app = builder.Build();

            // Only use HTTPS redirection in non-Development environments
            if (!app.Environment.IsDevelopment())
            {
                app.UseHttpsRedirection();
            }

            app.MapControllers();

            app.Run();
        }
    }
}