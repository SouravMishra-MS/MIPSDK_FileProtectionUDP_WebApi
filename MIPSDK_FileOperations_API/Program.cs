using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
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

            // Authentication / JWT validation for API
            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApi(
                    jwtOptions =>
                    {
                        configuration.Bind("AzureAd", jwtOptions);
                        jwtOptions.TokenValidationParameters.ValidAudience =
                            configuration["AzureAd:Audience"];
                    },
                    identityOptions =>
                    {
                        configuration.Bind("AzureAd", identityOptions);
                    });

            builder.Services.AddAuthorization();

            // Register application services
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<IFileProtectionService, FileProtectionService>();

            // MVC / Controllers
            builder.Services.AddControllers();

            var app = builder.Build();

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}