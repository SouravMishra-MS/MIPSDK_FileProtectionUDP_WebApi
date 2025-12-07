using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using Microsoft.OpenApi.Models;
using MIPSDK_FileOperations_API.Models;
using MIPSDK_FileOperations_API.Services;
using Swashbuckle.AspNetCore.SwaggerGen;

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

            // Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "MIP SDK File Operations API",
                    Version = "v1",
                    Description = "API for protecting files using Microsoft Information Protection SDK"
                });

                // Add Bearer token support
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
