using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MIPSDK_FileOperations_API.Models;
using MIPSDK_FileOperations_API.Services;
using System.Text.Json;

namespace MIPSDK_FileOperations_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class FileProtectionController : ControllerBase
    {
        private readonly IFileProtectionService _fileProtectionService;

        public FileProtectionController(IFileProtectionService fileProtectionService)
        {
            _fileProtectionService = fileProtectionService;
        }

        [HttpPost("protect")]
        [RequestSizeLimit(100_000_000)]
        public async Task<IActionResult> ProtectFile(
            [FromForm] IFormFile file,
            [FromForm] string protectionDefinition,
            CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
                return BadRequest("File is required.");

            if (string.IsNullOrWhiteSpace(protectionDefinition))
                return BadRequest("protectionDefinition (JSON) is required.");

            ProtectionFileRequestDto definition;
            try
            {
                definition = JsonSerializer.Deserialize<ProtectionFileRequestDto>(
                    protectionDefinition,
                    new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    }) ?? new ProtectionFileRequestDto();
            }
            catch (Exception ex)
            {
                return BadRequest($"Invalid protectionDefinition JSON: {ex.Message}");
            }

            var authHeader = Request.Headers["Authorization"].ToString();
            if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Unauthorized("Authorization header with Bearer token is required.");
            }

            var incomingToken = authHeader.Substring("Bearer ".Length).Trim();

            await using var inputStream = file.OpenReadStream();

            var result = await _fileProtectionService.ProtectWithUserDefinedPermissionsAsync(
                inputStream,
                file.FileName,
                definition,
                User,
                incomingToken,
                cancellationToken);

            // Return JSON metadata, not file bytes
            return Ok(result);
        }
    }
}
