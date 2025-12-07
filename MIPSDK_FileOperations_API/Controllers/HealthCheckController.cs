using Microsoft.AspNetCore.Mvc;

namespace MIPSDK_FileOperations_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HealthCheckController : ControllerBase
    {
        /// <summary>
        /// Health check endpoint to verify API is running.
        /// </summary>
        /// <returns>Simple health status response.</returns>
        [HttpGet("status")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public IActionResult HealthCheck()
        {
            var response = new
            {
                status = "healthy",
                timestamp = DateTime.UtcNow,
                service = "MIPSDK_FileOperations_API"
            };

            return Ok(response);
        }
    }
}
