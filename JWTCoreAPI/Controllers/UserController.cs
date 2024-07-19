using JWTCoreAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTCoreAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpGet("Public")]
        public IActionResult Public()
        {
            return Ok("Hi, you're on public property");
        }


        [HttpGet("Admin")]
        [Authorize(Roles = "Developer")]
        public IActionResult Administrator()
        {
            var currentuser = GetCurrentUser();

            return Ok($"Hi {currentuser.GivenName}, you are an {currentuser.Role}.");
        }

        [HttpGet("Client")]
        [Authorize(Roles = "Developer, Operator")]
        public IActionResult Client()
        {
            var currentuser = GetCurrentUser();

            return Ok($"Hi {currentuser.GivenName}, you are an {currentuser.Role}.");
        }

        private UserModel GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new UserModel
                {
                    Username = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value,
                    Email = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                    GivenName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.GivenName)?.Value,
                    Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value
                };
            }
            return null;
        }
    }
}
