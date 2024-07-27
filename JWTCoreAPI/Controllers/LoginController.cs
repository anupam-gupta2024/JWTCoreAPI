using JWTCoreAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTCoreAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _config;
        private static readonly ConcurrentDictionary<string, Guid> _refreshToken = new ConcurrentDictionary<string, Guid>();

        public LoginController(IConfiguration configuration)
        {
            _config = configuration;
        }

        [HttpGet]
        [Route("getData")]
        public Dictionary<string, string?> getData()
        {
            return _config.GetSection("ConnectionStrings")
                .GetChildren()
                .ToDictionary(a => a.Key, a => a.Value);
        }

        private UserModel AuthenticateUser(Userlogin userLogin)
        {
            var currentUser = UserConstants.Users.FirstOrDefault(o => o.Username.ToLower() == userLogin.Username.ToLower() && o.Password == userLogin.Password);

            if (currentUser != null)
            {
                return currentUser;
            }

            return null;
        }

        private AuthenticationResult GenerateToken(UserModel user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.GivenName),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var expiry = DateTime.Now.AddMinutes(user.expired);
            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: expiry,
                signingCredentials: credentials
                );

            return new AuthenticationResult()
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = GenerateRefreshToken(user.Username).ToString("D"),
                expired = expiry,
            };

            //return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login(Userlogin userlogin)
        {
            IActionResult response = Unauthorized();
            var user_ = AuthenticateUser(userlogin);
            if (user_ != null)
            {
                //var token = GenerateToken(user_);
                //response = Ok(new { token = token, expired = user_.expire, givenname = user_.GivenName });

                AuthenticationResult token = GenerateToken(user_);
                if (token != null)
                    response = Ok(token);
            }
            return response;
        }

        private Guid GenerateRefreshToken(string username)
        {
            Guid newToken = _refreshToken.AddOrUpdate(username, u => Guid.NewGuid(), (u, o) => Guid.NewGuid());
            return newToken;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("refresh")]
        public IActionResult RefreshAuthenticationToken([FromBody] AuthenticationResult oldResult)
        {
            IActionResult response = Unauthorized();

            AuthenticationResult token = GetAccessToken(oldResult);
            if (token != null)
                response = Ok(token);


            return response;
        }

        private AuthenticationResult GetAccessToken(AuthenticationResult oldResult)
        {
            if (!IsValid(oldResult, out string username))
                return null;

            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);

            var user = UserConstants.Users.FirstOrDefault(o => o.Username.ToLower() == username.ToLower());


            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.GivenName, user.GivenName),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var expiry = DateTime.Now.AddMinutes(user.expired);
            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: expiry,
                signingCredentials: credentials
                );

            return new AuthenticationResult()
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = GenerateRefreshToken(user.Username).ToString("D"),
                expired = expiry,
            };
        }

        private bool IsValid(AuthenticationResult authResult, out string username)
        {
            username = string.Empty;
            ClaimsPrincipal principal = GetPrincipalFromExpiredToken(authResult.AccessToken);
            if (principal is null)
                throw new UnauthorizedAccessException("No principal");

            username = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";

            if (string.IsNullOrEmpty(username))
                throw new UnauthorizedAccessException("No username");

            if (!Guid.TryParse(authResult.RefreshToken, out Guid givenRefreshToken))
                throw new UnauthorizedAccessException("Refresh token malformed");

            if (!_refreshToken.TryGetValue(username, out Guid currentRefreshToken))
                throw new UnauthorizedAccessException("No valid refresh token in system");

            if (currentRefreshToken != givenRefreshToken)
                throw new UnauthorizedAccessException("Invalid refresh token");

            return true;

        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken)
        {
            TokenValidationParameters tokenValidationParameter = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,   // change it to false
                ValidateIssuerSigningKey = true,    // optional
                ValidIssuer = _config["Jwt:Issuer"],
                ValidAudience = _config["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),

                NameClaimType = JwtRegisteredClaimNames.Sub,
                RoleClaimType = ClaimTypes.Role,
                //ClockSkew = TimeSpan.Zero,
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal =
                tokenHandler.ValidateToken(accessToken, tokenValidationParameter, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        [Route("revoke/{username}")]
        [HttpDelete]
        public IActionResult RevokeRefreshToken(string username)
        {
            if (_refreshToken.TryRemove(username, out _))
                return NoContent();

            return BadRequest("User doesn't exist.");
        }
    }
}
