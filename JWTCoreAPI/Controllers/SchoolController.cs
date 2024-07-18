using JWTCoreAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTCoreAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SchoolController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        [Route("GetData")]
        public string GetData()
        {
            return "Authenticated with Jwt!!";
        }

        [HttpGet]
        [Route("Detail")]
        public string Detail()
        {
            return "No Authentication required";
        }

        [Authorize]
        [HttpPost]
        public string AddUser(Users user)
        {
            return "User added with username " + user.Username;
        }
    }
}
