using System;
using System.Threading.Tasks;
using JWT.Models;
using JWT.Services;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<ActionResult> RegistreAsync(RegisterModel registerModel)
        {
            var result = await _userService.RegisterAsync(registerModel);
            return Ok(result);
        }
    }
}

