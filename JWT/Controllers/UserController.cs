using System;
using System.Threading.Tasks;
using JWT.Models;
using JWT.Services;
using Microsoft.AspNetCore.Http;
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
        public async Task<ActionResult> RegisterAsync(RegisterModel registerModel)
        {
            var result = await _userService.RegisterAsync(registerModel);
            return Ok(result);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync(TokenRequestModel tokenRequestModel)
        {
            var result = await _userService.GetTokenAsync(tokenRequestModel);
            SetRefreshTokenInCookie(result.RefreshToken);

            return Ok(result);
        }

        [HttpPost("addRole")]
        public async Task<IActionResult> AddRoleAsync(AddRoleModel addRoleModel)
        {
            var result = await _userService.AddRoleAsync(addRoleModel);
            return Ok(result);
        }

        private void SetRefreshTokenInCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(10)
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}

