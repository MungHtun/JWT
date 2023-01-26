using System;
using JWT.Services;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
	public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
		{
			_userService = userService;
		}
	}
}

