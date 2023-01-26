using System;
using JWT.Models;
using JWT.Settings;
using JWT.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace JWT.Services
{
	public class UserService: IUserService
	{
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT_Data _jwt;

        public UserService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT_Data> jwt)
		{
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }
	}
}

