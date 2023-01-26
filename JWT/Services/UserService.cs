using System;
using System.Threading.Tasks;
using JWT.Constants;
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

        public async Task<string> RegisterAsync(RegisterModel registerModel)
        {
            var user = new ApplicationUser
            {
                UserName = registerModel.Username,
                Email = registerModel.Email,
                FirstName = registerModel.FirstName,
                LastName = registerModel.LastName
            };

            var userWithEmail = await _userManager.FindByEmailAsync(registerModel.Email);
            if (userWithEmail == null)
            {
                var result = await _userManager.CreateAsync(user, registerModel.Password);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, Authorization.default_role.ToString());
                }
                return $"User Registered with username {user.UserName}";
            }
            else
            {
                return $"Email {user.Email} is already registered.";
            }
        }
    }
}

