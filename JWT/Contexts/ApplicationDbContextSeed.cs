using System;
using System.Linq;
using System.Threading.Tasks;
using JWT.Constants;
using JWT.Models;
using Microsoft.AspNetCore.Identity;

namespace JWT.Contexts
{
	public class ApplicationDbContextSeed
	{
		public static async Task SeedEssentialsAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
		{
			//seed roles
			await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Administrator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Moderator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.User.ToString()));


			//seed default user
			var defaultUser = new ApplicationUser {
				UserName = Authorization.default_username
				, Email = Authorization.default_email
				, EmailConfirmed = true
				, PhoneNumberConfirmed = true };


			if (userManager.Users.All(u => u.Id != defaultUser.Id))
			{
				//await userManager.CreateAsync(defaultUser, Authorization.default_password);
				//await userManager.AddToRoleAsync(defaultUser, Authorization.default_role.ToString());
                await userManager.CreateAsync(defaultUser, Authorization.default_password);
                await userManager.AddToRoleAsync(defaultUser, Authorization.default_role.ToString());
            }

        }
	}
}

