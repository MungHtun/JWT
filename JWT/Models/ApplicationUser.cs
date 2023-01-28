using System;
using System.Collections.Generic;
using JWT.Entities;
using Microsoft.AspNetCore.Identity;

namespace JWT.Models
{
	public class ApplicationUser : IdentityUser
	{
		public string FirstName { get; set; }
		public string LastName { get; set; }
		public List<RefreshToken> RefreshTokens { get; set; }
	}
}

