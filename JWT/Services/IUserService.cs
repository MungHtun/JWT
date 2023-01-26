using System;
using System.Threading.Tasks;
using JWT.Models;

namespace JWT.Services
{
	public interface IUserService
	{
		Task<string> RegisterAsync(RegisterModel registerModel);	
	}
}

