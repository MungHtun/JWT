using System;
using System.Threading.Tasks;
using JWT.Models;

namespace JWT.Services
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterModel registerModel);
        Task<AuthenticationModel> GetTokenAsync(TokenRequestModel tokenRequestModel);
        Task<string> AddRoleAsync(AddRoleModel addRoleModel);
        Task<AuthenticationModel> RefreshTokenAsync(string token);
        ApplicationUser GetById(string id);
        bool RevokeToken(string token);

    }
}

