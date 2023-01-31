using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JWT.Constants;
using JWT.Entities;
using JWT.Models;
using JWT.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Services
{
    public class UserService : IUserService
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

        #region[first]
        //public async Task<AuthenticationModel> GetTokenAsync(TokenRequestModel tokenRequestModel)
        //{
        //    var authenticationModel = new AuthenticationModel();
        //    var user = await _userManager.FindByEmailAsync(tokenRequestModel.Email);
        //    if (user == null)
        //    {
        //        authenticationModel.IsAuthenticated = false;
        //        authenticationModel.Message = $"No Accounts Registered with {tokenRequestModel.Email}.";
        //        return authenticationModel;
        //    }
        //    if (await _userManager.CheckPasswordAsync(user, tokenRequestModel.Password))
        //    {
        //        authenticationModel.IsAuthenticated = true;
        //        JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
        //        authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        //        authenticationModel.Email = user.Email;
        //        authenticationModel.UserName = user.UserName;
        //        var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
        //        authenticationModel.Roles = rolesList.ToList();
        //        return authenticationModel;
        //    }
        //    authenticationModel.IsAuthenticated = false;
        //    authenticationModel.Message = $"Incorrect Credentials for user {user.Email}.";
        //    return authenticationModel;
        //}
        #endregion[first]
        public async Task<AuthenticationModel> GetTokenAsync(TokenRequestModel tokenRequestModel)
        {
            var authenticationModel = new AuthenticationModel();
            var user = await _userManager.FindByEmailAsync(tokenRequestModel.Email);
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"No Accounts Registered with {tokenRequestModel.Email}.";
                return authenticationModel;
            }
            if (await _userManager.CheckPasswordAsync(user, tokenRequestModel.Password))
            {
                authenticationModel.IsAuthenticated = true;
                JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
                authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                authenticationModel.Email = user.Email;
                authenticationModel.UserName = user.UserName;
                var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                authenticationModel.Roles = rolesList.ToList();

                if(user.RefreshTokens.Any(a => a.IsActive))
                {
                    var activeRefreshToken = user.RefreshTokens.Where(a => a.IsActive == true).FirstOrDefault();
                    authenticationModel.RefreshToken = activeRefreshToken.Token;
                    authenticationModel.RefreshTokenExpiration = activeRefreshToken.Expires;
                }
                else
                {
                    var refreshToken = CreateRefreshToken();
                    authenticationModel.RefreshToken = refreshToken.Token;
                    authenticationModel.RefreshTokenExpiration = refreshToken.Expires;
                    user.RefreshTokens.Add(refreshToken);
                    _context.Update(user);
                    _context.SaveChanges();
                }



                return authenticationModel;
            }
            authenticationModel.IsAuthenticated = false;
            authenticationModel.Message = $"Incorrect Credentials for user {user.Email}.";
            return authenticationModel;
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();
            for (int i = 0; i < roles.Count; i++)
            {
                roleClaims.Add(new Claim("roles", roles[i]));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }

        public async Task<string> AddRoleAsync(AddRoleModel addRoleModel)
        {
            var user = await _userManager.FindByEmailAsync(addRoleModel.Email);
            if (user == null)
            {
                return $"-->No Accounts Registered with {addRoleModel.Email}";
            }
            if (await _userManager.CheckPasswordAsync(user, addRoleModel.Password))
            {
                var roleExists = Enum.GetNames(typeof(Authorization.Roles)).Any(x => x.ToLower() == addRoleModel.Role.ToLower());
                if (roleExists)
                {
                    var validRole = Enum.GetValues(typeof(Authorization.Roles)).Cast<Authorization.Roles>()
                                  .Where(x => x.ToString().ToLower() == addRoleModel.Role.ToLower()).FirstOrDefault();

                    await _userManager.AddToRoleAsync(user, validRole.ToString());
                    return $"--> Added {addRoleModel.Role} to user {addRoleModel.Email}";
                }
                return $"-->Role {addRoleModel.Role} not found.";
            }
            return $"-->Incorrect Creditials for user {user.Email}";
        }

        public Task<AuthenticationModel> RefreshTokenAsync(string jwtToken)
        {
            throw new NotImplementedException();
        }

        private RefreshToken CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var generator = new RNGCryptoServiceProvider())
            {
                generator.GetBytes(randomNumber);
                return new RefreshToken{
                    Token = Convert.ToBase64String(randomNumber),
                    Expires = DateTime.UtcNow.AddDays(10),
                    Created = DateTime.UtcNow
                };
            }
        }
    }
}

