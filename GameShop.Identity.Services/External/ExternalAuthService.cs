using GameShop.Identity.DAL.Entities;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GameShop.Identity.Services.External
{
    public class ExternalAuthService : IExternalAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ExternalAuthService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<ApplicationUser> AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;

            var user = new ApplicationUser
            {
                UserName = email,
                NormalizedUserName = email.ToUpper(),
                Email = email,
                NormalizedEmail = email.ToUpper(),
                EmailConfirmed = true
            };

            var identityResult = await _userManager.CreateAsync(user);
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            // create a list of claims that we want to transfer into our store
            var filtered = FillClaims(claims);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);

            return user;
        }

        public async Task<ApplicationUser> ConnectIfUserAlreadyExists(ClaimsPrincipal externalUser, string provider, string providerUserId)
        {
            var email = externalUser.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;

            var existingUser = await _userManager.FindByEmailAsync(email);

            if (existingUser == null)
            {
                return null;
            }

            // Connecting, creating external identity login for the user
            var identityResult = await _userManager.AddLoginAsync(existingUser, new UserLoginInfo(provider, providerUserId, provider));
            if (!identityResult.Succeeded)
            {
                throw new Exception("Add login failed");
            }

            // create a list of claims that we want to transfer into our store
            var filtered = FillClaims(externalUser.Claims);

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(existingUser, filtered);
                if (!identityResult.Succeeded) throw new Exception(identityResult.Errors.First().Description);
            }

            return existingUser;
        }

        public IEnumerable<Claim> FillClaims(IEnumerable<Claim> claims)
        {
            var filtered = new List<Claim>();

            var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
            var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;

            if (first != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.GivenName, first));
            }

            if (last != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.FamilyName, last));
            }

            return filtered;
        }
    }
}
