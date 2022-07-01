using GameShop.Identity.DAL.Entities;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GameShop.Identity.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEqualityComparer<Claim> _equalityComparer;

        public IdentityService(UserManager<ApplicationUser> userManager, IEqualityComparer<Claim> equalityComparer)
        {
            _userManager = userManager;
            _equalityComparer = equalityComparer;
        }

        public async Task<IdentityResult> UpdateUserAsync(ApplicationUser oldUser, string userName, string email, string phoneNumber)
        {
            if (oldUser.UserName != userName)
            {
                var setUserNameResult = await _userManager.SetUserNameAsync(oldUser, userName);
                if (!setUserNameResult.Succeeded)
                {
                    return IdentityResult.Failed(new IdentityError { Description = "ErrorSettingUserName" });
                }
            }

            if (oldUser.Email != email)
            {
                var setEmailResult = await _userManager.SetEmailAsync(oldUser, email);

                if (!setEmailResult.Succeeded)
                {
                    return IdentityResult.Failed(new IdentityError { Description = "ErrorSettingEmail" });
                }
            }

            if (oldUser.PhoneNumber != phoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(oldUser, phoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    return IdentityResult.Failed(new IdentityError { Description = "ErrorSettingPhone" });
                }
            }

            return IdentityResult.Success;
        }

        public async Task UpdateClaimsAsync(ApplicationUser user, IEnumerable<Claim> newClaims)
        {
            var oldClaims = await _userManager.GetClaimsAsync(user);
            var claimsToAdd = newClaims.Except(oldClaims, _equalityComparer).ToList();
            var claimsToRemove = oldClaims.Except(newClaims, _equalityComparer).ToList();

            if (claimsToRemove.Any())
            {
                await _userManager.RemoveClaimsAsync(user, claimsToRemove);
            }

            if (claimsToAdd.Any())
            {
                await _userManager.AddClaimsAsync(user, claimsToAdd);
            }
        }
    }
}
