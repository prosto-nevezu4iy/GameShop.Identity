using GameShop.Identity.DAL.Entities;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GameShop.Identity.Services
{
    public interface IIdentityService
    {
        Task<IdentityResult> UpdateUserAsync(ApplicationUser oldUser, string userName, string email, string phoneNumber);

        Task UpdateClaimsAsync(ApplicationUser user, IEnumerable<Claim> newClaims);
    }
}
