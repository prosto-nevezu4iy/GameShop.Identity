using GameShop.Identity.DAL.Entities;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GameShop.Identity.Services.External
{
    public interface IExternalAuthService
    {
        Task<ApplicationUser> AutoProvisionUserAsync(
            string provider,
            string providerUserId,
            IEnumerable<Claim> claims);

        IEnumerable<Claim> FillClaims(IEnumerable<Claim> claims);

        Task<ApplicationUser> ConnectIfUserAlreadyExists(ClaimsPrincipal externalUser, string provider, string providerUserId);
    }
}
