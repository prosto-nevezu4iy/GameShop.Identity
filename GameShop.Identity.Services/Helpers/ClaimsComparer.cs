using System.Collections.Generic;
using System.Security.Claims;

namespace GameShop.Identity.Services.Helpers
{
    public class ClaimsComparer : IEqualityComparer<Claim>
    {
        public bool Equals(Claim x, Claim y)
        {
            return x.Type == y.Type && x.Value == y.Value;
        }

        public int GetHashCode(Claim obj)
        {
            return obj.Type.GetHashCode() + obj.Value.GetHashCode();
        }
    }
}
