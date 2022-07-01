using GameShop.Identity.DAL.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace GameShop.Identity.DAL
{
    public class IdentityContext : IdentityDbContext<ApplicationUser>
    {
        public const string SchemaName = "identity";

        public IdentityContext(DbContextOptions<IdentityContext> options)
            : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.HasDefaultSchema(SchemaName);
        }
    }
}
