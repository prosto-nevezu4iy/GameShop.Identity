using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Contracts.ViewModels.Account
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
