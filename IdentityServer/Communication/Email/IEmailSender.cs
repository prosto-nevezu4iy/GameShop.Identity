using System.Threading.Tasks;

namespace IdentityServer.Communication.Email
{
    public interface IEmailSender
    {
        Task SendEmailAsync(Message message);
    }
}
