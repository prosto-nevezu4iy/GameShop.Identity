using IdentityServer.Contracts.Settings;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using System.Threading.Tasks;

namespace IdentityServer.Communication.Email
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailConfiguration emailConfig;

        public EmailSender(EmailConfiguration emailConfig)
        {
            this.emailConfig = emailConfig;
        }

        public Task SendEmailAsync(Message message)
        {
            var mailMessage = CreateEmailMessage(message);
            return SendAsync(mailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(MailboxAddress.Parse(emailConfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message.Content };
            return emailMessage;
        }

        private async Task SendAsync(MimeMessage mailMessage)
        {
            using var client = new SmtpClient();
            try
            {
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.ServerCertificateValidationCallback = (sender, certificate, certChainType, errors) => true;

                if (emailConfig.Port == 587)
                {
                    await client.ConnectAsync(emailConfig.SmtpServer, emailConfig.Port, SecureSocketOptions.StartTls);
                }
                else
                {
                    await client.ConnectAsync(emailConfig.SmtpServer, emailConfig.Port, false);
                }


                if (!string.IsNullOrEmpty(emailConfig.UserName) || !string.IsNullOrEmpty(emailConfig.Password))
                {
                    await client.AuthenticateAsync(emailConfig.UserName, emailConfig.Password);
                }

                await client.SendAsync(mailMessage);
            }
            finally
            {
                await client.DisconnectAsync(true);
                client.Dispose();
            }
        }
    }
}
