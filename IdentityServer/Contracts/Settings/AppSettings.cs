namespace IdentityServer.Contracts.Settings
{
    public class AppSettings
    {
        public ConnectionStrings ConnectionStrings { get; set; }
        public EmailConfiguration EmailConfiguration { get; set; }
        public Authentication Authentication { get; set; }
        public Clients Clients { get; set; }
    }
}
