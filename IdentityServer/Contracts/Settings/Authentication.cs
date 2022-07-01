namespace IdentityServer.Contracts.Settings
{
    public class Authentication
    {
        public Google Google { get; set; }
    }

    public class Google
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}
