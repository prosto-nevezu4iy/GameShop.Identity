// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityServer.Contracts.Settings;
using System.Collections.Generic;

namespace IdentityServer.IdentityConfig
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
                   new IdentityResource[]
                   {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                   };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                
            };

        public static IEnumerable<Client> GetClients(GameShopClient client) =>
            new Client[]
            {
                // interactive client using code flow + pkce
                new Client
                {
                    ClientId = "GameShop",
                    ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,

                    RedirectUris = { $"{client.WebHost}/signin-oidc" },
                    PostLogoutRedirectUris = { $"{client.WebHost}/signout-callback-oidc" },

                    AllowOfflineAccess = true,
                    AllowedScopes = 
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                    }
                },
            };
    }
}