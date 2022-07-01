// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IdentityServer.Contracts.Settings;
using GameShop.Identity.DAL;
using GameShop.Identity.DAL.Entities;
using IdentityServer.Communication.Email;
using System.Collections.Generic;
using GameShop.Identity.Services.Helpers;
using System.Security.Claims;
using GameShop.Identity.Services.External;
using GameShop.Identity.Services;

namespace IdentityServer
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }
        public AppSettings AppSettings { get; set; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
            AppSettings = configuration.Get<AppSettings>();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddDbContext<IdentityContext>(options =>
                options.UseSqlServer(AppSettings.ConnectionStrings.DefaultConnection, o =>
                {
                    o.MigrationsAssembly(typeof(IdentityContext).Assembly.FullName);
                    o.MigrationsHistoryTable("__EFMigrationsHistory", IdentityContext.SchemaName);
                }));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<IdentityContext>()
                .AddDefaultTokenProviders();

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
            })
                .AddInMemoryIdentityResources(IdentityConfig.IdentityResources)
                .AddInMemoryApiScopes(IdentityConfig.ApiScopes)
                .AddInMemoryClients(IdentityConfig.Clients)
                .AddAspNetIdentity<ApplicationUser>();

            // not recommended for production - you need to store your key material somewhere secure
            builder.AddDeveloperSigningCredential();

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.ClientId = AppSettings.Authentication.Google.ClientId;
                    options.ClientSecret = AppSettings.Authentication.Google.ClientSecret;
                });

            services.AddSingleton(AppSettings);
            services.AddSingleton(AppSettings.EmailConfiguration);
            services.AddScoped<IEmailSender, EmailSender>();
            services.AddScoped<IExternalAuthService, ExternalAuthService>();
            services.AddScoped<IIdentityService, IdentityService>();
            services.AddScoped<IEqualityComparer<Claim>, ClaimsComparer>();
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}