using OpenIddict.Abstractions;

namespace AuthServer;

public static class DataSeeding
{
    public static void CreateData(IApplicationBuilder app)
    {
        CreateApplications(app.ApplicationServices);
    }

    private static async void CreateApplications(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

		// Handle "credential-flow-client"
		var credentialFlowClient = await manager.FindByClientIdAsync("private-client");
		if (credentialFlowClient is null)
		{
			await manager.CreateAsync(new OpenIddictApplicationDescriptor
			{
				ClientId = "private-client",
				DisplayName = "Credential Flow Client",
				ClientSecret = "credential-flow-secret",
				Permissions =
			{
				OpenIddictConstants.Permissions.Endpoints.Token,
				OpenIddictConstants.Permissions.Endpoints.Revocation,
				OpenIddictConstants.Permissions.Endpoints.Introspection,
				OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
				OpenIddictConstants.Permissions.Prefixes.Scope + "api",
			}
			});
		}
		else
		{
			// Update the existing application
			var descriptor = new OpenIddictApplicationDescriptor
			{
				ClientId = "credential-flow-client-reference",
				ClientSecret = "credential-flow-secret",
				Permissions =
			{
				OpenIddictConstants.Permissions.Endpoints.Token,
				OpenIddictConstants.Permissions.Endpoints.Revocation,
				OpenIddictConstants.Permissions.Endpoints.Introspection,
				OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
				OpenIddictConstants.Permissions.Prefixes.Scope + "api",
			}
			};

			await manager.PopulateAsync(descriptor, credentialFlowClient);
			await manager.UpdateAsync(credentialFlowClient);
		}


		// Handle "code-pcke-client"
		var codePkceClient = await manager.FindByClientIdAsync("code-pcke-client4");
		if (codePkceClient is null)
		{
			await manager.CreateAsync(new OpenIddictApplicationDescriptor
			{
				ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
				ClientId = "code-pcke-client4",
				Permissions =
				{
					OpenIddictConstants.Permissions.Endpoints.Authorization,
					OpenIddictConstants.Permissions.Endpoints.Revocation,
					OpenIddictConstants.Permissions.Endpoints.Introspection,
					OpenIddictConstants.Permissions.Endpoints.Token,
					OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
					OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
					OpenIddictConstants.Permissions.ResponseTypes.Code,
					OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access"
				},
				RedirectUris =
				{
					new Uri("https://oauth.pstmn.io/v1/callback"),
				},
			});
		}
		else
		{
			// Update the existing application
			var descriptor = new OpenIddictApplicationDescriptor
			{
				ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
				ClientId = "code-pcke-client4",
				Permissions =
				{
					OpenIddictConstants.Permissions.Endpoints.Authorization,
					OpenIddictConstants.Permissions.Endpoints.Revocation,
					OpenIddictConstants.Permissions.Endpoints.Introspection,
					OpenIddictConstants.Permissions.Endpoints.Token,
					OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
					OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
					OpenIddictConstants.Permissions.ResponseTypes.Code,
					OpenIddictConstants.Permissions.Prefixes.Scope + "offline_access"
				},
				RedirectUris =
				{
					new Uri("https://oauth.pstmn.io/v1/callback"),
				},
			};

			await manager.PopulateAsync(descriptor, codePkceClient);
			await manager.UpdateAsync(codePkceClient);
		}
	}
}