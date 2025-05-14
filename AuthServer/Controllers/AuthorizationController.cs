using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Validation.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AuthServer.Controllers;

[ApiController]
[Route("connect")]
public class AuthorizationController: ControllerBase
{
	private readonly IOpenIddictApplicationManager _applicationManager;

	public AuthorizationController(IOpenIddictApplicationManager applicationManager)
		=> _applicationManager = applicationManager;

	[HttpGet("authorize")]
	public async Task<IActionResult> Authorize()
	{
		var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The request cannot be retrieved.");

		// Retrieve the user principal stored in the authentication cookie.
		var result = await HttpContext.AuthenticateAsync();

		//TODO we need to know if the user is validated with 3rd party IDP
		if (result.Succeeded)
		{

		}

		var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		identity.AddClaim(Claims.Subject, "test123");

		var principal = new ClaimsPrincipal(identity);
		principal.SetScopes(Scopes.OpenId);

		// 'offline_access' scope to allow  OpenIddict to return a refresh token to the caller.
		// 'openid' scope to allow  OpenIddict to return a id token to the caller.
		principal.SetScopes(request.GetScopes());

		// Persist the identity in a cookie for session management
		await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

		// Issue an authorization code
		return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	[HttpGet("reference-authorize")]
	public async Task<IActionResult> ReferenceAuthorize()
	{
		var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The request cannot be retrieved.");

		// Retrieve the user principal stored in the authentication cookie.
		var result = await HttpContext.AuthenticateAsync();

		//TODO we need to know if the user is validated with 3rd party IDP
		if (result.Succeeded)
		{

		}

		var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		identity.AddClaim(Claims.Subject, "test123");

		var principal = new ClaimsPrincipal(identity);
		principal.SetScopes(Scopes.OpenId);

		// 'offline_access' scope to allow  OpenIddict to return a refresh token to the caller.
		// 'openid' scope to allow  OpenIddict to return a id token to the caller.
		principal.SetScopes(request.GetScopes());

		// Persist the identity in a cookie for session management
		await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

		// Issue an authorization code
		return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	[HttpPost]
	[Route("token")]
	public async Task<IActionResult> Exchange()
	{
		var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

		if (request.IsClientCredentialsGrantType())
		{
			// Note: the client credentials are automatically validated by OpenIddict:
			// if client_id or client_secret are invalid, this action won't be invoked.

			var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
				throw new InvalidOperationException("The application cannot be found.");

			// Create a new ClaimsIdentity containing the claims that
			// will be used to create an id_token, a token or a code.
			var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

			identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
			identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

			identity.SetDestinations(static claim => claim.Type switch
			{
				// Allow the "name" claim to be stored in both the access and identity tokens
				// when the "profile" scope was granted (by calling principal.SetScopes(...)).
				Claims.Name when claim.Subject.HasScope(Scopes.Profile)
					=> [Destinations.AccessToken, Destinations.IdentityToken],

				// Otherwise, only store the claim in the access tokens.
				_ => [Destinations.AccessToken]
			});

			var principal = new ClaimsPrincipal(identity);

			// Set the scopes granted to the client.
			principal.SetScopes(request.GetScopes());

			return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		throw new NotImplementedException("The specified grant is not implemented.");
	}

	[HttpPost]
	[Route("reference-token")]
	public async Task<IActionResult> ReferenceToken()
	{
		var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

		if (request.IsClientCredentialsGrantType())
		{
			// Note: the client credentials are automatically validated by OpenIddict:
			// if client_id or client_secret are invalid, this action won't be invoked.

			var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
				throw new InvalidOperationException("The application cannot be found.");
			// Create a new ClaimsIdentity containing the claims that
			// will be used to create an id_token, a token or a code.
			var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

			// Use the client_id as the subject identifier.
			identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
			identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

			identity.SetDestinations(static claim => claim.Type switch
			{
				// Allow the "name" claim to be stored in both the access and identity tokens
				// when the "profile" scope was granted (by calling principal.SetScopes(...)).
				Claims.Name when claim.Subject.HasScope(Scopes.Profile)
					=> [Destinations.AccessToken, Destinations.IdentityToken],

				// Otherwise, only store the claim in the access tokens.
				_ => [Destinations.AccessToken]
			});

			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}
		
		if(request.IsAuthorizationCodeGrantType())
		{
			var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

			var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
				throw new InvalidOperationException("The application cannot be found.");

			// Create a new ClaimsPrincipal containing the claims that
			// will be used to create an id_token, a token or a code.
			var principal = new ClaimsPrincipal(identity);

			identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
			identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

			// Set the scopes granted to the client.
			principal.SetScopes(request.GetScopes());

			return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		if (request.IsRefreshTokenGrantType())
		{
			// Retrieve the claims principal stored in the authorization code/device code/refresh token.
			var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

			

			var identity = new ClaimsIdentity(result.Principal.Claims,
				authenticationType: TokenValidationParameters.DefaultAuthenticationType,
				nameType: Claims.Name,
				roleType: Claims.Role);

			return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		}

		throw new NotImplementedException("The specified grant is not implemented.");
	}

	[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
	[HttpGet("protected")]
	[ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
	public async Task<IActionResult> AccessProtectedEndpoint()
	{
		// validate user and generate response
		return await Task.FromResult(Ok(new
		{
			name = User.FindFirst(Claims.Subject)?.Value,
			sadf = User.FindFirst(Claims.Name)?.Value,
			sadf1 = User.FindFirst(Claims.ClientId)?.Value,
			sadf2 = User.FindFirst(Claims.ExpiresAt)?.Value,
			sadf3 = User.FindFirst(Claims.IssuedAt)?.Value
		}));
	}
}