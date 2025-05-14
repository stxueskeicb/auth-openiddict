using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthServer.Models;
using AuthServer;
using static OpenIddict.Server.OpenIddictServerHandlers.Exchange;
using static OpenIddict.Server.OpenIddictServerEvents;
using AuthServer.Filters;
using static OpenIddict.Server.OpenIddictServerHandlers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System.Diagnostics;
using System;
using AuthServer.Middlewares;
using OpenIddict.Validation;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Authentication;
using AuthServer.Handlers;
using static OpenIddict.Validation.OpenIddictValidationHandlers;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddConsole();    // Add console logging

builder.Services.AddSingleton<AccessTokenConfigurationFilter>();
builder.Services.AddSingleton<RefreshTokenConfigurationFilter>();


builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
	// Configure the context to use Microsoft SQL Server.
	options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "Auth-Server")}");

	// Register the entity sets needed by OpenIddict.
	options.UseOpenIddict();
});

// Register OpenIddict core services.
builder.Services.AddOpenIddict()
	// Register the OpenIddict core components.
	.AddCore(options =>
	{
		// Configure OpenIddict to use the Entity Framework Core stores and models.
		options.UseEntityFrameworkCore()
			   .UseDbContext<ApplicationDbContext>();
	})
	// Register the OpenIddict server components.
	.AddServer(options =>
	{
		//options.AddEventHandler<ProcessRequestContext>(builder =>
		//{
		//	builder.Import(InferEndpointType.Descriptor)
		//	.AddFilter<RefreshTokenConfigurationFilter>();
		//});


		//options.AddEventHandler<ProcessRequestContext>(builder =>
		//			builder.Import(ExtractTokenRequest.Descriptor)
		//			.AddFilter<AccessTokenConfigurationFilter>());

		//options.AddEventHandler<ProcessSignInContext>(builder =>
		//			builder.Import(GenerateAccessToken.Descriptor)
		//			.AddFilter<AccessTokenConfigurationFilter>());

		//options.AddEventHandler<ProcessRequestContext>(builder =>
		//	builder.Import(ExtractTokenRequest.Descriptor)
		//	.AddFilter<RefreshTokenConfigurationFilter>());

		//options.AddEventHandler<ProcessSignInContext>(builder =>
		//			builder.Import(GenerateAccessToken.Descriptor)
		//			.AddFilter<RefreshTokenConfigurationFilter>());


		// Allow client applications to use the grant_type=password flow.
		options.AllowClientCredentialsFlow()
			   .AllowAuthorizationCodeFlow()
			   .AllowRefreshTokenFlow();

		// Enable the authorization and token endpoints.
		options.SetAuthorizationEndpointUris("connect/authorize", "connect/reference-authorize")
			   .SetTokenEndpointUris("connect/token", "connect/reference-token")
			   .SetIntrospectionEndpointUris("connect/introspect")
			   .SetRevocationEndpointUris("connect/revoke");

		options.AddDevelopmentEncryptionCertificate()
			   .AddDevelopmentSigningCertificate(); // Used for create and validate token signature


		options.UseAspNetCore()
				.EnableAuthorizationEndpointPassthrough()
				.EnableTokenEndpointPassthrough()
				.EnableStatusCodePagesIntegration()
				.DisableTransportSecurityRequirement(); //development only.

		options.DisableAccessTokenEncryption();
	})
	// Register the OpenIddict validation components.
	.AddValidation(options =>
	{
		//options.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(builder =>
		//{
		//	builder.Import(OpenIddictValidationHandler..Descriptor)
		//	.AddFilter<TokenValidationFilter>())
		//});

		//options.EnableAuthorizationEntryValidation();
		//options.EnableTokenEntryValidation();

		//options.AddEventHandler<OpenIddictValidationEvents.ValidateTokenContext>(builder =>
		//			builder.Import(OpenIddictValidationHandlers.Protection.ValidateReferenceTokenIdentifier.Descriptor)
		//			.AddFilter<AccessTokenValidationFilter>());

		// Use server's own confiugration to validate tokens.
		// This is mandatory for the OpenIddict server to validate reference tokens.

		options.UseLocalServer();
		// If the token is valid:
		// The ClaimsPrincipal is attached to the HttpContext.User property.
		// The request proceeds to the next middleware or the controller action.

		// Register OpenIddict validation middlewwares with the .NET Core
		//This enable OpenIddict to integrate with the ASP.NET Core pipeline.
		//This  let OpenIddict to integrate with .NET Core authentication and authorization system.
		// Which once OpenIddict validate the token, it create the ClaimsPrincipal,
		// then .NET Core attach this ClaimsPrincipal to the HttpContext.User property.
		// This allows the application to use the ClaimsPrincipal for authorization and authentication.
		options.UseAspNetCore();
	});

//Use OpenIdDict to handle authentication and authorization ontop of ASP.NET Core Identity
builder.Services
	.AddAuthentication(options =>
	{
		options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
		options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	})
	.AddCookie(options =>
	{
		options.Cookie.Name = "AuthCookie"; // Optional: Set a custom cookie name
		options.Cookie.HttpOnly = true;    // Ensure the cookie is HTTP-only for security
		options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Use secure cookies
		options.SlidingExpiration = true; // Enable sliding expiration
	});


builder.Services.AddControllers();

// Add services to the container.
//builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization(); // Register authorization services

var app = builder.Build();

DataSeeding.CreateData(app);

app.UseRouting(); // Ensure routing middleware is added
				  // Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}
else
{
	// Enable HTTPS redirection in production
	app.UseHttpsRedirection();
}

//app.UseMiddleware<ExceptionMiddleware>();
//Register OpenIddict server middleware with the request pipeline.
app.UseDeveloperExceptionPage();
app.UseForwardedHeaders();
app.UseRouting();
app.UseCors();
app.UseMiddleware<ExceptionMiddleware>();

//Adds the ASP.NET Core authentication middleware to the request pipeline.
//This middleware intercepts incoming requests and delegates token validation to 
//OpenIddict (via the OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme).
app.UseAuthentication();

//Adds the ASP.NET Core authorization middleware to the request pipeline.
//This middleware enforces authorization policies based on the 
//ClaimsPrincipal attached to HttpContext.User.
//The ASP.NET Core authorization middleware (app.UseAuthorization()) enforces 
//any authorization policies based on the ClaimsPrincipal attached to HttpContext.User.
app.UseAuthorization();
app.MapControllers();
app.Run();