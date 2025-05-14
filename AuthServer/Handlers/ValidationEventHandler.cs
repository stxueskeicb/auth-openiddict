using OpenIddict.Server;
using Microsoft.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;
using OpenIddict.Validation;
using OpenIddict.Abstractions;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlerFilters;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlers;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;


namespace AuthServer.Handlers
{
	public class ValidationEventHandler : IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
	{
		public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
		   = OpenIddictValidationHandlerDescriptor.CreateBuilder<OpenIddictValidationEvents.ProcessAuthenticationContext>()
			   .AddFilter<RequireHttpRequest>() 
			   .UseSingletonHandler<ValidateHostHeader>()
			   .SetOrder(int.MinValue + 100)
				.SetType(OpenIddictValidationHandlerType.Custom)
				.Build();

		public ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
		{
			context.Configuration.Properties["TokenType"] = "Reference";
			
			return default;
		}
	}
}
