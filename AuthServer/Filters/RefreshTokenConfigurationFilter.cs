using OpenIddict.Server;
using Microsoft.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace AuthServer.Filters
{
	public class RefreshTokenConfigurationFilter : IOpenIddictServerHandlerFilter<BaseContext>
	{
		public ValueTask<bool> IsActiveAsync(BaseContext context)
		{
			if (context is null)
			{
				throw new ArgumentNullException(nameof(context));
			}

			// Check if the request path is "/token1".
			var httpContext = (context.Transaction?.GetHttpRequest()?.HttpContext);
			if (httpContext != null && httpContext.Request.Path.Equals("/connect/reference-token", StringComparison.OrdinalIgnoreCase))
			{
				context.Options.UseReferenceRefreshTokens = true;
				context.Options.UseReferenceAccessTokens = true;
			}
			else
			{
				context.Options.UseReferenceRefreshTokens = false;
				context.Options.UseReferenceAccessTokens = false;
			}

			return new(context.Options.UseReferenceRefreshTokens);
		}
	}
}
