using static OpenIddict.Validation.OpenIddictValidationEvents;
using OpenIddict.Validation;

namespace AuthServer.Filters
{
	public class TokenValidationFilter : IOpenIddictValidationHandler<ProcessAuthenticationContext>
	{
		public ValueTask HandleAsync(ProcessAuthenticationContext context)
		{
			//check if context.AccessToken has value and contains three . in the string
			if (!string.IsNullOrEmpty(context.AccessToken))
			{

				if (context.AccessToken.Count(c => c == '.') == 3)
				{
					
				}
				else
				{

				}
			}
			return default;
		}
	}
}
