using System.Security.Principal;

namespace EventStore.Core.Authentication {
	public abstract class PasswordAuthenticationRequest : AuthenticationRequest {
		public readonly string SuppliedPassword;

		protected PasswordAuthenticationRequest(string id, string name, string suppliedPassword)
		: base(id, name){
			SuppliedPassword = suppliedPassword;
		}
	}
}
