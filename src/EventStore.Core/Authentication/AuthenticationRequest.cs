using System.Security.Principal;

namespace EventStore.Core.Authentication {
	public abstract class AuthenticationRequest {
		public readonly string Id;
		public readonly string Name;

		protected AuthenticationRequest(string id, string name) {
			Id = id;
			Name = name;
		}

		public abstract void Unauthorized();
		public abstract void Authenticated(IPrincipal principal);
		public abstract void Error();
		public abstract void NotReady();
	}
}
