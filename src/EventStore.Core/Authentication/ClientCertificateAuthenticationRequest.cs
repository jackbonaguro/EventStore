using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace EventStore.Core.Authentication {
	public abstract class ClientCertificateAuthenticationRequest : AuthenticationRequest {
		public readonly X509Certificate SuppliedClientCertificate;

		protected ClientCertificateAuthenticationRequest(string id, string name, X509Certificate suppliedClientCertificate)
		: base(id, name){
			SuppliedClientCertificate = suppliedClientCertificate;
		}
	}
}
