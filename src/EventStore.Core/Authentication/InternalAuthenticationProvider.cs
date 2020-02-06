using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using EventStore.Common.Log;
using EventStore.Common.Utils;
using EventStore.Core.Bus;
using EventStore.Core.Data;
using EventStore.Core.DataStructures;
using EventStore.Core.Helpers;
using EventStore.Core.Messages;
using EventStore.Core.Services.UserManagement;

namespace EventStore.Core.Authentication {
	public class InternalAuthenticationProvider : IAuthenticationProvider,
		IHandle<InternalAuthenticationProviderMessages.ResetPasswordCache> {
		private static readonly ILogger Log = LogManager.GetLoggerFor<InternalAuthenticationProvider>();
		private readonly IODispatcher _ioDispatcher;
		private readonly PasswordHashAlgorithm _passwordHashAlgorithm;
		private readonly bool _logFailedAuthenticationAttempts;
		private readonly LRUCache<string, Tuple<string, IPrincipal>> _userPasswordsCache;

		public InternalAuthenticationProvider(IODispatcher ioDispatcher, PasswordHashAlgorithm passwordHashAlgorithm,
			int cacheSize, bool logFailedAuthenticationAttempts) {
			_ioDispatcher = ioDispatcher;
			_passwordHashAlgorithm = passwordHashAlgorithm;
			_userPasswordsCache = new LRUCache<string, Tuple<string, IPrincipal>>(cacheSize);
			_logFailedAuthenticationAttempts = logFailedAuthenticationAttempts;
		}

		public void Authenticate(AuthenticationRequest authenticationRequest) {
			Tuple<string, IPrincipal> cached;
			if (_userPasswordsCache.TryGet(authenticationRequest.Name, out cached)) {
				if (authenticationRequest is PasswordAuthenticationRequest passwordAuthenticationRequest) {
					AuthenticateWithPassword(passwordAuthenticationRequest, cached.Item1, cached.Item2);
				} else if (authenticationRequest is ClientCertificateAuthenticationRequest
					clientCertificateAuthenticationRequest) {
					AuthenticateWithClientCertificate(clientCertificateAuthenticationRequest, cached.Item2);
				} else {
					authenticationRequest.Error();
				}
			} else {
				var userStreamId = "$user-" + authenticationRequest.Name;
				_ioDispatcher.ReadBackward(userStreamId, -1, 1, false, SystemAccount.Principal,
					m => ReadUserDataCompleted(m, authenticationRequest));
			}
		}

		private void ReadUserDataCompleted(ClientMessage.ReadStreamEventsBackwardCompleted completed,
			AuthenticationRequest authenticationRequest) {
			try {
				if (completed.Result == ReadStreamResult.StreamDeleted ||
				    completed.Result == ReadStreamResult.NoStream ||
				    completed.Result == ReadStreamResult.AccessDenied) {
					if (_logFailedAuthenticationAttempts)
						Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id, "Invalid user.");
					authenticationRequest.Unauthorized();
					return;
				}

				if (completed.Result == ReadStreamResult.Error) {
					if (_logFailedAuthenticationAttempts)
						Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id,
							"The system is not ready.");
					authenticationRequest.NotReady();
					return;
				}

				var userData = completed.Events[0].Event.Data.ParseJson<UserData>();
				if (userData.LoginName != authenticationRequest.Name) {
					authenticationRequest.Error();
					return;
				}

				if (userData.Disabled) {
					if (_logFailedAuthenticationAttempts)
						Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id,
							"The account is disabled.");
					authenticationRequest.Unauthorized();
				} else {
					if (authenticationRequest is PasswordAuthenticationRequest passwordAuthenticationRequest) {
						AuthenticateWithPasswordHash(passwordAuthenticationRequest, userData);
					} else if (authenticationRequest is ClientCertificateAuthenticationRequest clientCertificateAuthenticationRequest) {
						AuthenticateWithClientCertificate(clientCertificateAuthenticationRequest, CreatePrincipal(userData));
					} else {
						authenticationRequest.Error();
					}
				}
			} catch {
				authenticationRequest.Unauthorized();
			}
		}

		private void AuthenticateWithPasswordHash(PasswordAuthenticationRequest authenticationRequest, UserData userData) {
			if (!_passwordHashAlgorithm.Verify(authenticationRequest.SuppliedPassword, userData.Hash, userData.Salt)) {
				if (_logFailedAuthenticationAttempts)
					Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id,
						"Invalid credentials supplied.");
				authenticationRequest.Unauthorized();
				return;
			}

			var principal = CreatePrincipal(userData);
			CachePassword(authenticationRequest.Name, authenticationRequest.SuppliedPassword, principal);
			authenticationRequest.Authenticated(principal);
		}

		private static OpenGenericPrincipal CreatePrincipal(UserData userData) {
			var roles = new string[userData.Groups != null ? userData.Groups.Length + 1 : 1];
			if (userData.Groups != null)
				Array.Copy(userData.Groups, roles, userData.Groups.Length);
			roles[roles.Length - 1] = userData.LoginName;
			var principal = new OpenGenericPrincipal(new GenericIdentity(userData.LoginName), roles);
			return principal;
		}

		private void CachePassword(string loginName, string password, IPrincipal principal) {
			_userPasswordsCache.Put(loginName, Tuple.Create(password, principal));
		}

		private void AuthenticateWithPassword(PasswordAuthenticationRequest authenticationRequest, string correctPassword,
			IPrincipal principal) {
			if (authenticationRequest.SuppliedPassword != correctPassword) {
				if (_logFailedAuthenticationAttempts)
					Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id,
						"Invalid credentials supplied.");
				authenticationRequest.Unauthorized();
				return;
			}

			authenticationRequest.Authenticated(principal);
		}

		private void AuthenticateWithClientCertificate(ClientCertificateAuthenticationRequest authenticationRequest, IPrincipal principal) {
			using X509Chain chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } };
			if (chain.Build(new X509Certificate2(authenticationRequest.SuppliedClientCertificate))) {
				authenticationRequest.Authenticated(principal);
			} else {
				if (_logFailedAuthenticationAttempts)
					Log.Warn("Authentication Failed for {id}: {reason}", authenticationRequest.Id,
						"Invalid client certificate provided.");
				authenticationRequest.Unauthorized();
			}
		}

		public void Handle(InternalAuthenticationProviderMessages.ResetPasswordCache message) {
			_userPasswordsCache.Remove(message.LoginName);
		}
	}
}
