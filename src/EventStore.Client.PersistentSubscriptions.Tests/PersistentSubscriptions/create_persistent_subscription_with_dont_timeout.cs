using System;
using System.Threading.Tasks;
using Xunit;

namespace EventStore.Client.PersistentSubscriptions {
	public class create_with_dont_timeout
		: IClassFixture<create_with_dont_timeout.Fixture> {
		public create_with_dont_timeout(Fixture fixture) {
			_fixture = fixture;
		}

		private const string Stream = nameof(create_with_dont_timeout);
		private readonly Fixture _fixture;

		public class Fixture : EventStoreGrpcFixture {
			protected override Task Given() => Task.CompletedTask;
			protected override Task When() => Task.CompletedTask;
		}

		[Fact]
		public Task the_subscription_is_created_without_error() =>
			_fixture.Client.PersistentSubscriptions.CreateAsync(Stream, "dont-timeout",
				new PersistentSubscriptionSettings(messageTimeout: TimeSpan.Zero),
				TestCredentials.Root);
	}
}
