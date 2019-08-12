﻿using System;
using System.Threading.Tasks;
using EventStore.ClientAPI.Internal;
using EventStore.ClientAPI.Messages;
using EventStore.ClientAPI.SystemData;
using EventStore.ClientAPI.Transport.Tcp;

namespace EventStore.ClientAPI.ClientOperations {
	internal class VolatileSubscriptionOperation : SubscriptionOperation<EventStoreSubscription, ResolvedEvent> {
		public VolatileSubscriptionOperation(ILogger log, TaskCompletionSource<EventStoreSubscription> source,
			string streamId, bool resolveLinkTos, UserCredentials userCredentials,
			Func<EventStoreSubscription, ResolvedEvent, Task> eventAppeared,
			Action<EventStoreSubscription, SubscriptionDropReason, Exception> subscriptionDropped, bool verboseLogging,
			Func<TcpPackageConnection> getConnection, Func<EventStoreSubscription, Position, Task> checkpointRead = null)
			: base(log, source, streamId, resolveLinkTos, userCredentials, eventAppeared, subscriptionDropped,
				verboseLogging, getConnection, checkpointRead) {
		}

		protected override TcpPackage CreateSubscriptionPackage() {
			var dto = new ClientMessage.SubscribeToStream(_streamId, _resolveLinkTos);
			return new TcpPackage(
				TcpCommand.SubscribeToStream, _userCredentials != null ? TcpFlags.Authenticated : TcpFlags.None,
				_correlationId, _userCredentials != null ? _userCredentials.Username : null,
				_userCredentials != null ? _userCredentials.Password : null, dto.Serialize());
		}

		protected override bool InspectPackage(TcpPackage package, out InspectionResult result) {
			if (package.Command == TcpCommand.SubscriptionConfirmation) {
				var dto = package.Data.Deserialize<ClientMessage.SubscriptionConfirmation>();
				ConfirmSubscription(dto.LastCommitPosition, dto.LastEventNumber);
				result = new InspectionResult(InspectionDecision.Subscribed, "SubscriptionConfirmation");
				return true;
			}

			if (package.Command == TcpCommand.StreamEventAppeared) {
				var dto = package.Data.Deserialize<ClientMessage.StreamEventAppeared>();
				EventAppeared(new ResolvedEvent(dto.Event));
				result = new InspectionResult(InspectionDecision.DoNothing, "StreamEventAppeared");
				return true;
			}

			if (package.Command == TcpCommand.CheckpointRead) {
				var dto = package.Data.Deserialize<ClientMessage.CheckpointRead>();
				CheckpointRead(new Position(dto.CommitPosition, dto.PreparePosition));
				result = new InspectionResult(InspectionDecision.DoNothing, "CheckpointRead");
				return true;
			}

			result = null;
			return false;
		}

		protected override EventStoreSubscription CreateSubscriptionObject(long lastCommitPosition,
			long? lastEventNumber) {
			return new VolatileEventStoreSubscription(this, _streamId, lastCommitPosition, lastEventNumber);
		}
	}

	internal class VolatileFilteredSubscriptionOperation : VolatileSubscriptionOperation {
		private readonly StreamFilter _streamFilter;
		private readonly int _sendCheckpointMessageCount;

		public VolatileFilteredSubscriptionOperation(ILogger log, TaskCompletionSource<EventStoreSubscription> source,
			string streamId, bool resolveLinkTos, int sendCheckpointMessageCount, StreamFilter streamFilter, UserCredentials userCredentials,
			Func<EventStoreSubscription, ResolvedEvent, Task> eventAppeared,
			Func<EventStoreSubscription, Position, Task> checkpointRead,
			Action<EventStoreSubscription, SubscriptionDropReason, Exception> subscriptionDropped, bool verboseLogging,
			Func<TcpPackageConnection> getConnection) :
			base(log, source, streamId, resolveLinkTos, userCredentials, eventAppeared, subscriptionDropped,
				verboseLogging, getConnection, checkpointRead) {
			_streamFilter = streamFilter;
			_sendCheckpointMessageCount = sendCheckpointMessageCount;
		}

		protected override TcpPackage CreateSubscriptionPackage() {
			var dto = new ClientMessage.SubscribeToStreamFiltered(_streamId, _resolveLinkTos,
				_streamFilter.EventFilters, _streamFilter.StreamFilters, _sendCheckpointMessageCount);
			return new TcpPackage(
				TcpCommand.SubscribeToStreamFiltered, _userCredentials != null ? TcpFlags.Authenticated : TcpFlags.None,
				_correlationId, _userCredentials != null ? _userCredentials.Username : null,
				_userCredentials != null ? _userCredentials.Password : null, dto.Serialize());
		}
	}
}
