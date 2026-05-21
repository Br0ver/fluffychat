// Signal Protocol key exchange helpers.
//
// Key exchange is bridge-mediated (same as Element Web):
//   1. generateAndPublishKeys() generates our keys and posts them as
//      Matrix state event io.dummywa.client_signal_keys.
//      The bridge picks this up and forwards to the dummy server.
//   2. establishSession() polls until the bridge has posted the contact's
//      prekey bundle (io.dummywa.contact_signal_keys), then performs X3DH.

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:matrix/matrix.dart';

import 'signal_key_store.dart';

const int kPreKeyCount = 5;
const int kSignedPreKeyId = 1;
const int kDeviceId = 1;

const Duration _pollInterval = Duration(seconds: 2);
const Duration _pollTimeout = Duration(minutes: 1);

// ------------------------------------------------------------------ helpers

String _b64(Uint8List bytes) => base64Encode(bytes);
Uint8List _unb64(String s) => base64Decode(s);

// ------------------------------------------------------------------ public API

/// Generate our Signal prekeys (if not already done) and publish them as a
/// Matrix state event so the bridge can relay them to the dummy server.
///
/// Pass [forceRepublish] = true to always post fresh keys — used when
/// establishing a brand-new session so the bridge re-fetches the server's
/// current prekey bundle.
Future<void> generateAndPublishKeys(
  SignalKeyStore store,
  Room room,
  Client client, {
  bool forceRepublish = false,
}) async {
  final identityKeyPair = await store.getIdentityKeyPair();
  final registrationId = await store.getLocalRegistrationId();

  if (!forceRepublish) {
    // Return early if we already published matching keys for this room.
    final existing = room.getState('io.dummywa.client_signal_keys', '');
    if (existing != null && existing.senderId == client.userID) {
      final ourPubKey = _b64(identityKeyPair.getPublicKey().serialize());
      if (existing.content['identity_key'] == ourPubKey) return;
    }
  }

  // Generate signed prekey.
  final spkRecord = generateSignedPreKey(identityKeyPair, kSignedPreKeyId);
  await store.storeSignedPreKey(kSignedPreKeyId, spkRecord);

  // Generate one-time prekeys.
  final preKeyRecords = generatePreKeys(1, kPreKeyCount);
  for (final pk in preKeyRecords) {
    await store.storePreKey(pk.id, pk);
  }

  final content = {
    'identity_key': _b64(identityKeyPair.getPublicKey().serialize()),
    'registration_id': registrationId,
    'signed_prekey': {
      'id': spkRecord.id,
      'key': _b64(spkRecord.getKeyPair().publicKey.serialize()),
      'signature': _b64(spkRecord.signature),
    },
    'prekeys': preKeyRecords
        .map((pk) => {'id': pk.id, 'key': _b64(pk.getKeyPair().publicKey.serialize())})
        .toList(),
  };

  await client.setRoomStateWithKey(
    room.id,
    'io.dummywa.client_signal_keys',
    '',
    content,
  );
}

/// Wait for the bridge to post io.dummywa.contact_signal_keys, then perform
/// X3DH key agreement to establish a Signal session with the contact.
///
/// Pass [requireFreshBundle] = true when we need the bridge to re-fetch a new
/// prekey bundle (e.g. fresh session, no existing persisted state).
Future<void> establishSession(
  SignalKeyStore store,
  Room room,
  Client client,
  String contactJid, {
  bool requireFreshBundle = false,
}) async {
  final contactBundle =
      await _waitForContactKeys(room, requireFreshBundle: requireFreshBundle);
  if (contactBundle == null) {
    Logs().w('[Signal] Timed out waiting for contact_signal_keys for $contactJid');
    return;
  }

  final identityKeyBytes = _unb64(contactBundle['identity_key'] as String);
  final identityKey = IdentityKey(Curve.decodePoint(identityKeyBytes, 0));

  final spkMap = contactBundle['signed_prekey'] as Map<String, dynamic>;
  final spkPubKeyBytes = _unb64(spkMap['key'] as String);
  final spkPublicKey = Curve.decodePoint(spkPubKeyBytes, 0);
  final spkSignature = _unb64(spkMap['signature'] as String);

  final pkMap = contactBundle['prekey'] as Map<String, dynamic>?;
  // PreKeyBundle in libsignal_protocol_dart 0.5.x requires a non-null one-time
  // prekey.  The dummy server always provides one (10 prekeys are generated on
  // startup), so this guard is only hit if the server ran out.
  if (pkMap == null) {
    Logs().w('[Signal] No one-time prekey in bundle for $contactJid — cannot establish session');
    return;
  }
  final preKeyPublic = Curve.decodePoint(_unb64(pkMap['key'] as String), 0);
  final preKeyId = (pkMap['id'] as num).toInt();

  final address = SignalProtocolAddress(contactJid, kDeviceId);

  // Reuse an existing session if the server identity hasn't changed, to avoid
  // burning a one-time prekey on a plain page reload.
  if (await store.containsSession(address)) {
    final storedIdentity = await store.getIdentity(address);
    if (storedIdentity != null &&
        storedIdentity.serialize().join() == identityKey.serialize().join()) {
      Logs().i('[Signal] Reusing existing session for $contactJid');
      return;
    }
    // Identity changed (server restart) — rebuild.
    Logs().i('[Signal] Server identity changed for $contactJid — re-establishing');
    await store.deleteAllSessions(contactJid);
  }

  final preKeyBundle = PreKeyBundle(
    (contactBundle['registration_id'] as num?)?.toInt() ?? 1,
    (contactBundle['device_id'] as num?)?.toInt() ?? kDeviceId,
    preKeyId,
    preKeyPublic,
    (spkMap['id'] as num).toInt(),
    spkPublicKey,
    spkSignature,
    identityKey,
  );

  final sessionBuilder = SessionBuilder(store, store, store, store, address);
  await sessionBuilder.processPreKeyBundle(preKeyBundle);
  Logs().i('[Signal] Session established with $contactJid');
}

// ------------------------------------------------------------------ internal

Future<Map<String, dynamic>?> _waitForContactKeys(
  Room room, {
  bool requireFreshBundle = false,
}) async {
  // Snapshot current content so we can detect genuinely fresh bundles.
  final staleContent = () {
    final evt = room.getState('io.dummywa.contact_signal_keys', '');
    return evt != null ? jsonEncode(evt.content) : null;
  }();

  final deadline = DateTime.now().add(_pollTimeout);
  while (DateTime.now().isBefore(deadline)) {
    final stateEvt = room.getState('io.dummywa.contact_signal_keys', '');
    if (stateEvt != null) {
      final content = stateEvt.content;
      if (content['identity_key'] != null) {
        if (!requireFreshBundle ||
            jsonEncode(content) != staleContent) {
          return Map<String, dynamic>.from(content);
        }
        // Same bundle — keep polling until bridge re-fetches.
      }
    }
    await Future.delayed(_pollInterval);
  }
  return null;
}
