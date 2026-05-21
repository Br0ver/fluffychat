// SignalMiddleware — per-userId session manager.
//
// One instance per logged-in Matrix user.  Manages Signal sessions per DM
// room and provides encrypt/decrypt helpers for the FluffyChat UI layer.

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:matrix/matrix.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'signal_encryption.dart';
import 'signal_key_exchange.dart';
import 'signal_key_store.dart';

class SignalMiddleware {
  final String _userId;
  final SignalKeyStore _store;

  // contactJid → true once session is established
  final _ready = <String, bool>{};
  // contactJid → Future to avoid duplicate initialisation
  final _pending = <String, Future<void>>{};

  // In-memory plaintext cache for fast intra-session lookup.
  final _decryptCache = <String, String>{};

  // SharedPreferences instance for persistent plaintext cache.
  // Mirrors Megolm key backup: first decrypt writes here so that re-renders
  // (and page reloads) never attempt to re-decrypt with an advanced ratchet.
  SharedPreferences? _ptPrefs;

  SignalMiddleware(this._userId) : _store = SignalKeyStore(_userId);

  // -------------------------------------------- event-driven key exchange

  /// Called on every incoming Matrix event.  Reacts to
  /// io.dummywa.bridge_info state events to kick off key exchange.
  Future<void> onRoomStateEvent(
    Map<String, dynamic> rawEvent,
    Room room,
    Client client,
  ) async {
    if (rawEvent['type'] != 'io.dummywa.bridge_info') return;
    final content = rawEvent['content'] as Map<String, dynamic>? ?? {};
    final contactJid = content['contact_jid'] as String?;
    if (contactJid == null ||
        _ready[contactJid] == true ||
        _pending.containsKey(contactJid)) {
      return;
    }

    final init = _initSession(room, client, contactJid);
    _pending[contactJid] = init;
    await init;
    _pending.remove(contactJid);
  }

  Future<void> _initSession(
    Room room,
    Client client,
    String contactJid,
  ) async {
    try {
      // Force republish if there is no existing session yet, so the bridge
      // re-fetches a fresh prekey bundle from the server.
      final addr = SignalProtocolAddress(contactJid, kDeviceId);
      final hasSession = await _store.containsSession(addr);
      final forceRepublish = !hasSession;

      await generateAndPublishKeys(
        _store,
        room,
        client,
        forceRepublish: forceRepublish,
      );
      await establishSession(
        _store,
        room,
        client,
        contactJid,
        requireFreshBundle: forceRepublish,
      );
      _ready[contactJid] = true;
      Logs().i('[Signal] Session ready for $contactJid');
    } catch (e, s) {
      Logs().e('[Signal] Key exchange failed for $contactJid', e, s);
    }
  }

  // --------------------------------------------------------- query helpers

  /// Returns true if a Signal session is established for [room].
  bool isReadyForRoom(Room room) {
    final bridgeInfo = room.getState('io.dummywa.bridge_info', '');
    if (bridgeInfo == null) return false;
    final contactJid = bridgeInfo.content['contact_jid'] as String?;
    return contactJid != null && _ready[contactJid] == true;
  }

  // ----------------------------------------------------------- encryption

  /// Signal-encrypt [plaintext] for the Signal-enabled room.
  /// Returns null if the room is not Signal-enabled or the session is not ready.
  Future<Map<String, dynamic>?> encryptForRoom(
    Room room,
    String plaintext,
  ) async {
    final bridgeInfo = room.getState('io.dummywa.bridge_info', '');
    if (bridgeInfo == null) return null;
    final contactJid = bridgeInfo.content['contact_jid'] as String?;
    if (contactJid == null || _ready[contactJid] != true) return null;

    final envelope = await signalEncrypt(_store, contactJid, plaintext);
    // body carries the plaintext so the sender can display their own message.
    // This is safe because the room is also Megolm-encrypted.
    return {
      'msgtype': 'io.dummywa.signal',
      'body': plaintext,
      'm.signal': envelope.toJson(),
    };
  }

  // ----------------------------------------------------------- decryption

  /// Attempt to Signal-decrypt an incoming Matrix event.
  /// Returns the plaintext, or null if the event is not a Signal event.
  Future<String?> decryptEvent(Event event, Client client) async {
    final content = event.content;
    if (content['msgtype'] != 'io.dummywa.signal') return null;

    final sigMap = content['m.signal'] as Map<String, dynamic>?;
    if (sigMap == null || sigMap['ciphertext'] == null) return null;

    // Sender's own messages already carry plaintext in body.
    if (event.senderId == _userId) return content['body'] as String?;

    // Check in-memory cache first.
    final eventId = event.eventId;
    final mem = _decryptCache[eventId];
    if (mem != null) return mem;

    // Check persistent cache — so re-renders after a ratchet advance don't fail.
    final ptPrefs = _ptPrefs ??= await SharedPreferences.getInstance();
    final persisted = ptPrefs.getString('signal_pt_${_userId}_$eventId');
    if (persisted != null) {
      _decryptCache[eventId] = persisted;
      return persisted;
    }

    // Determine contactJid from the room's bridge_info state.
    final room = client.getRoomById(event.roomId ?? '');
    if (room == null) return null;
    final bridgeInfo = room.getState('io.dummywa.bridge_info', '');
    if (bridgeInfo == null) return null;
    final contactJid = bridgeInfo.content['contact_jid'] as String?;
    if (contactJid == null) return null;

    try {
      final plaintext = await signalDecrypt(
        _store,
        contactJid,
        (sigMap['type'] as num).toInt(),
        sigMap['ciphertext'] as String,
      );
      _decryptCache[eventId] = plaintext;
      // Fire-and-forget — don't block the render on the prefs write.
      ptPrefs.setString('signal_pt_${_userId}_$eventId', plaintext);
      return plaintext;
    } catch (e, s) {
      Logs().e('[Signal] Decrypt failed for $eventId', e, s);
      return null;
    }
  }
}

// ----------------------------------------------------------------- registry

// One SignalMiddleware per Matrix userId — handles multi-account correctly.
final _middlewares = <String, SignalMiddleware>{};

SignalMiddleware getOrCreateSignalMiddleware(String userId) =>
    _middlewares.putIfAbsent(userId, () => SignalMiddleware(userId));

SignalMiddleware? getSignalMiddleware(String userId) => _middlewares[userId];
