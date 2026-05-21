// Signal Protocol key store backed by SharedPreferences.
// Implements all four libsignal_protocol_dart store interfaces so a single
// instance can be passed wherever any of the four stores is required.

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:shared_preferences/shared_preferences.dart';

class SignalKeyStore
    implements
        IdentityKeyStore,
        PreKeyStore,
        SessionStore,
        SignedPreKeyStore {
  final String _userId;

  // Lazy-loaded prefs handle — call _prefs() to get it.
  SharedPreferences? _prefsCache;

  // In-memory cache for hot path
  IdentityKeyPair? _identityKeyPair;
  int? _registrationId;

  SignalKeyStore(this._userId);

  // ------------------------------------------------------------------ helpers

  Future<SharedPreferences> _prefs() async =>
      _prefsCache ??= await SharedPreferences.getInstance();

  String _k(String suffix) => 'signal_v1_${_userId}_$suffix';

  Future<String?> _getString(String suffix) async =>
      (await _prefs()).getString(_k(suffix));

  Future<void> _setString(String suffix, String value) async =>
      (await _prefs()).setString(_k(suffix), value);

  Future<void> _remove(String suffix) async =>
      (await _prefs()).remove(_k(suffix));

  // base64 helpers
  static String _b64(Uint8List bytes) => base64Encode(bytes);
  static Uint8List _unb64(String s) => base64Decode(s);

  // ---------------------------------------------------------- IdentityKeyStore

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async {
    if (_identityKeyPair != null) return _identityKeyPair!;
    final stored = await _getString('identity_key_pair');
    if (stored != null) {
      _identityKeyPair = IdentityKeyPair.fromSerialized(_unb64(stored));
      return _identityKeyPair!;
    }
    final kp = generateIdentityKeyPair();
    _identityKeyPair = kp;
    await _setString('identity_key_pair', _b64(kp.serialize()));
    return kp;
  }

  @override
  Future<int> getLocalRegistrationId() async {
    if (_registrationId != null) return _registrationId!;
    final stored = (await _prefs()).getInt(_k('registration_id'));
    if (stored != null) {
      _registrationId = stored;
      return stored;
    }
    final id = generateRegistrationId(false);
    _registrationId = id;
    await (await _prefs()).setInt(_k('registration_id'), id);
    return id;
  }

  @override
  Future<bool> saveIdentity(
    SignalProtocolAddress address,
    IdentityKey? identityKey,
  ) async {
    if (identityKey == null) return false;
    final key = 'identity_${address.getName()}';
    final existing = await _getString(key);
    await _setString(key, _b64(identityKey.serialize()));
    return existing != null;
  }

  @override
  Future<bool> isTrustedIdentity(
    SignalProtocolAddress address,
    IdentityKey? identityKey,
    Direction direction,
  ) async {
    if (identityKey == null) return true;
    final stored = await _getString('identity_${address.getName()}');
    if (stored == null) return true; // trust on first use
    return stored == _b64(identityKey.serialize());
  }

  @override
  Future<IdentityKey?> getIdentity(SignalProtocolAddress address) async {
    final stored = await _getString('identity_${address.getName()}');
    if (stored == null) return null;
    return IdentityKey.fromBytes(_unb64(stored), 0);
  }

  // ---------------------------------------------------------------- PreKeyStore

  @override
  Future<PreKeyRecord> loadPreKey(int preKeyId) async {
    final stored = await _getString('prekey_$preKeyId');
    if (stored == null) throw InvalidKeyIdException('No prekey $preKeyId');
    return PreKeyRecord.fromBuffer(_unb64(stored));
  }

  @override
  Future<void> storePreKey(int preKeyId, PreKeyRecord record) async {
    await _setString('prekey_$preKeyId', _b64(record.serialize()));
  }

  @override
  Future<void> removePreKey(int preKeyId) async {
    await _remove('prekey_$preKeyId');
  }

  @override
  Future<bool> containsPreKey(int preKeyId) async {
    return await _getString('prekey_$preKeyId') != null;
  }

  // ----------------------------------------------------------- SessionStore

  @override
  Future<SessionRecord> loadSession(SignalProtocolAddress address) async {
    final stored = await _getString('session_$address');
    if (stored == null) return SessionRecord();
    return SessionRecord.fromSerialized(_unb64(stored));
  }

  @override
  Future<void> storeSession(
    SignalProtocolAddress address,
    SessionRecord record,
  ) async {
    await _setString('session_$address', _b64(record.serialize()));
  }

  @override
  Future<bool> containsSession(SignalProtocolAddress address) async {
    return await _getString('session_$address') != null;
  }

  @override
  Future<void> deleteSession(SignalProtocolAddress address) async {
    await _remove('session_$address');
  }

  @override
  Future<void> deleteAllSessions(String name) async {
    final prefs = await _prefs();
    final prefix = _k('session_$name');
    final toRemove = prefs.getKeys().where((k) => k.startsWith(prefix)).toList();
    for (final k in toRemove) {
      await prefs.remove(k);
    }
  }

  @override
  Future<List<int>> getSubDeviceSessions(String name) async {
    final prefs = await _prefs();
    final prefix = _k('session_$name.');
    return prefs
        .getKeys()
        .where((k) => k.startsWith(prefix))
        .map((k) => int.tryParse(k.split('.').last) ?? 0)
        .where((d) => d > 0)
        .toList();
  }

  // ------------------------------------------------------ SignedPreKeyStore

  @override
  Future<SignedPreKeyRecord> loadSignedPreKey(int signedPreKeyId) async {
    final stored = await _getString('spk_$signedPreKeyId');
    if (stored == null) {
      throw InvalidKeyIdException('No signed prekey $signedPreKeyId');
    }
    return SignedPreKeyRecord.fromSerialized(_unb64(stored));
  }

  @override
  Future<List<SignedPreKeyRecord>> loadSignedPreKeys() async {
    final prefs = await _prefs();
    final prefix = _k('spk_');
    final records = <SignedPreKeyRecord>[];
    for (final k in prefs.getKeys()) {
      if (k.startsWith(prefix)) {
        final val = prefs.getString(k);
        if (val != null) records.add(SignedPreKeyRecord.fromSerialized(_unb64(val)));
      }
    }
    return records;
  }

  @override
  Future<void> storeSignedPreKey(
    int signedPreKeyId,
    SignedPreKeyRecord record,
  ) async {
    await _setString('spk_$signedPreKeyId', _b64(record.serialize()));
  }

  @override
  Future<void> removeSignedPreKey(int signedPreKeyId) async {
    await _remove('spk_$signedPreKeyId');
  }

  @override
  Future<bool> containsSignedPreKey(int signedPreKeyId) async {
    return await _getString('spk_$signedPreKeyId') != null;
  }
}
