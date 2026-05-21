// Signal Protocol encrypt / decrypt wrappers.

import 'dart:convert';
import 'dart:typed_data';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';

import 'signal_key_exchange.dart' show kDeviceId;
import 'signal_key_store.dart';

class SignalCiphertextEnvelope {
  /// 2 = WhisperMessage, 3 = PreKeyWhisperMessage (CiphertextMessage constants)
  final int type;

  /// base64-encoded serialised Signal message
  final String ciphertext;

  const SignalCiphertextEnvelope({required this.type, required this.ciphertext});

  Map<String, dynamic> toJson() => {'type': type, 'ciphertext': ciphertext};
}

Future<SignalCiphertextEnvelope> signalEncrypt(
  SignalKeyStore store,
  String contactJid,
  String plaintext,
) async {
  final address = SignalProtocolAddress(contactJid, kDeviceId);
  final cipher = SessionCipher(store, store, store, store, address);
  final msg = await cipher.encrypt(
    Uint8List.fromList(utf8.encode(plaintext)),
  );
  return SignalCiphertextEnvelope(
    type: msg.getType(),
    ciphertext: base64Encode(msg.serialize()),
  );
}

Future<String> signalDecrypt(
  SignalKeyStore store,
  String contactJid,
  int msgType,
  String ciphertextB64,
) async {
  final address = SignalProtocolAddress(contactJid, kDeviceId);
  final cipher = SessionCipher(store, store, store, store, address);
  final raw = base64Decode(ciphertextB64);

  Uint8List plainBytes;
  if (msgType == CiphertextMessage.prekeyType) {
    // PreKeySignalMessage constructor takes raw serialized bytes directly.
    plainBytes = await cipher.decrypt(PreKeySignalMessage(raw));
  } else {
    // SignalMessage uses a named constructor for deserialization.
    plainBytes = await cipher.decryptFromSignal(SignalMessage.fromSerialized(raw));
  }
  return utf8.decode(plainBytes);
}
