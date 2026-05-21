// Renderer for io.dummywa.signal messages.
// Asynchronously Signal-decrypts the event and shows spinner → plaintext.

import 'package:fluffychat/signal/index.dart';
import 'package:fluffychat/widgets/matrix.dart';
import 'package:flutter/material.dart';
import 'package:matrix/matrix.dart';

class SignalMessageWidget extends StatefulWidget {
  final Event event;
  final Color textColor;
  final double fontSize;

  const SignalMessageWidget({
    super.key,
    required this.event,
    required this.textColor,
    required this.fontSize,
  });

  @override
  State<SignalMessageWidget> createState() => _SignalMessageWidgetState();
}

class _SignalMessageWidgetState extends State<SignalMessageWidget> {
  String? _plaintext;
  bool _started = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_started) return;
    _started = true;
    _decrypt();
  }

  Future<void> _decrypt() async {
    final client = Matrix.of(context).client;
    final userId = client.userID;
    if (userId == null) {
      setState(() => _plaintext = '[Signal: not logged in]');
      return;
    }

    final middleware = getSignalMiddleware(userId);
    if (middleware == null) {
      setState(() => _plaintext = '[Signal: middleware not initialised]');
      return;
    }

    try {
      final plaintext = await middleware.decryptEvent(widget.event, client);
      if (mounted) {
        setState(() => _plaintext = plaintext ?? '[Signal: decryption failed]');
      }
    } catch (e) {
      if (mounted) {
        setState(() => _plaintext = '[Signal: decryption error]');
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final text = _plaintext;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: text == null
          ? Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: widget.textColor,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  '🔐 Decrypting…',
                  style: TextStyle(
                    color: widget.textColor,
                    fontSize: widget.fontSize,
                  ),
                ),
              ],
            )
          : Text(
              '🔐 $text',
              style: TextStyle(
                color: widget.textColor,
                fontSize: widget.fontSize,
              ),
            ),
    );
  }
}
