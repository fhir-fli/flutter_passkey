import 'dart:async';
import 'package:flutter/services.dart';
import 'flutter_passkey_platform_interface.dart';

class FlutterPasskeyLinux extends FlutterPasskeyPlatform {
  static const MethodChannel _channel = MethodChannel('flutter_passkey');

  static void registerWith() {
    FlutterPasskeyPlatform.instance = FlutterPasskeyLinux();
  }

  @override
  Future<String?> getPlatformVersion() async {
    return _channel.invokeMethod<String>('getPlatformVersion');
  }

  @override
  Future<String?> createCredential(String options) async {
    // Sends { "options": options } to native
    return _channel.invokeMethod<String>('createCredential', {
      'options': options,
    });
  }

  @override
  Future<String?> getCredential(String options) async {
    // Sends { "options": options } to native
    return _channel.invokeMethod<String>('getCredential', {
      'options': options,
    });
  }
}
