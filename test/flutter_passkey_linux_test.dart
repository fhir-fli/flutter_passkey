import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_passkey/flutter_passkey.dart';
import 'package:flutter_passkey/flutter_passkey_platform_interface.dart';
import 'package:flutter_passkey/flutter_passkey_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockFlutterPasskeyPlatform
    with MockPlatformInterfaceMixin
    implements FlutterPasskeyPlatform {

  // Pretend this is a Linux platform. "Linux 5.0" or any Linux-like string
  // that your isSupported() method will interpret as Linux.
  @override
  Future<String?> getPlatformVersion() => Future.value("Linux 5.0");

  // Return some dummy values for createCredential/getCredential
  @override
  Future<String?> createCredential(String options) => Future.value("FakePublicKeyPEM");

  @override
  Future<String?> getCredential(String options) => Future.value("FakeSignatureBase64");
}

void main() {
  final FlutterPasskeyPlatform initialPlatform = FlutterPasskeyPlatform.instance;

  test('$MethodChannelFlutterPasskey is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelFlutterPasskey>());
  });

  test('isSupported', () async {
    FlutterPasskey flutterPasskeyPlugin = FlutterPasskey();
    MockFlutterPasskeyPlatform fakePlatform = MockFlutterPasskeyPlatform();
    FlutterPasskeyPlatform.instance = fakePlatform;

    // Because mock returns "Linux 5.0", we expect isSupported() to be true
    // if your isSupported() method checks for "Linux" in getPlatformVersion().
    expect(await flutterPasskeyPlugin.isSupported(), true);
  });

  test('createCredential', () async {
    FlutterPasskey flutterPasskeyPlugin = FlutterPasskey();
    MockFlutterPasskeyPlatform fakePlatform = MockFlutterPasskeyPlatform();
    FlutterPasskeyPlatform.instance = fakePlatform;

    // Expects "FakePublicKeyPEM" from mock
    expect(await flutterPasskeyPlugin.createCredential(""), "FakePublicKeyPEM");
  });

  test('getCredential', () async {
    FlutterPasskey flutterPasskeyPlugin = FlutterPasskey();
    MockFlutterPasskeyPlatform fakePlatform = MockFlutterPasskeyPlatform();
    FlutterPasskeyPlatform.instance = fakePlatform;

    // Expects "FakeSignatureBase64" from mock
    expect(await flutterPasskeyPlugin.getCredential(""), "FakeSignatureBase64");
  });
}
