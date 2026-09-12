import 'package:flutter/material.dart';

void main() {
  runApp(const FixtureApp());
}

@pragma('vm:entry-point')
class VoucherValidator {
  @pragma('vm:entry-point')
  final int modulus;

  @pragma('vm:entry-point')
  final String merchantTag;

  @pragma('vm:entry-point')
  const VoucherValidator(this.modulus, this.merchantTag);

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  int computeChecksum(List<int> values) {
    int accumulator = merchantTag.codeUnits.fold<int>(
      0,
      (int sum, int unit) => sum + unit,
    );
    for (final int value in values) {
      accumulator = (accumulator * 31 + value) % modulus;
    }
    return accumulator;
  }

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  String formatReceipt(List<int> values) {
    return '$merchantTag:${computeChecksum(values)}';
  }
}

@pragma('vm:entry-point')
class FixtureApp extends StatelessWidget {
  @pragma('vm:entry-point')
  const FixtureApp({super.key});

  @override
  Widget build(BuildContext context) {
    const VoucherValidator validator = VoucherValidator(65521, 'DISROBE');
    final String token = validator.formatReceipt(<int>[19, 7, 42, 2026]);
    return MaterialApp(
      home: Scaffold(
        body: Center(child: Text(token)),
      ),
    );
  }
}
