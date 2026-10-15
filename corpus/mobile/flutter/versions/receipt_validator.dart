@pragma('vm:entry-point')
class ReceiptValidator {
  @pragma('vm:entry-point')
  final int modulus;

  @pragma('vm:entry-point')
  final String merchantTag;

  @pragma('vm:entry-point')
  const ReceiptValidator(this.modulus, this.merchantTag);

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
class FixtureApp {
  @pragma('vm:entry-point')
  const FixtureApp();

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  String build(List<String> arguments) {
    const ReceiptValidator validator = ReceiptValidator(65521, 'DISROBE');
    return validator.formatReceipt(<int>[19, 7, 42, 2026, arguments.length]);
  }
}

void main(List<String> arguments) {
  print(const FixtureApp().build(arguments));
}
