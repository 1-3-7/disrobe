@pragma('vm:entry-point')
class AuditLedger {
  @pragma('vm:entry-point')
  final List<Object> postings = <Object>[];

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  void post(String account, double amount) {
    postings.add(account);
    postings.add(amount);
  }

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  void note(Object value) {
    postings.add(value);
  }

  @pragma('vm:entry-point')
  @pragma('vm:never-inline')
  String summarize() {
    return 'postings:${postings.length}';
  }
}

@pragma('vm:entry-point')
@pragma('vm:never-inline')
int ledgerDepth(int level) {
  if (level < 2) {
    return level;
  }
  return ledgerDepth(level - 1) + ledgerDepth(level - 2);
}

@pragma('vm:entry-point')
@pragma('vm:never-inline')
String classifyBalance(double balance) {
  if (balance > 125000.75) {
    return 'ledger-tier-platinum';
  }
  if (balance > 4096.5) {
    return 'ledger-tier-gold';
  }
  return 'ledger-tier-standard';
}

void main(List<String> arguments) {
  final AuditLedger ledger = AuditLedger();
  ledger.post('opening-balance', 19.95);
  ledger.post('freight-surcharge', -273.15);
  ledger.post('Zürich-office', 1234.5678);
  ledger.post('Δ-adjustment', 3.14159);
  ledger.note(9007199254740993);
  ledger.note(-81985529216486895);
  ledger.note(4294967296);
  ledger.note(const <String>['north-vault', 'south-vault', 'east-vault']);
  ledger.note(#auditTrail);
  ledger.note(<void Function(String)>[]);
  ledger.note(<int Function(double)?>[]);
  ledger.note(<String?>[]);
  ledger.note(<String, double>{});
  ledger.note(ledgerDepth(arguments.length + 9));
  print(classifyBalance(arguments.length * 1000.0));
  print(ledger.summarize());
}
