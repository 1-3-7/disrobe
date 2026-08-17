const Symbol shipmentStatus = Symbol('shipment.status');

@pragma('vm:never-inline')
@pragma('vm:entry-point')
String describeSymbol(Symbol value) => value.toString();

@pragma('vm:never-inline')
@pragma('vm:entry-point')
String symbolProbe() => describeSymbol(shipmentStatus);

void main() => print(symbolProbe());
