public protocol EmptyProtocol {}

public extension EmptyProtocol {
    func run(_: (Self) -> Void) {}
}

public class FunctionConversionTest: EmptyProtocol {
    func convertFunction(_ fn: (Any) -> Void) -> Self {
        run(fn)

        return self
    }
}
