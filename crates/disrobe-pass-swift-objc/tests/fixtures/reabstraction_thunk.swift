public func acceptPair(_ body: ((Int, Int)) -> Void) {
    body((1, 2))
}

public func convertPair(_ body: (Any, Any) -> Void) {
    acceptPair(body)
}
