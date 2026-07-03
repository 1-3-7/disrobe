public struct Greeting {
    public let recipientName: String
    public let salutationCount: Int

    public init(recipientName: String, salutationCount: Int) {
        self.recipientName = recipientName
        self.salutationCount = salutationCount
    }

    public func renderBanner() -> String {
        return "Hello, \(recipientName)"
    }
}

public enum DeliveryChannel {
    case inbox
    case archive
    case spamFolder
}

public class CourierService {
    public var pendingMessages: Int
    public let channelLabel: String

    public init(channelLabel: String) {
        self.pendingMessages = 0
        self.channelLabel = channelLabel
    }

    public func enqueueGreeting(_ greeting: Greeting) {
        self.pendingMessages += 1
    }
}
