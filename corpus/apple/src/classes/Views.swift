import UIKit

@objc(FXGreeter)
public final class Greeter: NSObject {
    @objc public var name: String = "fixture"
    @objc public var visits: Int = 0

    @objc public func greet(_ who: String) -> String {
        visits += 1
        return "hello \(who) from \(name)"
    }
}

public final class SettingsViewController: UIViewController {
    public var count: Int = 3
    public let title2: String = "Settings"

    public override func viewDidLoad() {
        super.viewDidLoad()
        count += 1
    }

    public func reset() {
        count = 0
    }
}

open class BaseCell: UITableViewCell {
    open func configure(with text: String) {
        textLabel?.text = text
    }
}

public final class ValueCell: BaseCell {
    public var value: Double = 0

    public override func configure(with text: String) {
        super.configure(with: text)
        value = Double(text.count)
    }
}

public struct Point {
    public var x: Int
    public var y: Int
}

public enum Mode {
    case on
    case off(Int)
}

public func distance(_ a: Point, _ b: Point) -> Int {
    abs(a.x - b.x) + abs(a.y - b.y)
}
