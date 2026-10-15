import Foundation

final class Person: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    let name: String
    let age: Int
    var friend: Person?
    let tags: [String]
    let scores: [String: Double]
    let born: Date
    let avatar: Data
    let home: URL
    let id: UUID

    init(name: String, age: Int, tags: [String], scores: [String: Double], born: Date, avatar: Data, home: URL, id: UUID) {
        self.name = name
        self.age = age
        self.tags = tags
        self.scores = scores
        self.born = born
        self.avatar = avatar
        self.home = home
        self.id = id
    }

    required init?(coder: NSCoder) {
        guard let name = coder.decodeObject(of: NSString.self, forKey: "name") as String? else { return nil }
        self.name = name
        self.age = coder.decodeInteger(forKey: "age")
        self.friend = coder.decodeObject(of: Person.self, forKey: "friend")
        self.tags = coder.decodeObject(of: [NSArray.self, NSString.self], forKey: "tags") as? [String] ?? []
        self.scores = coder.decodeObject(of: [NSDictionary.self, NSString.self, NSNumber.self], forKey: "scores") as? [String: Double] ?? [:]
        self.born = coder.decodeObject(of: NSDate.self, forKey: "born") as Date? ?? Date(timeIntervalSince1970: 0)
        self.avatar = coder.decodeObject(of: NSData.self, forKey: "avatar") as Data? ?? Data()
        self.home = coder.decodeObject(of: NSURL.self, forKey: "home") as URL? ?? URL(fileURLWithPath: "/")
        self.id = coder.decodeObject(of: NSUUID.self, forKey: "id") as UUID? ?? UUID()
    }

    func encode(with coder: NSCoder) {
        coder.encode(name, forKey: "name")
        coder.encode(age, forKey: "age")
        coder.encode(friend, forKey: "friend")
        coder.encode(tags, forKey: "tags")
        coder.encode(scores, forKey: "scores")
        coder.encode(born, forKey: "born")
        coder.encode(avatar, forKey: "avatar")
        coder.encode(home, forKey: "home")
        coder.encode(id, forKey: "id")
    }
}

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let alice = Person(
    name: "Alice", age: 34, tags: ["admin", "ops"], scores: ["speed": 9.5, "accuracy": 8.25],
    born: Date(timeIntervalSinceReferenceDate: 123_456_789), avatar: Data([0, 1, 2, 3, 255]),
    home: URL(string: "https://example.org/alice")!, id: UUID(uuidString: "6F9619FF-8B86-D011-B42D-00C04FC964FF")!)
let bob = Person(
    name: "Bob", age: 29, tags: [], scores: [:],
    born: Date(timeIntervalSinceReferenceDate: 0), avatar: Data(),
    home: URL(string: "https://example.org/bob")!, id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!)
alice.friend = bob
bob.friend = alice
let root: NSDictionary = ["people": [alice, bob], "count": 2, "set": NSSet(array: ["x", "y"]), "null": NSNull()]
let data = try NSKeyedArchiver.archivedData(withRootObject: root, requiringSecureCoding: false)
try data.write(to: output.appendingPathComponent("graph.archive"))
let xml = try PropertyListSerialization.data(
    fromPropertyList: try PropertyListSerialization.propertyList(from: data, format: nil), format: .xml, options: 0)
try xml.write(to: output.appendingPathComponent("graph.archive.xml"))
