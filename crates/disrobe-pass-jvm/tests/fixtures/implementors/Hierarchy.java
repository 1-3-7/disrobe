package implementors;

interface Root {}
interface Middle extends Root {}
abstract class Base implements Middle {}
final class Direct implements Root {}
final class Leaf extends Base {}
