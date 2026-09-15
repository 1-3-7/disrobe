module rtti_families;

struct Packet {
    ulong identifier;
    string label;
}

interface Transport {
    int send(Packet packet);
}

enum Mode : uint {
    idle = 1,
    active = 2,
}

struct Box(T) {
    T value;
}

alias PacketBox = Box!Packet;

class Holder {
    Packet packet;
    Transport transport;
    Mode mode;
    PacketBox boxed;
}

__gshared TypeInfo packetType = typeid(Packet);
__gshared TypeInfo packetBoxType = typeid(PacketBox);
__gshared TypeInfo transportType = typeid(Transport);
__gshared TypeInfo modeType = typeid(Mode);

int main() {
    Holder holder = new Holder();
    return cast(int) holder.mode;
}
