class Vehicle {
    constructor(wheels) {
        this.wheels = wheels;
    }
}

const instance = Reflect.construct(Vehicle, [4]);
const wheels = Reflect.get(instance, "wheels");
Reflect.set(instance, "color", "red");
const keys = Reflect.ownKeys(instance);
const proto = Reflect.getPrototypeOf(instance);
const called = Reflect.apply((a, b) => a + b, null, [3, 4]);

console.log({ wheels, keys, protoName: proto.constructor.name, called });
