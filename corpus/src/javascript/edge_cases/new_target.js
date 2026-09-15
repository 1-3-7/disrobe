class Base {
    constructor() {
        this.calledViaNew = new.target !== undefined;
        this.constructedAs = new.target?.name ?? "none";
    }
}

class Derived extends Base {}

const direct = new Base();
const subclassed = new Derived();
const reflected = Reflect.construct(Base, []);

console.log({
    direct: { ok: direct.calledViaNew, name: direct.constructedAs },
    subclassed: { ok: subclassed.calledViaNew, name: subclassed.constructedAs },
    reflected: { ok: reflected.calledViaNew, name: reflected.constructedAs },
});
