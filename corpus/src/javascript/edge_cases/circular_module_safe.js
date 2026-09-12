const moduleA = {
    name: "A",
    partner: null,
    describe() {
        return `${this.name} -> ${this.partner?.name ?? "none"}`;
    },
};

const moduleB = {
    name: "B",
    partner: moduleA,
    describe() {
        return `${this.name} -> ${this.partner?.name ?? "none"}`;
    },
};

moduleA.partner = moduleB;
console.log(moduleA.describe(), moduleB.describe());
