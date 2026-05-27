class CountdownRange {
    constructor(start, end) {
        this.start = start;
        this.end = end;
    }
    [Symbol.iterator]() {
        let current = this.start;
        const end = this.end;
        return {
            next() {
                if (current <= end) return { value: undefined, done: true };
                const value = current;
                current -= 1;
                return { value, done: false };
            },
            return(value) {
                current = end;
                return { value, done: true };
            },
        };
    }
}

const cr = new CountdownRange(5, 1);
console.log([...cr]);
