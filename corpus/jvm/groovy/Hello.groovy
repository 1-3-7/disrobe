package disrobe.sample

class Calculator {
    int base

    Calculator(int base) {
        this.base = base
    }

    int addTo(int value) {
        return base + value
    }

    String describe() {
        if (base > 0) {
            return "positive base " + base
        } else {
            return "non-positive base " + base
        }
    }
}
