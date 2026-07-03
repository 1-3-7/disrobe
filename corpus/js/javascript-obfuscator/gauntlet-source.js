'use strict';

class TokenCounter {
    constructor(label) {
        this.label = label;
        this.counts = {};
    }

    add(token) {
        const key = token.toLowerCase();
        if (this.counts[key]) {
            this.counts[key] += 1;
        } else {
            this.counts[key] = 1;
        }
    }

    top(n) {
        const pairs = Object.entries(this.counts);
        pairs.sort((a, b) => b[1] - a[1]);
        return pairs.slice(0, n).map(pair => pair[0] + ':' + pair[1]);
    }

    report() {
        const lines = this.top(5);
        return this.label + ' => ' + lines.join(', ');
    }
}

function tokenize(text) {
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const result = [];
    for (let i = 0; i < words.length; i++) {
        const cleaned = words[i].replace(/[^a-z0-9]/gi, '');
        if (cleaned.length > 0) {
            result.push(cleaned);
        }
    }
    return result;
}

function buildHistogram(tokens) {
    const counter = new TokenCounter('histogram');
    for (const tok of tokens) {
        counter.add(tok);
    }
    return counter;
}

function pipeline(inputs) {
    const results = [];
    for (const input of inputs) {
        const tokens = tokenize(input);
        const hist = buildHistogram(tokens);
        results.push(hist.report());
    }
    return results;
}

const SAMPLES = [
    'the quick brown fox jumps over the lazy dog',
    'pack my box with five dozen liquor jugs',
    'how vexingly quick daft zebras jump',
];

const output = pipeline(SAMPLES);
for (const line of output) {
    console.log(line);
}
