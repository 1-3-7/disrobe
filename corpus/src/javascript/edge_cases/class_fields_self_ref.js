class Graph {
    nodes = new Set();
    edges = new Map();
    self = this;
    nodeCount = () => this.nodes.size;
    addNode(name) {
        this.nodes.add(name);
        if (!this.edges.has(name)) this.edges.set(name, new Set());
        return this;
    }
    addEdge(from, to) {
        this.addNode(from).addNode(to);
        this.edges.get(from).add(to);
        return this;
    }
}

const g = new Graph().addEdge("a", "b").addEdge("a", "c").addEdge("b", "c");
console.log({
    count: g.nodeCount(),
    nodes: [...g.nodes],
    edgesFromA: [...g.edges.get("a")],
    selfMatches: g.self === g,
});
