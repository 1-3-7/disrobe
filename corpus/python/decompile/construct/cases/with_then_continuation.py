def f(self, node):
    self.fill("try")
    with self.block():
        self.traverse(node.body)
    for ex in node.handlers:
        self.traverse(ex)
    if node.orelse:
        self.fill("else")
        with self.block():
            self.traverse(node.orelse)
