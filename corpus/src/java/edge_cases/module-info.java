module disrobe.corpus.edge {
    requires java.base;
    requires java.sql;
    exports disrobe.corpus.edge to disrobe.corpus.consumer;
    opens disrobe.corpus.edge.internal;
    uses java.util.spi.ToolProvider;
}
