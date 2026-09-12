class DispatchShapesProbe {
	static function main():Void {
		for (index in -2...12) {
			Sys.println("dense " + index + " " + DispatchShapes.dense(index));
			Sys.println("sparse " + index + " " + DispatchShapes.sparse(index));
			Sys.println("unordered " + index + " " + DispatchShapes.unordered(index));
		}
		for (limit in 0...8)
			Sys.println("inLoop " + limit + " " + DispatchShapes.inLoop(limit));
		for (token in ["red", "green", "blue", "teal", "", "RED"])
			Sys.println("shared " + token + " " + DispatchShapes.shared(token));
		Sys.println("coalesce null 7 " + DispatchShapes.coalesce(null, 7));
		Sys.println("coalesce 3 7 " + DispatchShapes.coalesce(3, 7));
		Sys.println("coalesce 0 7 " + DispatchShapes.coalesce(0, 7));
	}
}
