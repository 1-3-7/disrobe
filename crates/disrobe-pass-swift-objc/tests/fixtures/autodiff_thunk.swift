import _Differentiation

protocol NumericDifferentiable: Numeric, Differentiable {}
extension Float: NumericDifferentiable {}

func multiply<T: Numeric>(_ x: T, _ y: T) -> T {
    x * y
}

@derivative(of: multiply)
func multiplyVjp<T: NumericDifferentiable>(_ x: T, _ y: T) -> (
    value: T,
    pullback: (T.TangentVector) -> (T.TangentVector, T.TangentVector)
) {
    (multiply(x, y), { _ in (.zero, .zero) })
}

@differentiable(reverse)
public func differentiateMultiply(_ x: Float) -> Float {
    multiply(x, 1)
}
