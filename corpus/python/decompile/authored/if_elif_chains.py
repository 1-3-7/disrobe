GRADE_BOUNDS = (90, 80, 70, 60)


def letter_grade(score):
    if score >= GRADE_BOUNDS[0]:
        return "A"
    elif score >= GRADE_BOUNDS[1]:
        return "B"
    elif score >= GRADE_BOUNDS[2]:
        return "C"
    elif score >= GRADE_BOUNDS[3]:
        return "D"
    else:
        return "F"


def classify_triangle(a, b, c):
    sides = sorted((a, b, c))
    if sides[0] <= 0:
        raise ValueError("sides must be positive")
    if sides[0] + sides[1] <= sides[2]:
        return "degenerate"
    if a == b == c:
        kind = "equilateral"
    elif a == b or b == c or a == c:
        kind = "isosceles"
    else:
        kind = "scalene"
    if sides[0] ** 2 + sides[1] ** 2 == sides[2] ** 2:
        kind += " right"
    return kind


def shipping_cost(weight, express, country):
    cost = 0.0
    if country == "home":
        if weight < 1:
            cost = 3.5
        elif weight < 5:
            cost = 7.25
        else:
            cost = 7.25 + (weight - 5) * 1.1
    elif country in ("near", "border"):
        cost = 12.0 if weight < 2 else 12.0 + weight * 2
    else:
        cost = 25.0 + weight * 4
    if express:
        if cost > 50:
            cost *= 1.25
        else:
            cost += 10
    return round(cost, 2)


def sign_word(value):
    if value < 0:
        word = "negative"
    elif value == 0:
        word = "zero"
    elif value > 0:
        word = "positive"
    else:
        word = "undefined"
    return word
