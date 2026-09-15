export const PI_APPROX = 3.14159;
export const MAX_SIDES = 12;

export function circleArea(radius) {
  return PI_APPROX * radius * radius;
}

export function polygonPerimeter(sideLength, sideCount) {
  if (sideCount > MAX_SIDES) {
    throw new RangeError("too many sides for polygon");
  }
  let total = 0;
  for (let edge = 0; edge < sideCount; edge += 1) {
    total += sideLength;
  }
  return total;
}
