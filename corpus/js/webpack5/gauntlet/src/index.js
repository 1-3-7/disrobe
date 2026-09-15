import { circleArea, polygonPerimeter, MAX_SIDES } from "./geometry.js";
import { Warehouse, STORE_NAME } from "./inventory.js";

function report() {
  const area = circleArea(5);
  const perimeter = polygonPerimeter(4, 6);
  const warehouse = new Warehouse(STORE_NAME);
  warehouse.restock("widget", 10);
  warehouse.restock("gadget", 3);
  const banner = `area=${area} perimeter=${perimeter} maxSides=${MAX_SIDES}`;
  console.log(banner);
  console.log(warehouse.summary());
  return warehouse.available("widget");
}

report();
