import * as echarts from "echarts";
import { SANS } from "./kit.mjs";

export function renderChart(width, height, option) {
  const chart = echarts.init(null, null, {
    renderer: "svg",
    ssr: true,
    width,
    height,
  });
  chart.setOption(
    {
      backgroundColor: "transparent",
      animation: false,
      textStyle: { fontFamily: SANS },
      ...option,
    },
    true,
  );
  const svg = chart.renderToSVGString();
  chart.dispose();
  return svg;
}
