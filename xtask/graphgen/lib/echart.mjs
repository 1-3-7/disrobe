import * as echarts from "echarts";
import { SANS } from "./kit.mjs";

const STYLE_ELEMENT = /<style(?:\s[^>]*)?>[\s\S]*?<\/style\s*>/g;
const STYLE_OPEN_TAG = /<style(?:\s|>)/i;

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
  const staticSvg = svg.replace(STYLE_ELEMENT, "");
  if (STYLE_OPEN_TAG.test(staticSvg)) {
    throw new Error("ECharts emitted a static SVG with a style element");
  }
  return staticSvg;
}
