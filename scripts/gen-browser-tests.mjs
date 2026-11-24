import fs from "node:fs";
import path from "node:path";

const handleFile = (srcPath, dstPath, ...pipelines) => {
  let data = fs.readFileSync(srcPath, "utf8");
  for (const f of pipelines) {
    data = f(data);
  }
  const dstDir = path.dirname(dstPath);
  if (!fs.existsSync(dstDir)) {
    fs.mkdirSync(dstDir);
  }
  fs.writeFileSync(dstPath, data);
};

const pipelines = [(data) => data.replaceAll("../src", "@ecies/threshold")];

handleFile("./tests/entry.test.ts", "./tests-browser/entry.test.ts", ...pipelines);
