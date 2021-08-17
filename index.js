const VirusTotalApi = require("virustotal-api");
const { API_KEY } = require("./config.json");
const fs = require("fs/promises");
const { constants: fsConstants } = require("fs");
const path = require("path");
const bluebird = require("bluebird");
const input = require("input");

const virusTotal = new VirusTotalApi(API_KEY);

async function uploadFile(dir, base) {
  const buffer = await fs.readFile(path.join(__dirname, dir, base));
  const response = await virusTotal.fileScan(buffer, base);
  console.log(response.verbose_msg);
  return response.resource;
}

async function checkScanResult(resource) {
  const result = await virusTotal.fileReport(resource);
  if (result.response_code < 0) {
    console.log(`${new Date().toISOString()}: ${result.verbose_msg}`);
    await bluebird.delay(1000 * 15);
    return await checkScanResult(resource);
  } else {
    return result;
  }
}

async function scanFile(dir, base) {
  const access = await fs
    .access(path.join(dir, base), fsConstants.F_OK)
    .catch((err) => false);
  if (access === false) {
    throw new Error(`File is not found at ${path.join(__dirname, dir, base)}`);
  }
  const resource = await uploadFile(dir, base);
  await bluebird.delay(1000 * 10);
  return await checkScanResult(resource);
}

(async () => {
  let filePath;
  if (process.argv.length > 2) {
    const [cmd, scriptPath, path] = process.argv;
    filePath = path;
    console.log(`Start check for ${path}`);
  } else {
    filePath = await input.text(`Please specify file path: `);
  }
  try {
    const { dir, base } = path.parse(filePath);
    const result = await scanFile(dir, base);
    await fs.writeFile(`${filePath}.virustotal.json`, JSON.stringify(result));
    console.log(`Result: ${result.positives}/${result.total}`);
  } catch (e) {
    console.error(e.toString());
  }
})();
