const { chromium } = require("playwright");
const path = require("path");

const HERE = __dirname;
const HTML = path.join(HERE, "slide_guide.html");
const PDF = path.join(HERE, "RuntimeLens_slide_guide.pdf");

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto("file://" + HTML, { waitUntil: "networkidle" });
  await page.emulateMedia({ media: "print" });
  await page.pdf({
    path: PDF,
    format: "A4",
    printBackground: true,
    preferCSSPageSize: true,
    displayHeaderFooter: true,
    headerTemplate: "<div></div>",
    footerTemplate:
      '<div style="width:100%;font-family:Helvetica,Arial,sans-serif;font-size:8pt;color:#4E6076;padding:0 15mm;display:flex;justify-content:space-between;">' +
      "<span>RuntimeLens · Slide-by-Slide Guide · Cloud Security and SRE</span>" +
      '<span style="color:#0E7E9E;font-weight:bold;"><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
    margin: { top: "0mm", bottom: "0mm", left: "0mm", right: "0mm" },
  });
  await browser.close();
  console.log("wrote", PDF);
})();
