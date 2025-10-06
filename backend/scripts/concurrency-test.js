// backend/scripts/concurrency-test.js
const axios = require("axios");

const URL = process.env.VALIDATE_URL || "http://localhost:3000/validate";
const token = process.argv[2] || "TOKEN_A_PROBAR";
const concurrency = Number(process.argv[3] || 20);

async function run() {
  const promises = [];
  for (let i=0;i<concurrency;i++){
    promises.push(axios.post(URL, { token, sessionId: "sala-101", type: "entry" }).then(r => r.data).catch(e => ({ error: e.response ? e.response.data : e.message })));
  }
  const results = await Promise.all(promises);
  console.log("Resultados:", results);
  const okCount = results.filter(r=> r && r.ok).length;
  console.log("Éxitos:", okCount, " Fallos:", results.length - okCount);
}
run();
